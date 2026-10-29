//! Reconciliation's progress, kept so that a run cut off at any point
//! resumes where it was, and never claims work that isn't durable.
//!
//! It lives in `cobs/cache.db`, beside the cache it rebuilds: it is progress
//! about derived data, and is lost with it, which only makes the next run
//! start over. Its tables are its own, created if absent, and the cache's
//! schema version doesn't change. Its connection writes with
//! `synchronous = FULL`.
//!
//! Progress is bound to its input:
//! - a repository's, to its [`version`], a hash over all its refs taken when
//!   its repair began: at another version, its progress is discarded;
//! - a namespace check's checkpoint, to the namespace's own version and the
//!   check's [`Authority`]: with either changed, the check starts over.

use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;
use std::{fmt, time};

use sqlite as sql;
use thiserror::Error;

use crate::git;
use crate::git::Oid;
use crate::git::fmt::RefString;
use crate::prelude::{NodeId, RepoId};
use crate::sql::transaction;
use crate::storage::git::Repository;

use super::cache;
use super::namespace::{Authority, Checkpoint};

/// How long a write waits for the database's lock.
const DB_WRITE_TIMEOUT: time::Duration = time::Duration::from_secs(6);

/// The progress tables, created if absent.
const SCHEMA: &str = include_str!("state/schema.sql");

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] sql::Error),
    #[error(transparent)]
    Git(#[from] git::raw::Error),
    #[error("invalid reconcile state: {0}")]
    Invalid(String),
    /// A symbolic ref resolves through a ref outside `refs/` whose name isn't
    /// UTF-8. libgit2 follows it, but it can't be looked up here, so the
    /// version can't take what it points at: it is refused rather than taken
    /// as absent.
    #[error("a symbolic ref resolves through {0:?}, a ref whose name isn't UTF-8")]
    Undecodable(String),
}

/// A step of one repository's repair, recorded once it is finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// Its ref lock files are removed.
    RefLocks,
    /// Every namespace the dirty marker names is checked, or re-signed.
    Namespaces,
    /// Its COB cache is rebuilt.
    Cache,
}

impl Step {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RefLocks => "ref-locks",
            Self::Namespaces => "namespaces",
            Self::Cache => "cache",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Step {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ref-locks" => Ok(Self::RefLocks),
            "namespaces" => Ok(Self::Namespaces),
            "cache" => Ok(Self::Cache),
            other => Err(Error::Invalid(format!("unknown step {other:?}"))),
        }
    }
}

fn authority(authority: Authority) -> &'static str {
    match authority {
        Authority::Owner => "owner",
        Authority::None => "none",
    }
}

/// How a rebuilt cache is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    /// At a start, before the node runs: the repair's progress is kept, until
    /// the whole run clears it.
    Start,
    /// Online, while the node runs: the repository's progress is deleted with
    /// it.
    Online,
}

/// A unit of work: the repository, its kind, and its position, such as the
/// checkpoint a namespace check runs from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub rid: RepoId,
    pub kind: String,
    pub position: String,
}

/// The unit in progress, and how many processes have started it: a unit
/// still recorded when a process starts was cut off when the last one ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InProgress {
    pub unit: Unit,
    pub attempts: u32,
}

/// The version of `repo`: a hash over every ref's name and target. Any
/// change to a ref changes it, and so does any change to what a symbolic ref
/// resolves through.
///
/// - **Each ref** is taken as libgit2 stores it, none skipped: its name's
///   bytes, UTF-8 or not, and its target, an object ID or, for a symbolic
///   ref, the name it points at, unresolved.
/// - **What the refs depend on beyond them:** libgit2 iterates `refs/` only.
///   A symbolic ref that points outside it, at `HEAD` for example, is
///   followed there, and each ref on the way is taken too, with its own
///   target: one that is absent is taken as absent.
///
/// Each field is length-prefixed, and each entry tagged with its class, so
/// that no two sets of refs hash the same bytes. A ref that is neither direct
/// nor symbolic, or that libgit2 can't read, is an error, and so is a
/// dependency whose name isn't UTF-8 ([`Error::Undecodable`]).
pub fn version(repo: &Repository) -> Result<Oid, Error> {
    let mut refs = BTreeSet::new();
    let mut outside = Vec::new();
    for reference in repo.backend.references()? {
        let reference = reference?;
        let name = reference.name_bytes().to_vec();
        let target = target(&reference, &name)?;
        if let Some(symbolic) = reference.symbolic_target_bytes()
            && !symbolic.starts_with(b"refs/")
        {
            outside.push(symbolic.to_vec());
        }
        refs.insert((b"ref".to_vec(), name, target));
    }
    // The refs outside `refs/` that symbolic refs resolve through, followed
    // as far as they go: each is taken once.
    let mut followed = BTreeSet::new();
    while let Some(name) = outside.pop() {
        if !followed.insert(name.clone()) {
            continue;
        }
        // libgit2 resolves through a name that isn't UTF-8, but git2 looks
        // names up as strings only: such a dependency can't be taken, and is
        // refused, never taken as absent.
        let Ok(text) = std::str::from_utf8(&name) else {
            return Err(Error::Undecodable(
                String::from_utf8_lossy(&name).into_owned(),
            ));
        };
        let found = match repo.backend.find_reference(text) {
            Ok(reference) => Some(reference),
            Err(e) if e.code() == git::raw::ErrorCode::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let target = match found {
            Some(reference) => {
                if let Some(symbolic) = reference.symbolic_target_bytes()
                    && !symbolic.starts_with(b"refs/")
                {
                    outside.push(symbolic.to_vec());
                }
                target(&reference, &name)?
            }
            None => b"absent".to_vec(),
        };
        refs.insert((b"dep".to_vec(), name, target));
    }
    let mut bytes = Vec::new();
    for (class, name, target) in refs {
        for field in [class, name, target] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(&field);
        }
    }
    let hash = git::raw::Oid::hash_object(git::raw::ObjectType::Blob, &bytes)?;
    Ok(hash.into())
}

/// A ref's target, tagged: an object ID, or the name it points at.
fn target(reference: &git::raw::Reference, name: &[u8]) -> Result<Vec<u8>, Error> {
    if let Some(oid) = reference.target() {
        Ok([b"oid ".as_slice(), oid.as_bytes()].concat())
    } else if let Some(symbolic) = reference.symbolic_target_bytes() {
        Ok([b"ref ".as_slice(), symbolic].concat())
    } else {
        Err(Error::Invalid(format!(
            "the ref {:?} has no target",
            String::from_utf8_lossy(name)
        )))
    }
}

/// Reconciliation's progress, in `cobs/cache.db`.
pub struct State {
    db: sql::ConnectionThreadSafe,
    /// The unit in progress when the last process ended, as this one found
    /// it, until this one starts it again.
    interrupted: Option<InProgress>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State").finish()
    }
}

impl State {
    /// Opens the progress in the cache database at `path`, creating its
    /// tables if they are absent, with `synchronous = FULL`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut db = sql::Connection::open_thread_safe(path)?;
        db.set_busy_timeout(DB_WRITE_TIMEOUT.as_millis() as usize)?;
        db.execute("PRAGMA synchronous = FULL;")?;
        transaction(&db, |db| db.execute(SCHEMA))?;
        let mut state = Self {
            db,
            interrupted: None,
        };
        state.interrupted = state.in_progress()?;
        Ok(state)
    }

    /// Begins, or resumes, the repair of `rid` at its `version`: the steps
    /// it has finished. Progress recorded at another version is discarded
    /// first, so the repair starts over.
    pub fn begin(&mut self, rid: &RepoId, version: Oid) -> Result<BTreeSet<Step>, Error> {
        transaction(&self.db, |db| {
            let mut stmt =
                db.prepare("SELECT version, steps FROM reconcile_repository WHERE rid = ?1")?;
            stmt.bind((1, rid))?;
            if let Some(row) = stmt.into_iter().next() {
                let row = row?;
                if row.try_read::<&str, _>("version")? == version.to_string() {
                    return steps(row.try_read::<&str, _>("steps")?);
                }
            }
            discard(db, rid)?;
            let mut stmt = db.prepare(
                "INSERT INTO reconcile_repository (rid, version, steps) VALUES (?1, ?2, '')",
            )?;
            stmt.bind((1, rid))?;
            stmt.bind((2, version.to_string().as_str()))?;
            stmt.next()?;
            Ok(BTreeSet::new())
        })
    }

    /// Records that `rid`'s repair has finished `step`.
    pub fn finish(&mut self, rid: &RepoId, step: Step) -> Result<(), Error> {
        transaction(&self.db, |db| {
            let mut stmt = db.prepare("SELECT steps FROM reconcile_repository WHERE rid = ?1")?;
            stmt.bind((1, rid))?;
            let Some(row) = stmt.into_iter().next() else {
                return Err(Error::Invalid(format!("no repair of {rid} has begun")));
            };
            let mut done = steps(row?.try_read::<&str, _>("steps")?)?;
            done.insert(step);
            let text = done.iter().map(Step::as_str).collect::<Vec<_>>().join(",");
            let mut stmt =
                db.prepare("UPDATE reconcile_repository SET steps = ?2 WHERE rid = ?1")?;
            stmt.bind((1, rid))?;
            stmt.bind((2, text.as_str()))?;
            stmt.next()?;
            Ok(())
        })
    }

    /// The checkpoint of the check of `namespace` in `rid`, if one was
    /// recorded at the namespace's `version` and under `authority`: otherwise
    /// the check starts over.
    pub fn checkpoint(
        &self,
        rid: &RepoId,
        namespace: &NodeId,
        version: Oid,
        authority: Authority,
    ) -> Result<Option<Checkpoint>, Error> {
        let mut stmt = self.db.prepare(
            "SELECT version, authority, after, stale FROM reconcile_namespace
             WHERE rid = ?1 AND namespace = ?2",
        )?;
        stmt.bind((1, rid))?;
        stmt.bind((2, namespace))?;
        let Some(row) = stmt.into_iter().next() else {
            return Ok(None);
        };
        let row = row?;
        if row.try_read::<&str, _>("version")? != version.to_string()
            || row.try_read::<&str, _>("authority")? != self::authority(authority)
        {
            return Ok(None);
        }
        let after = row
            .try_read::<Option<&str>, _>("after")?
            .map(|after| RefString::try_from(after).map_err(|e| Error::Invalid(e.to_string())))
            .transpose()?;
        Ok(Some(Checkpoint {
            after,
            stale: row.try_read::<i64, _>("stale")? != 0,
        }))
    }

    /// Records `checkpoint` for the check of `namespace` in `rid`, at the
    /// namespace's `version` and under `authority`.
    pub fn save_checkpoint(
        &mut self,
        rid: &RepoId,
        namespace: &NodeId,
        version: Oid,
        authority: Authority,
        checkpoint: &Checkpoint,
    ) -> Result<(), Error> {
        let mut stmt = self.db.prepare(
            "INSERT INTO reconcile_namespace (rid, namespace, version, authority, after, stale)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (rid, namespace) DO UPDATE SET
               version = excluded.version, authority = excluded.authority,
               after = excluded.after, stale = excluded.stale",
        )?;
        stmt.bind((1, rid))?;
        stmt.bind((2, namespace))?;
        stmt.bind((3, version.to_string().as_str()))?;
        stmt.bind((4, self::authority(authority)))?;
        stmt.bind((5, checkpoint.after.as_ref().map(|after| after.as_str())))?;
        stmt.bind((6, i64::from(checkpoint.stale)))?;
        stmt.next()?;
        Ok(())
    }

    /// The unit recorded in progress: the one running, or else the one in
    /// progress when the last process ended, until it runs again.
    pub fn in_progress(&self) -> Result<Option<InProgress>, Error> {
        let stmt = self
            .db
            .prepare("SELECT rid, kind, position, attempts FROM reconcile_unit WHERE id = 1")?;
        let Some(row) = stmt.into_iter().next() else {
            return Ok(None);
        };
        let row = row?;
        Ok(Some(InProgress {
            unit: Unit {
                rid: row.try_read::<RepoId, _>("rid")?,
                kind: row.try_read::<&str, _>("kind")?.to_owned(),
                position: row.try_read::<&str, _>("position")?.to_owned(),
            },
            attempts: row
                .try_read::<i64, _>("attempts")?
                .clamp(0, u32::MAX.into()) as u32,
        }))
    }

    /// The unit in progress when the last process ended, as this one opened
    /// the state, until this one starts it again.
    pub fn interrupted(&self) -> Option<&InProgress> {
        self.interrupted.as_ref()
    }

    /// Records `unit` as in progress, before it starts: how many processes
    /// have now started it. That is one more than before if it is the unit
    /// the last process ended during ([`Self::interrupted`]), whatever units
    /// ran since, and one otherwise.
    pub fn start(&mut self, unit: &Unit) -> Result<u32, Error> {
        let attempts = match &self.interrupted {
            Some(interrupted) if interrupted.unit == *unit => {
                interrupted.attempts.saturating_add(1)
            }
            _ => 1,
        };
        record(&self.db, unit, attempts)?;
        if attempts > 1 {
            self.interrupted = None;
        }
        Ok(attempts)
    }

    /// Records that the unit in progress has ended. The record of a unit
    /// the last process ended during, that hasn't run again, is kept: the
    /// next process still finds it.
    pub fn end(&mut self) -> Result<(), Error> {
        match &self.interrupted {
            Some(interrupted) => record(&self.db, &interrupted.unit, interrupted.attempts),
            None => {
                self.db.execute("DELETE FROM reconcile_unit")?;
                Ok(())
            }
        }
    }

    /// The checkpoint of `rid`'s cache rebuild, if one was recorded at its
    /// `version`: otherwise the rebuild starts over.
    pub fn cache_checkpoint(
        &self,
        rid: &RepoId,
        version: Oid,
    ) -> Result<Option<cache::Checkpoint>, Error> {
        let mut stmt = self
            .db
            .prepare("SELECT version, kind, after FROM reconcile_cache WHERE rid = ?1")?;
        stmt.bind((1, rid))?;
        let Some(row) = stmt.into_iter().next() else {
            return Ok(None);
        };
        let row = row?;
        if row.try_read::<&str, _>("version")? != version.to_string() {
            return Ok(None);
        }
        let kind = row
            .try_read::<&str, _>("kind")?
            .parse::<cache::Kind>()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let after = row
            .try_read::<Option<&str>, _>("after")?
            .map(|after| {
                after
                    .parse::<crate::cob::ObjectId>()
                    .map_err(|e| Error::Invalid(e.to_string()))
            })
            .transpose()?;
        Ok(Some(cache::Checkpoint { kind, after }))
    }

    /// The scan of `rid`'s remotes for its cache rebuild, if one was recorded
    /// at its `version`: otherwise the scan starts over.
    pub fn scan(&self, rid: &RepoId, version: Oid) -> Result<Option<cache::Scan>, Error> {
        let mut stmt = self
            .db
            .prepare("SELECT version, after, complete FROM rebuild_scan WHERE rid = ?1")?;
        stmt.bind((1, rid))?;
        let Some(row) = stmt.into_iter().next() else {
            return Ok(None);
        };
        let row = row?;
        if row.try_read::<&str, _>("version")? != version.to_string() {
            return Ok(None);
        }
        let after = row
            .try_read::<Option<&str>, _>("after")?
            .map(|after| {
                after
                    .parse::<NodeId>()
                    .map_err(|e| Error::Invalid(e.to_string()))
            })
            .transpose()?;
        let complete = row.try_read::<i64, _>("complete")? != 0;
        Ok(Some(cache::Scan { after, complete }))
    }

    /// Adds the COB tips of `remote`, scanned whole, to `rid`'s worklist at
    /// its `version`, and moves its scan past `remote`, in one durable
    /// transaction: a remote is in the worklist whole, or not at all. A
    /// `complete` scan has no remote left; one with no remote at all is
    /// recorded with none.
    pub fn scanned(
        &mut self,
        rid: &RepoId,
        version: Oid,
        remote: Option<&NodeId>,
        tips: &[cache::Tip],
        complete: bool,
    ) -> Result<(), Error> {
        transaction(&self.db, |db| {
            if let Some(remote) = remote {
                let remote = remote.to_string();
                for tip in tips {
                    let mut stmt = db.prepare(
                        "INSERT INTO rebuild_worklist (rid, kind, id, remote, tip)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT (rid, kind, id, remote) DO UPDATE SET tip = excluded.tip",
                    )?;
                    stmt.bind((1, rid))?;
                    stmt.bind((2, tip.kind.as_str()))?;
                    stmt.bind((3, tip.id.to_string().as_str()))?;
                    stmt.bind((4, remote.as_str()))?;
                    stmt.bind((5, tip.oid.to_string().as_str()))?;
                    stmt.next()?;
                }
            }
            let mut stmt = db.prepare(
                "INSERT INTO rebuild_scan (rid, version, after, complete) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (rid) DO UPDATE SET
                   version = excluded.version, after = excluded.after,
                   complete = excluded.complete",
            )?;
            stmt.bind((1, rid))?;
            stmt.bind((2, version.to_string().as_str()))?;
            stmt.bind((3, remote.map(|remote| remote.to_string()).as_deref()))?;
            stmt.bind((4, i64::from(complete)))?;
            stmt.next()?;
            Ok(())
        })
    }

    /// The next COBs of `kind` in `rid`'s worklist after `after`, at most
    /// `limit`, in the order of their IDs, and whether more remain.
    pub fn worklist(
        &self,
        rid: &RepoId,
        kind: cache::Kind,
        after: Option<&crate::cob::ObjectId>,
        limit: usize,
    ) -> Result<(Vec<crate::cob::ObjectId>, bool), Error> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT id FROM rebuild_worklist
             WHERE rid = ?1 AND kind = ?2 AND id > ?3 ORDER BY id LIMIT ?4",
        )?;
        stmt.bind((1, rid))?;
        stmt.bind((2, kind.as_str()))?;
        stmt.bind((
            3,
            after
                .map(|after| after.to_string())
                .unwrap_or_default()
                .as_str(),
        ))?;
        stmt.bind((
            4,
            i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX),
        ))?;
        let mut ids = Vec::with_capacity(limit.min(cache::BATCH_COBS) + 1);
        for row in stmt.into_iter() {
            let id = row?
                .try_read::<&str, _>("id")?
                .parse::<crate::cob::ObjectId>()
                .map_err(|e| Error::Invalid(e.to_string()))?;
            ids.push(id);
        }
        let more = ids.len() > limit;
        ids.truncate(limit);
        Ok((ids, more))
    }

    /// The tips of the COB `id` of `kind` in `rid`'s worklist: one for each
    /// remote that signed refs for it.
    pub fn tips(
        &self,
        rid: &RepoId,
        kind: cache::Kind,
        id: &crate::cob::ObjectId,
    ) -> Result<Vec<Oid>, Error> {
        let mut stmt = self.db.prepare(
            "SELECT tip FROM rebuild_worklist WHERE rid = ?1 AND kind = ?2 AND id = ?3
             ORDER BY remote",
        )?;
        stmt.bind((1, rid))?;
        stmt.bind((2, kind.as_str()))?;
        stmt.bind((3, id.to_string().as_str()))?;
        let mut tips = Vec::new();
        for row in stmt.into_iter() {
            let tip = row?
                .try_read::<&str, _>("tip")?
                .parse::<Oid>()
                .map_err(|e| Error::Invalid(e.to_string()))?;
            tips.push(tip);
        }
        Ok(tips)
    }

    /// Stages `row` for `rid`'s cache rebuild, in a durable transaction of
    /// its own: a batch's rows are staged as each is made, so that none is
    /// held for long. The batch's checkpoint follows them
    /// ([`State::save_cache_checkpoint`]). A row staged past the checkpoint,
    /// by a batch cut off, is staged again by the next.
    pub fn stage_row(&mut self, rid: &RepoId, row: &cache::Row) -> Result<(), Error> {
        transaction(&self.db, |db| {
            let mut stmt = db.prepare(
                "INSERT INTO rebuild_staging (rid, kind, id, json) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (rid, kind, id) DO UPDATE SET json = excluded.json",
            )?;
            stmt.bind((1, rid))?;
            stmt.bind((2, row.kind.as_str()))?;
            stmt.bind((3, row.id.to_string().as_str()))?;
            stmt.bind((4, row.json.as_str()))?;
            stmt.next()?;
            Ok(())
        })
    }

    /// Records `next` as the checkpoint of `rid`'s cache rebuild at its
    /// `version`, durably.
    pub fn save_cache_checkpoint(
        &mut self,
        rid: &RepoId,
        version: Oid,
        next: &cache::Checkpoint,
    ) -> Result<(), Error> {
        self.stage(rid, version, &[], next)
    }

    /// Stages `rows` for `rid`'s cache rebuild at its `version`, with the
    /// checkpoint `next`, in one durable transaction: a batch is staged with
    /// its checkpoint, or not at all.
    pub fn stage(
        &mut self,
        rid: &RepoId,
        version: Oid,
        rows: &[cache::Row],
        next: &cache::Checkpoint,
    ) -> Result<(), Error> {
        transaction(&self.db, |db| {
            for row in rows {
                let mut stmt = db.prepare(
                    "INSERT INTO rebuild_staging (rid, kind, id, json) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (rid, kind, id) DO UPDATE SET json = excluded.json",
                )?;
                stmt.bind((1, rid))?;
                stmt.bind((2, row.kind.as_str()))?;
                stmt.bind((3, row.id.to_string().as_str()))?;
                stmt.bind((4, row.json.as_str()))?;
                stmt.next()?;
            }
            let mut stmt = db.prepare(
                "INSERT INTO reconcile_cache (rid, version, kind, after) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (rid) DO UPDATE SET
                   version = excluded.version, kind = excluded.kind, after = excluded.after",
            )?;
            stmt.bind((1, rid))?;
            stmt.bind((2, version.to_string().as_str()))?;
            stmt.bind((3, next.kind.as_str()))?;
            stmt.bind((4, next.after.map(|after| after.to_string()).as_deref()))?;
            stmt.next()?;
            Ok(())
        })
    }

    /// Publishes `rid`'s rebuilt cache, once every COB is staged: its live
    /// rows are swapped for the staged ones, and its staging cleared, in one
    /// durable transaction. At a start, its `Cache` step is recorded finished
    /// in the same transaction; online, its progress is deleted with it, so a
    /// finished repair can't be reused once new mutations begin.
    pub fn publish(&mut self, rid: &RepoId, publication: Publication) -> Result<(), Error> {
        transaction(&self.db, |db| {
            for kind in cache::Kind::ALL {
                let (table, column) = kind.table();
                let mut stmt = db.prepare(format!("DELETE FROM {table} WHERE repo = ?1"))?;
                stmt.bind((1, rid))?;
                stmt.next()?;
                let mut stmt = db.prepare(format!(
                    "INSERT INTO {table} (id, repo, {column})
                     SELECT id, rid, json FROM rebuild_staging WHERE rid = ?1 AND kind = ?2"
                ))?;
                stmt.bind((1, rid))?;
                stmt.bind((2, kind.as_str()))?;
                stmt.next()?;
            }
            for table in [
                "rebuild_staging",
                "reconcile_cache",
                "rebuild_worklist",
                "rebuild_scan",
            ] {
                let mut stmt = db.prepare(format!("DELETE FROM {table} WHERE rid = ?1"))?;
                stmt.bind((1, rid))?;
                stmt.next()?;
            }
            match publication {
                Publication::Start => {
                    let mut stmt =
                        db.prepare("SELECT steps FROM reconcile_repository WHERE rid = ?1")?;
                    stmt.bind((1, rid))?;
                    let Some(row) = stmt.into_iter().next() else {
                        return Err(Error::Invalid(format!("no repair of {rid} has begun")));
                    };
                    let mut done = steps(row?.try_read::<&str, _>("steps")?)?;
                    done.insert(Step::Cache);
                    let text = done.iter().map(Step::as_str).collect::<Vec<_>>().join(",");
                    let mut stmt =
                        db.prepare("UPDATE reconcile_repository SET steps = ?2 WHERE rid = ?1")?;
                    stmt.bind((1, rid))?;
                    stmt.bind((2, text.as_str()))?;
                    stmt.next()?;
                }
                Publication::Online => discard(db, rid)?,
            }
            Ok(())
        })
    }

    /// Discards the progress of `rid`'s repair.
    pub fn clear_repository(&mut self, rid: &RepoId) -> Result<(), Error> {
        transaction(&self.db, |db| discard(db, rid))
    }

    /// Discards all progress, in one transaction: once a run has finished,
    /// before any new mutation could make it wrong.
    pub fn clear(&mut self) -> Result<(), Error> {
        transaction(&self.db, |db| {
            db.execute(
                "DELETE FROM reconcile_namespace;
                 DELETE FROM reconcile_repository;
                 DELETE FROM reconcile_unit;
                 DELETE FROM rebuild_staging;
                 DELETE FROM reconcile_cache;
                 DELETE FROM rebuild_worklist;
                 DELETE FROM rebuild_scan;",
            )?;
            Ok::<_, Error>(())
        })?;
        self.interrupted = None;
        Ok(())
    }
}

/// Records `unit` as the unit in progress, started `attempts` times.
fn record(db: &sql::Connection, unit: &Unit, attempts: u32) -> Result<(), Error> {
    let mut stmt = db.prepare(
        "INSERT INTO reconcile_unit (id, rid, kind, position, attempts)
         VALUES (1, ?1, ?2, ?3, ?4)
         ON CONFLICT (id) DO UPDATE SET
           rid = excluded.rid, kind = excluded.kind,
           position = excluded.position, attempts = excluded.attempts",
    )?;
    stmt.bind((1, &unit.rid))?;
    stmt.bind((2, unit.kind.as_str()))?;
    stmt.bind((3, unit.position.as_str()))?;
    stmt.bind((4, i64::from(attempts)))?;
    stmt.next()?;
    Ok(())
}

fn steps(text: &str) -> Result<BTreeSet<Step>, Error> {
    text.split(',')
        .filter(|step| !step.is_empty())
        .map(Step::from_str)
        .collect()
}

/// Deletes `rid`'s progress: its steps, its checkpoints, and its staged
/// cache rebuild.
fn discard(db: &sql::Connection, rid: &RepoId) -> Result<(), Error> {
    for table in [
        "reconcile_namespace",
        "reconcile_repository",
        "rebuild_staging",
        "reconcile_cache",
        "rebuild_worklist",
        "rebuild_scan",
    ] {
        let mut stmt = db.prepare(format!("DELETE FROM {table} WHERE rid = ?1"))?;
        stmt.bind((1, rid))?;
        stmt.next()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::{Signer as _, SigningKey};
    use crate::storage::git::Storage;
    use crate::storage::{ReadRepository as _, ReadStorage as _};
    use crate::test::{arbitrary, fixtures};

    fn rid() -> RepoId {
        arbitrary::r#gen(1)
    }

    fn oid(byte: u8) -> Oid {
        Oid::from(git::raw::Oid::from_bytes(&[byte; 20]).unwrap())
    }

    fn state() -> (tempfile::TempDir, State) {
        let tmp = tempfile::tempdir().unwrap();
        let state = State::open(tmp.path().join("cache.db")).unwrap();
        (tmp, state)
    }

    #[test]
    fn its_tables_sit_beside_the_cache_s_without_changing_its_version() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cache.db");
        let cache = crate::cob::cache::StoreWriter::open(&path)
            .unwrap()
            .with_migrations(crate::cob::cache::migrate::ignore)
            .unwrap();
        let before = cache.version().unwrap();
        let mut state = State::open(&path).unwrap();
        let mut stmt = state.db.prepare("PRAGMA synchronous").unwrap();
        stmt.next().unwrap();
        // `FULL` is 2.
        assert_eq!(stmt.read::<i64, _>(0).unwrap(), 2);
        drop(stmt);
        assert_eq!(cache.version().unwrap(), before);
        // Opened again, its tables and their rows stay.
        let rid = rid();
        state.begin(&rid, oid(1)).unwrap();
        state.finish(&rid, Step::RefLocks).unwrap();
        drop(state);
        let mut state = State::open(&path).unwrap();
        assert_eq!(state.begin(&rid, oid(1)).unwrap(), [Step::RefLocks].into());
    }

    #[test]
    fn a_repair_resumes_at_its_version_and_starts_over_at_another() {
        let (_tmp, mut state) = state();
        let (rid, other) = (rid(), rid());
        let nid = *SigningKey::mock(1).public_key();
        let at = Checkpoint {
            after: Some(RefString::try_from("refs/heads/master").unwrap()),
            stale: true,
        };

        assert!(state.begin(&rid, oid(1)).unwrap().is_empty());
        state.finish(&rid, Step::RefLocks).unwrap();
        state.finish(&rid, Step::Namespaces).unwrap();
        state
            .save_checkpoint(&rid, &nid, oid(7), Authority::Owner, &at)
            .unwrap();
        state.begin(&other, oid(1)).unwrap();
        state.finish(&other, Step::Cache).unwrap();

        // The same version: it resumes.
        assert_eq!(
            state.begin(&rid, oid(1)).unwrap(),
            [Step::RefLocks, Step::Namespaces].into()
        );
        assert_eq!(
            state
                .checkpoint(&rid, &nid, oid(7), Authority::Owner)
                .unwrap(),
            Some(at.clone())
        );
        // Another: its steps and checkpoints are gone, and no other
        // repository's.
        assert!(state.begin(&rid, oid(2)).unwrap().is_empty());
        assert_eq!(
            state
                .checkpoint(&rid, &nid, oid(7), Authority::Owner)
                .unwrap(),
            None
        );
        assert_eq!(state.begin(&other, oid(1)).unwrap(), [Step::Cache].into());
        assert!(state.finish(&self::tests::rid(), Step::Cache).is_err());
    }

    #[test]
    fn a_checkpoint_holds_at_its_namespace_s_version_and_authority_only() {
        let (_tmp, mut state) = state();
        let rid = rid();
        let nid = *SigningKey::mock(1).public_key();
        let at = Checkpoint {
            after: Some(RefString::try_from("refs/rad/id").unwrap()),
            stale: false,
        };
        state.begin(&rid, oid(1)).unwrap();
        state
            .save_checkpoint(&rid, &nid, oid(7), Authority::None, &at)
            .unwrap();
        let get = |version, authority| state.checkpoint(&rid, &nid, version, authority).unwrap();
        assert_eq!(get(oid(7), Authority::None), Some(at.clone()));
        // The namespace changed, or its key arrived: start over.
        assert_eq!(get(oid(8), Authority::None), None);
        assert_eq!(get(oid(7), Authority::Owner), None);
        // Another namespace has none.
        let other = *SigningKey::mock(2).public_key();
        assert_eq!(
            state
                .checkpoint(&rid, &other, oid(7), Authority::None)
                .unwrap(),
            None
        );
        // A later checkpoint replaces it.
        let later = Checkpoint {
            after: None,
            stale: true,
        };
        state
            .save_checkpoint(&rid, &nid, oid(7), Authority::None, &later)
            .unwrap();
        assert_eq!(
            state
                .checkpoint(&rid, &nid, oid(7), Authority::None)
                .unwrap(),
            Some(later)
        );
    }

    #[test]
    fn a_unit_cut_off_counts_its_attempts() {
        let (tmp, mut state) = state();
        let unit = Unit {
            rid: rid(),
            kind: "namespace".to_owned(),
            position: "z6Mk..@refs/heads/master".to_owned(),
        };
        assert_eq!(state.in_progress().unwrap(), None);
        assert_eq!(state.start(&unit).unwrap(), 1);
        // The process ends during it; the next one starts it again.
        drop(state);
        let mut state = State::open(tmp.path().join("cache.db")).unwrap();
        assert_eq!(
            state.in_progress().unwrap(),
            Some(InProgress {
                unit: unit.clone(),
                attempts: 1
            })
        );
        assert_eq!(state.start(&unit).unwrap(), 2);
        // Another unit starts at one.
        let next = Unit {
            position: "z6Mk..@refs/rad/id".to_owned(),
            ..unit.clone()
        };
        assert_eq!(state.start(&next).unwrap(), 1);
        state.end().unwrap();
        assert_eq!(state.in_progress().unwrap(), None);
        assert_eq!(state.start(&unit).unwrap(), 1);
    }

    #[test]
    fn a_cut_off_unit_s_record_outlasts_the_units_before_it_runs_again() {
        let (tmp, mut state) = state();
        let unit = Unit {
            rid: rid(),
            kind: "cache".to_owned(),
            position: "issue:".to_owned(),
        };
        let other = Unit {
            kind: "ref-locks".to_owned(),
            position: String::new(),
            ..unit.clone()
        };
        let reopen = |state: State| {
            drop(state);
            State::open(tmp.path().join("cache.db")).unwrap()
        };
        state.start(&unit).unwrap();
        // The process ends during it. The next one runs another unit first,
        // and ends before it reaches it again.
        let mut state = reopen(state);
        assert_eq!(state.start(&other).unwrap(), 1);
        state.end().unwrap();
        let interrupted = InProgress {
            unit: unit.clone(),
            attempts: 1,
        };
        assert_eq!(state.interrupted(), Some(&interrupted));
        assert_eq!(state.in_progress().unwrap(), Some(interrupted.clone()));
        // The one after still counts it as started once.
        let mut state = reopen(state);
        assert_eq!(state.interrupted(), Some(&interrupted));
        assert_eq!(state.start(&other).unwrap(), 1);
        state.end().unwrap();
        assert_eq!(state.start(&unit).unwrap(), 2);
        assert_eq!(state.interrupted(), None);
        // It ends during it again: the next process counts a third start,
        // after other units.
        let mut state = reopen(state);
        assert_eq!(state.start(&other).unwrap(), 1);
        state.end().unwrap();
        assert_eq!(state.start(&unit).unwrap(), 3);
        state.end().unwrap();
        assert_eq!(state.in_progress().unwrap(), None);
        assert_eq!(reopen(state).interrupted(), None);
    }

    #[test]
    fn clearing_leaves_no_progress() {
        let (_tmp, mut state) = state();
        let (a, b) = (rid(), rid());
        let nid = *SigningKey::mock(1).public_key();
        for rid in [a, b] {
            state.begin(&rid, oid(1)).unwrap();
            state.finish(&rid, Step::Namespaces).unwrap();
            state
                .save_checkpoint(&rid, &nid, oid(7), Authority::Owner, &Checkpoint::default())
                .unwrap();
        }
        state
            .start(&Unit {
                rid: a,
                kind: "cache".to_owned(),
                position: String::new(),
            })
            .unwrap();

        state.clear_repository(&a).unwrap();
        assert!(state.begin(&a, oid(1)).unwrap().is_empty());
        assert_eq!(state.begin(&b, oid(1)).unwrap(), [Step::Namespaces].into());

        state.clear().unwrap();
        assert!(state.begin(&b, oid(1)).unwrap().is_empty());
        assert_eq!(
            state
                .checkpoint(&b, &nid, oid(7), Authority::Owner)
                .unwrap(),
            None
        );
        assert_eq!(state.in_progress().unwrap(), None);
    }

    #[test]
    fn a_repository_s_version_changes_with_any_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = SigningKey::mock(0xb4);
        let storage = Storage::open(tmp.path().join("storage"), fixtures::user()).unwrap();
        let (rid, _, _, _) =
            fixtures::project(tmp.path().join("project"), &storage, &signer).unwrap();
        let repo = storage.repository(rid).unwrap();
        let before = version(&repo).unwrap();
        assert_eq!(version(&repo).unwrap(), before);
        let head = repo.backend.head().unwrap().target().unwrap();
        repo.backend
            .reference(
                "refs/namespaces/z6MkothernodeUNUSEDxxxxxxxxxxxxxxxxxxxxxxxxxxxx/refs/heads/x",
                head,
                true,
                "test",
            )
            .unwrap();
        let added = version(&repo).unwrap();
        assert_ne!(added, before);
        let tree = repo.backend.find_commit(head).unwrap().tree_id();
        repo.backend
            .reference(
                "refs/namespaces/z6MkothernodeUNUSEDxxxxxxxxxxxxxxxxxxxxxxxxxxxx/refs/heads/x",
                tree,
                true,
                "test",
            )
            .unwrap();
        assert_ne!(version(&repo).unwrap(), added);
    }

    /// A project's repository in a new storage, and its signer's node ID.
    fn project() -> (tempfile::TempDir, Repository, NodeId) {
        let tmp = tempfile::tempdir().unwrap();
        let signer = SigningKey::mock(0xb4);
        let storage = Storage::open(tmp.path().join("storage"), fixtures::user()).unwrap();
        let (rid, _, _, _) =
            fixtures::project(tmp.path().join("project"), &storage, &signer).unwrap();
        let repo = storage.repository(rid).unwrap();
        (tmp, repo, *signer.public_key())
    }

    // Review of heartwood #8, round 1: a ref whose name isn't UTF-8 is part of
    // the version, so that a repair's finished steps don't hold once one is
    // added.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_ref_with_a_name_that_isn_t_utf_8_changes_the_version() {
        use std::os::unix::ffi::OsStrExt as _;

        let (tmp, repo, nid) = project();
        let mut state = State::open(tmp.path().join("cache.db")).unwrap();
        let before = version(&repo).unwrap();
        state.begin(&repo.id, before).unwrap();
        state.finish(&repo.id, Step::Namespaces).unwrap();

        // A loose ref under the namespace, named with a byte that isn't
        // UTF-8, at a valid target.
        let head = repo.backend.head().unwrap().target().unwrap();
        let heads = repo
            .path()
            .join(format!("refs/namespaces/{nid}/refs/heads"));
        std::fs::create_dir_all(&heads).unwrap();
        std::fs::write(
            heads.join(std::ffi::OsStr::from_bytes(b"caf\xe9")),
            format!("{head}\n"),
        )
        .unwrap();
        let after = version(&repo).unwrap();
        assert_ne!(after, before);
        assert!(state.begin(&repo.id, after).unwrap().is_empty());
    }

    // Review of heartwood #8, round 1: a symbolic ref is taken by the name it
    // points at, unresolved: moved to another ref at the same commit, or left
    // dangling, it changes the version, and is never an error.
    #[test]
    fn a_symbolic_ref_is_taken_by_the_name_it_points_at() {
        let (_tmp, repo, nid) = project();
        let head = repo.backend.head().unwrap().target().unwrap();
        let name = |leaf: &str| format!("refs/namespaces/{nid}/refs/heads/{leaf}");
        for leaf in ["one", "two"] {
            repo.backend
                .reference(&name(leaf), head, true, "test")
                .unwrap();
        }
        repo.backend
            .reference_symbolic(&name("link"), &name("one"), true, "test")
            .unwrap();
        let one = version(&repo).unwrap();
        repo.backend
            .reference_symbolic(&name("link"), &name("two"), true, "test")
            .unwrap();
        let two = version(&repo).unwrap();
        assert_ne!(two, one);
        repo.backend
            .reference_symbolic(&name("link"), &name("gone"), true, "test")
            .unwrap();
        let dangling = version(&repo).unwrap();
        assert_ne!(dangling, two);
        assert_eq!(version(&repo).unwrap(), dangling);
    }

    // Review of heartwood #8, round 2: a symbolic ref that resolves through
    // `HEAD`, outside the refs libgit2 iterates, depends on it. Moving `HEAD`
    // changes the version, so that a repair's finished steps don't hold.
    #[test]
    fn a_symbolic_ref_through_head_changes_the_version_when_head_moves() {
        use super::super::namespace::{Check, Signed, check};
        use crate::storage::SignRepository as _;

        let (tmp, repo, nid) = project();
        let signer = SigningKey::mock(0xb4);
        let head = repo.backend.head().unwrap().target().unwrap();
        let parent = repo.backend.find_commit(head).unwrap();
        let who = git::raw::Signature::now("t", "t@example.com").unwrap();
        let other = repo
            .backend
            .commit(
                None,
                &who,
                &who,
                "other",
                &parent.tree().unwrap(),
                &[&parent],
            )
            .unwrap();
        repo.backend
            .reference("refs/heads/one", head, true, "test")
            .unwrap();
        repo.backend
            .reference("refs/heads/two", other, true, "test")
            .unwrap();
        repo.backend.set_head("refs/heads/one").unwrap();
        repo.backend
            .reference_symbolic(
                &format!("refs/namespaces/{nid}/refs/heads/link"),
                "HEAD",
                true,
                "test",
            )
            .unwrap();
        repo.sign_refs(&signer).unwrap();
        let checked = || {
            let signed = Signed::load(&repo, &nid).unwrap();
            let mut from = Checkpoint::default();
            loop {
                match check(&repo, &signed, Authority::None, &from, 1024).unwrap() {
                    Check::Continue(next) => from = next,
                    end => return end,
                }
            }
        };
        assert_eq!(checked(), Check::Clean);
        let mut state = State::open(tmp.path().join("cache.db")).unwrap();
        let before = version(&repo).unwrap();
        state.begin(&repo.id, before).unwrap();
        state.finish(&repo.id, Step::Namespaces).unwrap();

        // Only `HEAD` moves: the namespace no longer checks clean.
        repo.backend.set_head("refs/heads/two").unwrap();
        assert!(matches!(checked(), Check::Quarantine(_)));
        let after = version(&repo).unwrap();
        assert_ne!(after, before);
        assert!(state.begin(&repo.id, after).unwrap().is_empty());

        // `HEAD` itself left dangling is taken as it is, not an error.
        repo.backend
            .reference_symbolic("HEAD", "refs/heads/gone", true, "test")
            .unwrap();
        assert_ne!(version(&repo).unwrap(), after);
    }

    // Review of heartwood #8, round 2: a chain of symbolic refs outside
    // `refs/` is followed to its end.
    #[test]
    fn a_chain_of_symbolic_refs_outside_refs_is_followed() {
        let (_tmp, repo, nid) = project();
        let head = repo.backend.head().unwrap().target().unwrap();
        let parent = repo.backend.find_commit(head).unwrap();
        let who = git::raw::Signature::now("t", "t@example.com").unwrap();
        let other = repo
            .backend
            .commit(
                None,
                &who,
                &who,
                "other",
                &parent.tree().unwrap(),
                &[&parent],
            )
            .unwrap();
        repo.backend
            .reference("refs/heads/one", head, true, "test")
            .unwrap();
        repo.backend
            .reference("refs/heads/two", other, true, "test")
            .unwrap();
        repo.backend.set_head("refs/heads/one").unwrap();
        repo.backend
            .reference_symbolic("FIRST_HEAD", "HEAD", true, "test")
            .unwrap();
        repo.backend
            .reference_symbolic(
                &format!("refs/namespaces/{nid}/refs/heads/link"),
                "FIRST_HEAD",
                true,
                "test",
            )
            .unwrap();
        let before = version(&repo).unwrap();
        repo.backend.set_head("refs/heads/two").unwrap();
        assert_ne!(version(&repo).unwrap(), before);
    }

    // Review of heartwood #8, round 3: a namespace's symbolic ref that
    // resolves through a ref outside `refs/` whose name isn't UTF-8 depends on
    // a ref the version can't read. libgit2 follows it, so the version is
    // refused, rather than taking it as absent: no progress is recorded at a
    // version blind to it, or reused.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dependency_whose_name_isn_t_utf_8_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;

        use super::super::namespace::{Check, Signed, check};
        use crate::storage::SignRepository as _;

        let (_tmp, repo, nid) = project();
        let signer = SigningKey::mock(0xb4);
        let head = repo.backend.head().unwrap().target().unwrap();
        // A ref outside `refs/`, named with a byte that isn't UTF-8, at the
        // head commit; and the namespace's ref pointing at it.
        let outside = repo.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join(std::ffi::OsStr::from_bytes(b"raw-\xff")),
            format!("{head}\n"),
        )
        .unwrap();
        let link = repo
            .path()
            .join(format!("refs/namespaces/{nid}/refs/heads/link"));
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::fs::write(&link, b"ref: outside/raw-\xff\n").unwrap();
        // libgit2 resolves it.
        let resolved = repo
            .backend
            .find_reference(&format!("refs/namespaces/{nid}/refs/heads/link"))
            .unwrap()
            .resolve()
            .unwrap()
            .target()
            .unwrap();
        assert_eq!(resolved, head);
        repo.sign_refs(&signer).unwrap();
        let signed = Signed::load(&repo, &nid).unwrap();
        let mut from = Checkpoint::default();
        let clean = loop {
            match check(&repo, &signed, Authority::None, &from, 1024).unwrap() {
                Check::Continue(next) => from = next,
                end => break end,
            }
        };
        assert_eq!(clean, Check::Clean);

        assert!(matches!(version(&repo), Err(Error::Undecodable(_))));
    }
}
