//! The COB cache's rebuild: in bounded batches that resume where they
//! stopped, published at once.
//!
//! heartwood's own `write_all` clears a repository's cache rows and writes
//! them again in place, so a reader can see the cache half-built. Here:
//!
//! 1. **A scan** reads each remote's signed refs, verified, a remote at a
//!    time, and records every COB tip they sign in a worklist bound to the
//!    repository's version ([`scan`]). A tip no verified signed refs name is
//!    never read.
//! 2. **Batches** page the worklist by kind and ID. Each COB is loaded
//!    strictly from its tips, within [`LIMITS`] ([`materialize`]): any change
//!    that doesn't load, whose signature is invalid or whose actions don't
//!    apply fails it, rather than leaving a partial row. Each row is staged
//!    as it is made, and the batch's checkpoint after them ([`batch`]).
//! 3. **Publication** swaps the repository's live rows for the staged ones
//!    in one transaction, once every COB is staged
//!    ([`super::state::State::publish`]). Readers see the old cache, then the
//!    new one.

use std::fmt;
use std::io;
use std::str::FromStr;

use thiserror::Error;

use crate::cob;
use crate::cob::{ObjectId, TypeName};
use crate::git;
use crate::issue;
use crate::patch;
use crate::prelude::NodeId;
use crate::storage::RemoteRepository as _;
use crate::storage::git::Repository;

/// COBs a batch stages at most, in its usual form, whatever it is asked
/// for. Its smallest form stages one.
pub const BATCH_COBS: usize = 64;

/// Remotes a scan unit reads at most, in its usual form. Its smallest form
/// reads one.
pub const SCAN_REMOTES: usize = 16;

/// What one COB may take to materialize. One past any of these doesn't
/// load: it is a cache error, never an exhausted process.
/// - **Changes:** evaluating a history costs time on the order of the
///   square of its length, so this also bounds a unit's time.
/// - **Bytes:** what its changes' objects take, measured before each is
///   read.
pub const LIMITS: cob::Limits = cob::Limits {
    changes: 8_192,
    operations: 65_536,
    bytes: 64 * 1024 * 1024,
};

/// A row's JSON, at most.
pub const MAX_ROW: usize = 16 * 1024 * 1024;

/// The kinds of COB the cache holds, in the order a rebuild takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Issue,
    Patch,
}

impl Kind {
    /// The kinds, in the order a rebuild takes them.
    pub const ALL: [Kind; 2] = [Kind::Issue, Kind::Patch];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Patch => "patch",
        }
    }

    /// Its COBs' type.
    pub fn typename(&self) -> &'static TypeName {
        match self {
            Self::Issue => &issue::TYPENAME,
            Self::Patch => &patch::TYPENAME,
        }
    }

    /// The cache table of its rows, and the column of their JSON.
    pub(super) fn table(&self) -> (&'static str, &'static str) {
        match self {
            Self::Issue => ("issues", "issue"),
            Self::Patch => ("patches", "patch"),
        }
    }

    /// The kind a rebuild takes after it, if any.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Issue => Some(Self::Patch),
            Self::Patch => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Kind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "issue" => Ok(Self::Issue),
            "patch" => Ok(Self::Patch),
            other => Err(Error::Invalid(format!("unknown kind {other:?}"))),
        }
    }
}

/// Where a rebuild stands between batches: the kind it is at, and the last
/// COB of that kind it staged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub kind: Kind,
    pub after: Option<ObjectId>,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self {
            kind: Kind::Issue,
            after: None,
        }
    }
}

/// Where a rebuild's scan of its remotes stands: the last remote it read,
/// and whether it has read them all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub after: Option<NodeId>,
    pub complete: bool,
}

/// A COB's tip, as a remote's verified signed refs give it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip {
    pub kind: Kind,
    pub id: ObjectId,
    pub oid: git::Oid,
}

/// A COB as the cache holds it: its kind, its ID, and its JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub kind: Kind,
    pub id: ObjectId,
    pub json: String,
}

/// What [`batch`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Batch {
    /// It staged a batch: the next runs from this checkpoint.
    Continue(Checkpoint),
    /// Every COB is staged: the rebuild is ready to publish.
    Staged,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Git(#[from] git::raw::Error),
    #[error("COB {kind} {id} doesn't load: {reason}")]
    Cob {
        kind: Kind,
        id: ObjectId,
        reason: String,
    },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    State(#[from] super::state::Error),
    #[error("the signed refs of {remote} don't verify: {reason}")]
    Sigrefs { remote: NodeId, reason: String },
    #[error("the rebuild was stopped")]
    Stopped,
    #[error("invalid cache rebuild: {0}")]
    Invalid(String),
}

/// One unit of the scan of `repo`'s remotes, at its input `version`: up to
/// `limit` remotes after the last one scanned, in the order of their IDs,
/// each recorded whole with the scan's checkpoint. A remote's signed refs
/// are verified as they are read: one that doesn't verify fails the scan.
/// It returns whether every remote has been scanned.
pub fn scan(
    repo: &Repository,
    state: &mut super::state::State,
    version: git::Oid,
    limit: usize,
) -> Result<bool, Error> {
    let at = state.scan(&repo.id, version)?.unwrap_or_default();
    if at.complete {
        return Ok(true);
    }
    let mut remotes = Vec::new();
    for remote in repo.remote_ids()? {
        let remote = remote.map_err(|e| Error::Invalid(e.to_string()))?;
        if at.after.is_none_or(|after| remote > after) {
            remotes.push(remote);
        }
    }
    remotes.sort();
    remotes.dedup();
    if remotes.is_empty() {
        state.scanned(&repo.id, version, at.after.as_ref(), &[], true)?;
        return Ok(true);
    }
    let count = remotes.len();
    for (i, remote) in remotes.into_iter().take(limit.max(1)).enumerate() {
        let refs = repo.remote(&remote).map_err(|e| Error::Sigrefs {
            remote,
            reason: e.to_string(),
        })?;
        let tips = refs
            .refs
            .iter()
            .filter_map(|(name, oid)| {
                let (typename, id) = cob::object::parse_refstr(name)?;
                let kind = Kind::ALL
                    .into_iter()
                    .find(|kind| kind.typename() == &typename)?;
                Some(Tip {
                    kind,
                    id,
                    oid: *oid,
                })
            })
            .collect::<Vec<_>>();
        let last = i + 1 == count;
        state.scanned(&repo.id, version, Some(&remote), &tips, last)?;
        if last {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Materializes the COB `id` of `kind` from its tips in `state`'s worklist,
/// strictly, within [`LIMITS`] and [`MAX_ROW`]: its row, with its JSON as the
/// cache writes it. `None` if it has no tips. `stop` is asked between its
/// changes. One unit of a rebuild.
pub fn materialize(
    repo: &Repository,
    state: &super::state::State,
    kind: Kind,
    id: ObjectId,
    stop: &dyn Fn() -> bool,
) -> Result<Option<Row>, Error> {
    let tips = state.tips(&repo.id, kind, &id)?;
    materialize_within(repo, kind, id, &tips, &LIMITS, MAX_ROW, stop)
}

/// [`materialize`] from `tips`, within `limits` and a row of `max_row`
/// bytes.
pub fn materialize_within(
    repo: &Repository,
    kind: Kind,
    id: ObjectId,
    tips: &[git::Oid],
    limits: &cob::Limits,
    max_row: usize,
    stop: &dyn Fn() -> bool,
) -> Result<Option<Row>, Error> {
    let failed = |e: cob::StrictError| match e {
        cob::StrictError::Stopped => Error::Stopped,
        e => Error::Cob {
            kind,
            id,
            reason: e.to_string(),
        },
    };
    let json = match kind {
        Kind::Issue => {
            cob::get_strict::<issue::Issue, _>(repo, kind.typename(), &id, tips, limits, stop)
                .map_err(failed)?
                .map(|cob| capped(&cob.object, max_row))
        }
        Kind::Patch => {
            cob::get_strict::<patch::Patch, _>(repo, kind.typename(), &id, tips, limits, stop)
                .map_err(failed)?
                .map(|cob| capped(&cob.object, max_row))
        }
    };
    let Some(json) = json else {
        return Ok(None);
    };
    let json = json.map_err(|e| Error::Cob {
        kind,
        id,
        reason: e.to_string(),
    })?;
    Ok(Some(Row { kind, id, json }))
}

/// `object`'s JSON, unless it is longer than `max` bytes: written into a
/// buffer that refuses to grow past it, rather than whole first.
fn capped(object: &impl serde::Serialize, max: usize) -> Result<String, serde_json::Error> {
    struct Capped {
        bytes: Vec<u8>,
        max: usize,
    }
    impl io::Write for Capped {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.bytes.len() + buf.len() > self.max {
                return Err(io::Error::other(format!(
                    "the row's JSON is longer than {} bytes",
                    self.max
                )));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut out = Capped {
        bytes: Vec::new(),
        max,
    };
    serde_json::to_writer(&mut out, object)?;
    String::from_utf8(out.bytes).map_err(|e| serde_json::Error::io(io::Error::other(e)))
}

/// One batch of the rebuild of `repo`'s cache, at its input `version`, once
/// its scan is complete: up to `limit` COBs after `from`, at most
/// [`BATCH_COBS`], taken from the worklist and materialized one at a time,
/// each row staged as it is made, then the next checkpoint. Kinds follow each
/// other; after the last COB of the last kind, it is [`Batch::Staged`].
pub fn batch(
    repo: &Repository,
    state: &mut super::state::State,
    version: git::Oid,
    from: &Checkpoint,
    limit: usize,
    stop: &dyn Fn() -> bool,
) -> Result<Batch, Error> {
    if !state
        .scan(&repo.id, version)?
        .is_some_and(|scan| scan.complete)
    {
        return Err(Error::Invalid(
            "the scan of the repository's remotes isn't complete".to_owned(),
        ));
    }
    let limit = limit.clamp(1, BATCH_COBS);
    let mut at = from.clone();
    let mut taken = 0;
    let end = loop {
        let (ids, more) = state.worklist(&repo.id, at.kind, at.after.as_ref(), limit - taken)?;
        for id in ids {
            if let Some(row) = materialize(repo, state, at.kind, id, stop)? {
                state.stage_row(&repo.id, &row)?;
            }
            at.after = Some(id);
            taken += 1;
        }
        if more {
            break false;
        }
        match at.kind.next() {
            Some(kind) => {
                at = Checkpoint { kind, after: None };
                if taken >= limit {
                    break false;
                }
            }
            None => break true,
        }
    };
    state.save_cache_checkpoint(&repo.id, version, &at)?;
    Ok(if end {
        Batch::Staged
    } else {
        Batch::Continue(at)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::ops::ControlFlow;

    use super::*;
    use crate::cob::migrate;
    use crate::cob::patch::MergeTarget;
    use crate::crypto::Signer as _;
    use crate::storage::git::reconcile::state::{Publication, State, Step};
    use crate::storage::{ReadRepository as _, SignRepository as _};
    use crate::test;

    struct Fixture {
        _tmp: tempfile::TempDir,
        alice: test::setup::NodeWithRepo,
        path: std::path::PathBuf,
        cache: cob::cache::StoreWriter,
        state: State,
    }

    /// Alice's repository with three issues and two patches, and an empty
    /// cache beside it, and the reconcile state in the same database.
    fn fixture() -> Fixture {
        let alice = test::setup::NodeWithRepo::default();
        {
            let mut issues = issue::Cache::no_cache(&*alice.repo, &alice.signer).unwrap();
            for title in ["First", "Second", "Third"] {
                issues
                    .create(
                        cob::Title::new(title).unwrap(),
                        "Its description.",
                        &[],
                        &[],
                        [],
                    )
                    .unwrap();
            }
            let checkout = alice.repo.checkout();
            let mut patches = patch::Cache::no_cache(&*alice.repo, &alice.signer).unwrap();
            for (title, file) in [("A patch", "a.txt"), ("Another", "b.txt")] {
                let branch = checkout.branch_with([(file, b"Hello".as_slice())]);
                patches
                    .create(
                        cob::Title::new(title).unwrap(),
                        "Its description.",
                        MergeTarget::Delegates,
                        branch.base,
                        branch.oid,
                        &[],
                    )
                    .unwrap();
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(cob::cache::COBS_DB_FILE);
        let cache = cob::cache::StoreWriter::open(&path)
            .unwrap()
            .with_migrations(migrate::ignore)
            .unwrap();
        let state = State::open(&path).unwrap();
        Fixture {
            _tmp: tmp,
            alice,
            path,
            cache,
            state,
        }
    }

    impl Fixture {
        fn repo(&self) -> &Repository {
            &self.alice.repo
        }

        fn version(&self) -> git::Oid {
            super::super::state::version(self.repo()).unwrap()
        }

        /// The repository's live cache rows, by kind and ID.
        fn live(&self) -> BTreeMap<(Kind, String), String> {
            rows(&self.cache, self.repo().id)
        }

        /// Scans the repository's remotes at its version, whole.
        fn scan(&mut self) {
            let version = self.version();
            while !scan(&self.alice.repo, &mut self.state, version, SCAN_REMOTES).unwrap() {}
        }

        /// Every batch of a rebuild from `from`, with `limit` COBs each, its
        /// scan first: how many batches it took. More batches than COBs, and
        /// two more, fail the test.
        fn rebuild(&mut self, mut from: Checkpoint, limit: usize) -> usize {
            self.scan();
            let version = self.version();
            for batches in 1..=5 + 2 {
                match batch(
                    &self.alice.repo,
                    &mut self.state,
                    version,
                    &from,
                    limit,
                    &|| false,
                )
                .unwrap()
                {
                    Batch::Continue(next) => from = next,
                    Batch::Staged => return batches,
                }
            }
            panic!("a rebuild of five COBs ran past seven batches")
        }

        /// The IDs of the repository's COBs of `kind`, in order.
        fn ids(&self, kind: Kind) -> Vec<ObjectId> {
            let mut ids = Vec::new();
            let name = |name: &str| name.contains(&format!("/refs/cobs/{}/", kind.typename()));
            for r in self.repo().backend.references().unwrap() {
                let r = r.unwrap();
                let Some(name) = r.name().ok().filter(|n| name(n)) else {
                    continue;
                };
                let id = name.rsplit('/').next().unwrap().parse().unwrap();
                ids.push(id);
            }
            ids.sort();
            ids.dedup();
            ids
        }

        /// Staged rows, by kind and ID.
        fn staged(&self) -> BTreeMap<(Kind, String), String> {
            let mut rows = BTreeMap::new();
            self.cache
                .raw_query(|db| {
                    let mut stmt =
                        db.prepare("SELECT kind, id, json FROM rebuild_staging WHERE rid = ?1")?;
                    stmt.bind((1, &self.repo().id))?;
                    for row in stmt.into_iter() {
                        let row = row?;
                        rows.insert(
                            (
                                row.read::<&str, _>("kind").parse().unwrap(),
                                row.read::<&str, _>("id").to_owned(),
                            ),
                            row.read::<&str, _>("json").to_owned(),
                        );
                    }
                    Ok::<_, sqlite::Error>(())
                })
                .unwrap();
            rows
        }

        /// Appends a change of `action` to the issue `id`, signed by `signer`,
        /// under `signer`'s namespace, from the issue's tip there, or from
        /// `from`: past the typed API, which refuses an action that doesn't
        /// apply.
        fn append(
            &self,
            signer: &impl crate::crypto::Signer,
            id: &ObjectId,
            from: git::Oid,
            action: &issue::Action,
        ) -> git::Oid {
            use crate::cob::change::Storage as _;
            use crate::cob::object::Storage as _;

            let resource = self.repo().identity_head().unwrap();
            let entry = self
                .repo()
                .store(
                    Some(resource),
                    vec![],
                    signer,
                    cob::change::Template {
                        type_name: issue::TYPENAME.clone(),
                        tips: vec![from],
                        message: "A change".to_owned(),
                        embeds: vec![],
                        contents: nonempty::NonEmpty::new(serde_json::to_vec(action).unwrap()),
                    },
                )
                .unwrap();
            self.repo()
                .update(signer.public_key(), &issue::TYPENAME, id, &entry.id)
                .unwrap();
            entry.id
        }

        /// The tip of the COB `id` of `kind` under alice's namespace.
        fn tip(&self, kind: Kind, id: &ObjectId) -> git::Oid {
            let name = format!(
                "refs/namespaces/{}/refs/cobs/{}/{id}",
                self.alice.signer.public_key(),
                kind.typename()
            );
            self.repo().backend.refname_to_id(&name).unwrap().into()
        }
    }

    fn rows(
        cache: &cob::cache::StoreWriter,
        rid: crate::prelude::RepoId,
    ) -> BTreeMap<(Kind, String), String> {
        let mut rows = BTreeMap::new();
        for kind in Kind::ALL {
            let (table, column) = kind.table();
            cache
                .raw_query(|db| {
                    let mut stmt =
                        db.prepare(format!("SELECT id, {column} FROM {table} WHERE repo = ?1"))?;
                    stmt.bind((1, &rid))?;
                    for row in stmt.into_iter() {
                        let row = row?;
                        rows.insert(
                            (kind, row.read::<&str, _>("id").to_owned()),
                            row.read::<&str, _>(column).to_owned(),
                        );
                    }
                    Ok::<_, sqlite::Error>(())
                })
                .unwrap();
        }
        rows
    }

    /// The rows heartwood's own `write_all` writes for `repo`.
    fn written_all(repo: &Repository) -> BTreeMap<(Kind, String), String> {
        let cache = cob::cache::StoreWriter::memory()
            .unwrap()
            .with_migrations(migrate::ignore)
            .unwrap();
        {
            let store = issue::Issues::open(repo, cob::store::access::ReadOnly).unwrap();
            let mut issues = issue::Cache::new(store, cache.clone());
            issues.write_all(|_, _| ControlFlow::Continue(())).unwrap();
        }
        {
            let store = patch::Patches::open(repo, cob::store::access::ReadOnly).unwrap();
            let mut patches = patch::Cache::new(store, cache.clone());
            patches.write_all(|_, _| ControlFlow::Continue(())).unwrap();
        }
        rows(&cache, repo.id)
    }

    #[test]
    fn a_rebuild_stages_in_batches_and_publishes_at_once() {
        let mut f = fixture();
        let rid = f.repo().id;
        let expected = written_all(f.repo());
        assert_eq!(expected.len(), 5);
        // The live cache is out of date: a COB that is gone, and one whose row
        // is stale.
        let gone = ObjectId::from_str("0123456789abcdef0123456789abcdef01234567").unwrap();
        let (_, id) = expected.keys().next().unwrap().clone();
        f.cache
            .raw_query(|db| {
                db.execute(format!(
                    "INSERT INTO issues (id, repo, issue) VALUES ('{gone}', '{}', '{{}}'),
                     ('{id}', '{}', '{{}}')",
                    rid.urn(),
                    rid.urn()
                ))
            })
            .unwrap();
        let before = f.live();
        assert_eq!(before.len(), 2);

        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        // Three batches of two, the last one patch; the cache is unchanged
        // meanwhile.
        let mut from = Checkpoint::default();
        let mut batches = 0;
        loop {
            batches += 1;
            assert!(batches <= 7);
            match batch(&f.alice.repo, &mut f.state, version, &from, 2, &|| false).unwrap() {
                Batch::Continue(next) => {
                    assert_eq!(f.live(), before, "a reader saw the rebuild half-done");
                    assert_eq!(
                        f.state.cache_checkpoint(&rid, f.version()).unwrap(),
                        Some(next.clone())
                    );
                    from = next;
                }
                Batch::Staged => break,
            }
        }
        assert_eq!(batches, 3);
        assert_eq!(f.live(), before);

        f.state.publish(&rid, Publication::Start).unwrap();
        assert_eq!(
            f.live(),
            expected,
            "the rebuilt cache isn't heartwood's own"
        );
        assert!(
            f.state
                .begin(&rid, f.version())
                .unwrap()
                .contains(&Step::Cache)
        );
        assert_eq!(f.state.cache_checkpoint(&rid, f.version()).unwrap(), None);
        assert_eq!(f.state.scan(&rid, f.version()).unwrap(), None);
        // Publication cleared the staging and the worklist.
        assert!(f.staged().is_empty(), "publication left the staging");
        for kind in Kind::ALL {
            let (ids, _) = f.state.worklist(&rid, kind, None, BATCH_COBS).unwrap();
            assert!(ids.is_empty(), "publication left the {kind} worklist");
        }
    }

    #[test]
    fn a_rebuild_resumes_where_it_stopped() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        let Batch::Continue(at) = batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            1,
            &|| false,
        )
        .unwrap() else {
            panic!("staged at once")
        };
        // The process ends; the next one resumes from the recorded checkpoint.
        drop(std::mem::replace(
            &mut f.state,
            State::open(&f.path).unwrap(),
        ));
        assert!(f.state.begin(&rid, version).unwrap().is_empty());
        let from = f.state.cache_checkpoint(&rid, version).unwrap().unwrap();
        assert_eq!(from, at);
        // In its smallest form, one COB a batch: four more, as one is staged.
        assert_eq!(f.rebuild(from, 1), 4);
        f.state.publish(&rid, Publication::Start).unwrap();
        assert_eq!(f.live(), written_all(f.repo()));
    }

    #[test]
    fn a_changed_repository_starts_its_rebuild_over() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            2,
            &|| false,
        )
        .unwrap();
        assert!(f.state.cache_checkpoint(&rid, version).unwrap().is_some());

        // Another version: the scan, the staging and the checkpoint are
        // discarded.
        let other = git::Oid::from(git::raw::Oid::from_bytes(&[7; 20]).unwrap());
        f.state.begin(&rid, other).unwrap();
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), None);
        assert_eq!(f.state.scan(&rid, version).unwrap(), None);
        assert!(
            f.state
                .worklist(&rid, Kind::Issue, None, 64)
                .unwrap()
                .0
                .is_empty()
        );
        f.state.publish(&rid, Publication::Start).unwrap();
        assert!(f.live().is_empty(), "a discarded staging was published");
    }

    #[test]
    fn an_online_publication_deletes_the_repair_s_progress() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.state.finish(&rid, Step::Namespaces).unwrap();
        assert_eq!(f.rebuild(Checkpoint::default(), BATCH_COBS), 1);
        f.state.publish(&rid, Publication::Online).unwrap();
        assert_eq!(f.live(), written_all(f.repo()));
        // No completion record survives into the run.
        assert!(f.state.begin(&rid, version).unwrap().is_empty());
    }

    #[test]
    fn a_batch_needs_its_scan_complete() {
        let mut f = fixture();
        let version = f.version();
        assert!(matches!(
            batch(
                &f.alice.repo,
                &mut f.state,
                version,
                &Checkpoint::default(),
                1,
                &|| false
            ),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn a_cob_that_doesn_t_load_is_an_error() {
        let mut f = fixture();
        let rid = f.repo().id;
        let ids = f.ids(Kind::Issue);
        assert_eq!(ids.len(), 3);
        // The first issue's ref points at a blob, and alice signs it.
        let blob = f.repo().backend.blob(b"not a COB").unwrap();
        let name = format!(
            "refs/namespaces/{}/refs/cobs/{}/{}",
            f.alice.signer.public_key(),
            issue::TYPENAME.as_str(),
            ids[0]
        );
        f.repo()
            .backend
            .reference(&name, blob, true, "test")
            .unwrap();
        f.repo().sign_refs(&f.alice.signer).unwrap();
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        assert!(matches!(
            materialize(f.repo(), &f.state, Kind::Issue, ids[0], &|| false),
            Err(Error::Cob {
                kind: Kind::Issue,
                ..
            })
        ));
        assert!(matches!(
            batch(
                &f.alice.repo,
                &mut f.state,
                version,
                &Checkpoint::default(),
                BATCH_COBS,
                &|| false,
            ),
            Err(Error::Cob { .. })
        ));
        // The batch's checkpoint wasn't moved.
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), None);
    }

    #[test]
    fn a_cache_checkpoint_holds_at_its_version_only() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        let Batch::Continue(at) = batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            1,
            &|| false,
        )
        .unwrap() else {
            panic!("staged at once")
        };
        let other = git::Oid::from(git::raw::Oid::from_bytes(&[7; 20]).unwrap());
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), Some(at));
        assert_eq!(f.state.cache_checkpoint(&rid, other).unwrap(), None);
    }

    #[test]
    fn the_worklist_pages_cobs_in_order_after_a_checkpoint() {
        let mut f = fixture();
        let rid = f.repo().id;
        f.state.begin(&rid, f.version()).unwrap();
        f.scan();
        let all = f.ids(Kind::Issue);
        let (listed, more) = f
            .state
            .worklist(&rid, Kind::Issue, None, BATCH_COBS)
            .unwrap();
        assert!(!more);
        assert_eq!(listed, all);
        let (first, more) = f.state.worklist(&rid, Kind::Issue, None, 2).unwrap();
        assert!(more);
        assert_eq!(first, all[..2]);
        let (rest, more) = f
            .state
            .worklist(&rid, Kind::Issue, Some(&first[1]), 2)
            .unwrap();
        assert!(!more);
        assert_eq!(rest, all[2..]);
        assert_eq!(
            f.state
                .worklist(&rid, Kind::Patch, None, BATCH_COBS)
                .unwrap()
                .0,
            f.ids(Kind::Patch)
        );
    }

    #[test]
    // Review of heartwood #18, round 1: batches page the worklist the scan
    // made once; they don't look at the repository's refs again.
    fn batches_read_the_worklist_not_the_refs() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        // Every issue and patch ref is gone; their objects stay.
        let names = f
            .repo()
            .backend
            .references()
            .unwrap()
            .map(|r| r.unwrap().name().unwrap().to_owned())
            .filter(|name| {
                Kind::ALL
                    .iter()
                    .any(|kind| name.contains(&format!("/refs/cobs/{}/", kind.typename())))
            })
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 5);
        for name in names {
            f.repo()
                .backend
                .find_reference(&name)
                .unwrap()
                .delete()
                .unwrap();
        }
        assert_eq!(
            batch(
                &f.alice.repo,
                &mut f.state,
                version,
                &Checkpoint::default(),
                BATCH_COBS,
                &|| false
            )
            .unwrap(),
            Batch::Staged
        );
        assert_eq!(f.staged().len(), 5);
    }

    #[test]
    // Review of heartwood #18, round 1: the scan reads a remote at a time, and
    // resumes past the last one it recorded.
    fn a_scan_resumes_a_remote_at_a_time() {
        let mut f = fixture();
        let rid = f.repo().id;
        let id = f.ids(Kind::Issue)[0];
        // Bob comments on the first issue: a remote of his own, with signed
        // refs.
        let bob = crate::crypto::SigningKey::mock(80);
        {
            let mut issues = issue::Cache::no_cache(&*f.alice.repo, &bob).unwrap();
            let mut issue = issues.get_mut(&id).unwrap();
            let root = *issue.root().0;
            issue.comment("Bob's comment", root, []).unwrap();
        }
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        assert!(!scan(&f.alice.repo, &mut f.state, version, 1).unwrap());
        drop(std::mem::replace(
            &mut f.state,
            State::open(&f.path).unwrap(),
        ));
        assert!(scan(&f.alice.repo, &mut f.state, version, 1).unwrap());
        assert!(f.state.scan(&rid, version).unwrap().unwrap().complete);
        // The issue has a tip from each remote.
        assert_eq!(f.state.tips(&rid, Kind::Issue, &id).unwrap().len(), 2);
        // And the rebuild is the one heartwood writes, with Bob's comment.
        assert_eq!(f.rebuild(Checkpoint::default(), BATCH_COBS), 1);
        f.state.publish(&rid, Publication::Start).unwrap();
        assert_eq!(f.live(), written_all(f.repo()));
    }

    #[test]
    // Review of heartwood #18, round 1: a tip that no verified signed refs
    // name is never read. Eve's comment under her namespace, which has no
    // signed refs, isn't in the rebuilt issue, where heartwood's own
    // permissive load takes it.
    fn a_tip_no_signed_refs_name_is_never_read() {
        let mut f = fixture();
        let rid = f.repo().id;
        let id = f.ids(Kind::Issue)[0];
        let eve = crate::crypto::SigningKey::mock(81);
        {
            let mut issues = issue::Cache::no_cache(&*f.alice.repo, &eve).unwrap();
            let mut issue = issues.get_mut(&id).unwrap();
            let root = *issue.root().0;
            issue.comment("Eve's comment", root, []).unwrap();
        }
        // Eve's signed refs are gone; her COB ref stays.
        f.repo()
            .backend
            .find_reference(&format!(
                "refs/namespaces/{}/refs/rad/sigrefs",
                eve.public_key()
            ))
            .unwrap()
            .delete()
            .unwrap();
        let permissive = written_all(f.repo());
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        assert_eq!(
            f.state.tips(&rid, Kind::Issue, &id).unwrap(),
            [f.tip(Kind::Issue, &id)]
        );
        let row = materialize(f.repo(), &f.state, Kind::Issue, id, &|| false)
            .unwrap()
            .unwrap();
        assert!(!row.json.contains("Eve's comment"));
        assert!(permissive[&(Kind::Issue, id.to_string())].contains("Eve's comment"));
    }

    #[test]
    // Review of heartwood #18, round 1: a remote whose signed refs don't
    // verify fails the scan: none of its tips is taken.
    fn a_remote_whose_signed_refs_don_t_verify_fails_the_scan() {
        let mut f = fixture();
        let rid = f.repo().id;
        let eve = crate::crypto::SigningKey::mock(82);
        // Eve's signed refs are Alice's commit: not signed by Eve.
        let alice = f
            .repo()
            .backend
            .refname_to_id(&format!(
                "refs/namespaces/{}/refs/rad/sigrefs",
                f.alice.signer.public_key()
            ))
            .unwrap();
        f.repo()
            .backend
            .reference(
                &format!("refs/namespaces/{}/refs/rad/sigrefs", eve.public_key()),
                alice,
                true,
                "test",
            )
            .unwrap();
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        let err = scan(&f.alice.repo, &mut f.state, version, SCAN_REMOTES).unwrap_err();
        assert!(
            matches!(&err, Error::Sigrefs { remote, .. } if remote == eve.public_key()),
            "{err}"
        );
        assert!(
            !f.state
                .scan(&rid, version)
                .unwrap()
                .is_some_and(|scan| scan.complete)
        );
    }

    #[test]
    // Review of heartwood #18, round 1: a change whose signature doesn't
    // verify, under Alice's signed refs, fails its COB, where heartwood's own
    // load leaves its branch out.
    fn a_change_whose_signature_doesn_t_verify_fails_its_cob() {
        let mut f = fixture();
        let rid = f.repo().id;
        let id = f.ids(Kind::Issue)[0];
        let (first, second) = {
            let mut issues = issue::Cache::no_cache(&*f.alice.repo, &f.alice.signer).unwrap();
            let mut issue = issues.get_mut(&id).unwrap();
            let root = *issue.root().0;
            let first = issue.comment("First", root, []).unwrap();
            let second = issue.comment("Second", root, []).unwrap();
            (first, second)
        };
        // The second comment's commit, with the first's signature: it is over
        // another revision.
        let forged = {
            let odb = f.repo().backend.odb().unwrap();
            let header = |oid: git::Oid| {
                let commit = odb.read(oid.into()).unwrap();
                String::from_utf8(commit.data().to_vec()).unwrap()
            };
            let signature = |commit: &str| {
                let start = commit.find("\ngpgsig ").unwrap() + 1;
                let end = start + commit[start..].find("\n").unwrap();
                let mut end = end;
                while commit[end + 1..].starts_with(' ') {
                    end += 1 + commit[end + 1..].find("\n").unwrap();
                }
                (start, end)
            };
            let (tampered, original) = (header(second), header(first));
            let (s, e) = signature(&tampered);
            let (os, oe) = signature(&original);
            let forged = format!("{}{}{}", &tampered[..s], &original[os..oe], &tampered[e..]);
            odb.write(git::raw::ObjectType::Commit, forged.as_bytes())
                .unwrap()
        };
        let name = format!(
            "refs/namespaces/{}/refs/cobs/{}/{id}",
            f.alice.signer.public_key(),
            issue::TYPENAME.as_str()
        );
        f.repo()
            .backend
            .reference(&name, forged, true, "test")
            .unwrap();
        f.repo().sign_refs(&f.alice.signer).unwrap();

        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        let err = materialize(f.repo(), &f.state, Kind::Issue, id, &|| false).unwrap_err();
        assert!(
            matches!(&err, Error::Cob { reason, .. } if reason.contains("signature")),
            "{err}"
        );
    }

    #[test]
    // Review of heartwood #18, round 1: a change whose action doesn't apply,
    // a redaction of a comment that doesn't exist, under Alice's signed refs,
    // fails its COB, where heartwood's own load leaves its branch out.
    fn a_change_whose_action_doesn_t_apply_fails_its_cob() {
        let mut f = fixture();
        let rid = f.repo().id;
        let id = f.ids(Kind::Issue)[0];
        let nowhere = git::Oid::from(git::raw::Oid::from_bytes(&[9; 20]).unwrap());
        let tip = f.tip(Kind::Issue, &id);
        f.append(
            &f.alice.signer,
            &id,
            tip,
            &issue::Action::CommentRedact { id: nowhere },
        );
        f.repo().sign_refs(&f.alice.signer).unwrap();
        let permissive = written_all(f.repo());
        assert!(permissive.contains_key(&(Kind::Issue, id.to_string())));

        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        let err = materialize(f.repo(), &f.state, Kind::Issue, id, &|| false).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Cob {
                    kind: Kind::Issue,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    // Review of heartwood #18, round 1: a COB past any of its limits fails to
    // materialize, as a cache error, and a stopped load is stopped.
    fn a_cob_past_its_limits_fails() {
        let f = fixture();
        let id = f.ids(Kind::Issue)[0];
        {
            let mut issues = issue::Cache::no_cache(&*f.alice.repo, &f.alice.signer).unwrap();
            let mut issue = issues.get_mut(&id).unwrap();
            let root = *issue.root().0;
            issue.comment("A comment", root, []).unwrap();
        }
        let tips = [f.tip(Kind::Issue, &id)];
        let within = |limits: cob::Limits, max_row: usize| {
            materialize_within(f.repo(), Kind::Issue, id, &tips, &limits, max_row, &|| {
                false
            })
        };
        assert!(within(LIMITS, MAX_ROW).unwrap().is_some());
        for (limits, what) in [
            (
                cob::Limits {
                    changes: 1,
                    ..LIMITS
                },
                "changes",
            ),
            (
                cob::Limits {
                    operations: 1,
                    ..LIMITS
                },
                "operations",
            ),
            (
                cob::Limits {
                    bytes: 64,
                    ..LIMITS
                },
                "bytes",
            ),
        ] {
            let err = within(limits, MAX_ROW).unwrap_err();
            assert!(
                matches!(&err, Error::Cob { reason, .. } if reason.contains(what)),
                "{what}: {err}"
            );
        }
        assert!(matches!(within(LIMITS, 16), Err(Error::Cob { .. })));
        assert!(matches!(
            materialize_within(f.repo(), Kind::Issue, id, &tips, &LIMITS, MAX_ROW, &|| true),
            Err(Error::Stopped)
        ));
    }

    #[test]
    // Review of heartwood #18, round 1: a COB's tips must lead to its own
    // history: another issue's tip, or a patch's, fails it.
    fn a_tip_of_another_cob_fails_it() {
        let f = fixture();
        let [issue, other] = [0, 1].map(|i| f.ids(Kind::Issue)[i]);
        let patch = f.ids(Kind::Patch)[0];
        let within = |tips: &[git::Oid]| {
            materialize_within(
                f.repo(),
                Kind::Issue,
                issue,
                tips,
                &LIMITS,
                MAX_ROW,
                &|| false,
            )
        };
        let ours = f.tip(Kind::Issue, &issue);
        assert!(within(&[ours]).unwrap().is_some());
        let err = within(&[ours, f.tip(Kind::Issue, &other)]).unwrap_err();
        assert!(
            matches!(&err, Error::Cob { reason, .. } if reason.contains("another root")),
            "{err}"
        );
        let err = within(&[f.tip(Kind::Patch, &patch)]).unwrap_err();
        assert!(
            matches!(&err, Error::Cob { reason, .. } if reason.contains("type")),
            "{err}"
        );
    }

    #[test]
    // Review of heartwood #18, round 1: a change that is measured but doesn't
    // load, a plain commit on the COB's tip with no manifest, fails its COB,
    // where heartwood's own load leaves it out.
    fn a_change_that_doesn_t_load_fails_its_cob() {
        let f = fixture();
        let id = f.ids(Kind::Issue)[0];
        let ours = f.tip(Kind::Issue, &id);
        let plain = {
            let backend = &f.repo().backend;
            let tree = backend.treebuilder(None).unwrap().write().unwrap();
            let tree = backend.find_tree(tree).unwrap();
            let parent = backend.find_commit(ours.into()).unwrap();
            let author = git::raw::Signature::now("alice", "alice@example.com").unwrap();
            git::Oid::from(
                backend
                    .commit(None, &author, &author, "Not a change", &tree, &[&parent])
                    .unwrap(),
            )
        };
        let within = |tips: &[git::Oid]| {
            materialize_within(f.repo(), Kind::Issue, id, tips, &LIMITS, MAX_ROW, &|| false)
        };
        assert!(within(&[ours]).unwrap().is_some());
        let err = within(&[ours, plain]).unwrap_err();
        assert!(
            matches!(&err, Error::Cob { reason, .. } if reason.contains("doesn't load")),
            "{err}"
        );
    }

    #[test]
    // Review of heartwood #18, round 1: a batch takes at most [`BATCH_COBS`],
    // whatever it is asked for.
    fn a_batch_takes_at_most_its_usual_size() {
        let mut f = fixture();
        let rid = f.repo().id;
        {
            let mut issues = issue::Cache::no_cache(&*f.alice.repo, &f.alice.signer).unwrap();
            for i in 0..BATCH_COBS - 2 {
                issues
                    .create(
                        cob::Title::new(&format!("Issue {i}")).unwrap(),
                        "Its description.",
                        &[],
                        &[],
                        [],
                    )
                    .unwrap();
            }
        }
        let issues = f.ids(Kind::Issue);
        assert_eq!(issues.len(), BATCH_COBS + 1);
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        let next = batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            BATCH_COBS + 1,
            &|| false,
        )
        .unwrap();
        assert_eq!(
            next,
            Batch::Continue(Checkpoint {
                kind: Kind::Issue,
                after: Some(issues[BATCH_COBS - 1]),
            })
        );
        assert_eq!(f.staged().len(), BATCH_COBS);
    }

    #[test]
    // Review of heartwood #18, round 1: each row is staged as it is made, so
    // a batch holds none for long: those before a COB that fails are staged,
    // and the batch's checkpoint, after them, isn't.
    fn a_batch_stages_each_row_as_it_is_made() {
        let mut f = fixture();
        let rid = f.repo().id;
        let ids = f.ids(Kind::Issue);
        let nowhere = git::Oid::from(git::raw::Oid::from_bytes(&[9; 20]).unwrap());
        let last = ids[2];
        let tip = f.tip(Kind::Issue, &last);
        f.append(
            &f.alice.signer,
            &last,
            tip,
            &issue::Action::CommentRedact { id: nowhere },
        );
        f.repo().sign_refs(&f.alice.signer).unwrap();
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        f.scan();
        assert!(
            batch(
                &f.alice.repo,
                &mut f.state,
                version,
                &Checkpoint::default(),
                BATCH_COBS,
                &|| false
            )
            .is_err()
        );
        assert_eq!(
            f.staged().keys().cloned().collect::<Vec<_>>(),
            ids[..2]
                .iter()
                .map(|id| (Kind::Issue, id.to_string()))
                .collect::<Vec<_>>()
        );
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), None);
    }
}
