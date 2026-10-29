//! The reconciliation driver: design 0008's repairs, run as units in order,
//! each recorded in progress before it starts.
//!
//! [`run`] reconciles a storage at a start, before a node runs on it: its
//! temporary clones and its repositories' ref lock files, always; and, when
//! the dirty marker was present, the namespaces it names, in every
//! repository, and every COB cache. [`Repair`] is the repair of one
//! repository, one unit a step: [`run`] runs one for each repository, and
//! the host runs one online after an uncertain write ([`Repair::online`]).
//!
//! - **A unit** is recorded in progress before it starts ([`State::start`]),
//!   and its record cleared once it returns. The host's [`Watch`] is told of
//!   each, for its watchdog. The deadline and the cancel token ([`Stop`]) are
//!   checked between units, never within one; only a cut off batch's commit
//!   runs after either.
//! - **The escape.** A unit the last process ended during
//!   ([`State::interrupted`]) runs again in its smallest form: one ref at a
//!   time for the refs that namespace unit held, and one COB a batch for the
//!   COBs that batch held. A unit in progress when two processes ended
//!   quarantines its repository instead of running a third time. A unit that
//!   fails with an error quarantines it at once.
//! - **Failures outside any one repository,** of the storage directory, the
//!   progress state or the quarantine record, are an [`Error`]: nothing is
//!   deleted to make the start succeed.
//! - **Reports** give counts and repository IDs, never paths inside a
//!   repository.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::io;
use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use localtime::LocalTime;
use thiserror::Error;

use crate::cob::ObjectId;
use crate::crypto;
use crate::git::Oid;
use crate::prelude::{NodeId, RepoId};
use crate::storage::git::{Repository, Storage};
use crate::storage::{ReadRepository as _, ReadStorage as _};

use super::cache;
use super::namespace::{self, Authority, Check, Checkpoint, Complete, Signed};
use super::quarantine::{self, Quarantine, Record};
use super::state::{self, Publication, State, Step, Unit};

/// The quarantine records a report gives at most.
pub const REPORTED: usize = 16;

/// How many processes have started a unit when it quarantines its
/// repository instead of running: two before this one ended during it.
const POISON: u32 = 3;

/// The kinds of unit, as their in-progress records name them.
pub mod kind {
    /// Removing one temporary clone. Its position is the clone's name.
    pub const CLONE: &str = "clone";
    /// Opening a repository and reading its version.
    pub const BEGIN: &str = "begin";
    /// Removing one repository's ref lock files.
    pub const REF_LOCKS: &str = "ref-locks";
    /// Reading a namespace's version and loading its signed refs, to begin its
    /// check. Its position is the namespace.
    pub const NAMESPACE_BEGIN: &str = "namespace-begin";
    /// Checking a namespace's next refs, from a checkpoint. Its position is
    /// the namespace and the last ref checked before it, `<namespace>:<ref>`.
    pub const NAMESPACE: &str = "namespace";
    /// Re-signing the running identity's namespace. Its position is the
    /// namespace.
    pub const RESIGN: &str = "resign";
    /// Listing a cache batch's COBs. Its position is the checkpoint it lists
    /// from, `<kind>:<id>`.
    pub const CACHE_LIST: &str = "cache-list";
    /// Materializing one COB. Its position is the COB, `<kind>:<id>`.
    pub const CACHE: &str = "cache";
    /// Committing a batch with its checkpoint. Its position is the
    /// checkpoint.
    pub const CACHE_COMMIT: &str = "cache-commit";
    /// Publishing a rebuilt cache.
    pub const PUBLISH: &str = "publish";
}

/// The step a quarantine names when a repository doesn't open.
const BEGIN_STEP: &str = "begin";

/// When a run stops between units: once its token is set, or its cutoff
/// passed. No unit starts after either, but a cut off batch's commit.
#[derive(Clone, Debug, Default)]
pub struct Stop {
    pub cancel: Arc<AtomicBool>,
    pub cutoff: Option<Instant>,
}

impl Stop {
    /// Why no unit may start now, if one may not.
    fn now(&self) -> Option<Ending> {
        if self.cancel.load(Ordering::Acquire) {
            Some(Ending::Cancelled)
        } else if self.cutoff.is_some_and(|cutoff| Instant::now() >= cutoff) {
            Some(Ending::Deadline)
        } else {
            None
        }
    }
}

/// What the host's watchdog is told: each unit as it starts, and its end.
/// A unit that doesn't return can't be interrupted from inside the process,
/// so its time limit is the host's to enforce.
pub trait Watch {
    /// `unit` is about to start.
    fn started(&self, _unit: &Unit) {}
    /// The unit that started last has returned.
    fn ended(&self) {}
}

impl Watch for () {}

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Every repair is done, or its repository quarantined. The progress
    /// state is cleared.
    Done,
    /// The cutoff passed. The progress state is kept, for the next run.
    Deadline,
    /// The token was set. The progress state is kept.
    Cancelled,
}

/// What a run did: counts, and repository IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub ending: Ending,
    /// Whether the dirty marker was present.
    pub dirty: bool,
    /// Temporary clones removed.
    pub clones: usize,
    /// Entries in the storage with an extension that were left alone.
    pub left: usize,
    /// Ref lock files removed.
    pub locks: usize,
    /// Namespace checks finished: clean, or stale and re-signed.
    pub namespaces: usize,
    /// The repositories whose own namespace was re-signed: each is to be
    /// announced once the node runs.
    pub resigned: Vec<RepoId>,
    /// COB caches rebuilt and published.
    pub caches: usize,
    /// The repositories this run quarantined.
    pub newly_quarantined: Vec<RepoId>,
    /// How many repositories are quarantined, in all.
    pub quarantined: usize,
    /// The first of them, in the order of their IDs, at most [`REPORTED`].
    pub first: Vec<Record>,
}

/// A failure outside any one repository: reconciliation can't go on.
#[derive(Debug, Error)]
pub enum Error {
    #[error("the storage: {0}")]
    Io(#[from] io::Error),
    #[error("the reconcile state: {0}")]
    State(#[from] state::Error),
    #[error("the quarantine record: {0}")]
    Quarantine(#[from] quarantine::Error),
    #[error(transparent)]
    Fsync(#[from] super::FsyncError),
    #[error("the temporary clone {name:?} wasn't removed: {reason}")]
    Clone { name: OsString, reason: String },
    #[error("the {kind} unit at {position:?} was in progress when two processes ended")]
    Poison { kind: String, position: String },
    #[error("a repair's step ran before it began")]
    NotBegun,
}

/// What a step of a repair did.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// It ran a unit, and more remain.
    More,
    /// The repair is done.
    Done,
    /// Its repository is quarantined, by this record: the repair is over.
    Quarantined(Record),
    /// No unit may start now.
    Stopped(Ending),
}

/// What a repair works with.
pub struct Context<'a, S> {
    pub storage: &'a Storage,
    /// The progress, in `cobs/cache.db`, beside the cache it rebuilds.
    pub state: &'a mut State,
    pub quarantine: &'a mut Quarantine,
    /// The running identity's key: it re-signs its own namespace, and no
    /// other. A throwaway key owns no namespace, so it signs nothing.
    pub signer: Option<&'a S>,
    pub stop: &'a Stop,
    pub watch: &'a dyn Watch,
}

/// What running a unit gave.
enum Ran<T> {
    Done(T),
    /// It failed, or was in progress when two processes ended.
    Failed(Failed),
    /// No unit may start now.
    Stopped(Ending),
}

/// Why a unit didn't finish.
enum Failed {
    /// It returned an error: the evidence.
    Error(String),
    /// It was in progress when two processes ended.
    Poison,
}

impl Failed {
    fn evidence(self) -> String {
        match self {
            Self::Error(evidence) => evidence,
            Self::Poison => "in progress when two processes ended".to_owned(),
        }
    }
}

/// A unit's work: its result, an error within the repository as its
/// evidence, or a failure outside it.
type Work<T> = Result<Result<T, String>, Error>;

impl<S> Context<'_, S> {
    /// Runs `work` as one unit, unless a unit may not start now.
    fn unit<T>(
        &mut self,
        unit: &Unit,
        work: impl FnOnce(&mut State) -> Work<T>,
    ) -> Result<Ran<T>, Error> {
        if let Some(ending) = self.stop.now() {
            return Ok(Ran::Stopped(ending));
        }
        self.run_unit(unit, work)
    }

    /// Runs `work` as one unit, whatever the stop says: recorded in progress
    /// first, and the record cleared once it returns. A unit started a third
    /// time doesn't run, and its record stays.
    fn run_unit<T>(
        &mut self,
        unit: &Unit,
        work: impl FnOnce(&mut State) -> Work<T>,
    ) -> Result<Ran<T>, Error> {
        if self.state.start(unit)? >= POISON {
            return Ok(Ran::Failed(Failed::Poison));
        }
        self.watch.started(unit);
        let result = work(&mut *self.state);
        self.watch.ended();
        // A failure outside the repository ends the unit too: only a
        // process's end counts as an attempt.
        let ended = self.state.end();
        let result = result?;
        ended?;
        Ok(match result {
            Ok(value) => Ran::Done(value),
            Err(evidence) => Ran::Failed(Failed::Error(evidence)),
        })
    }

    /// Quarantines `rid`, for `unit` of `step`, which didn't finish.
    fn quarantined(
        &mut self,
        rid: RepoId,
        kind: quarantine::Kind,
        step: &str,
        unit: &Unit,
        failed: Failed,
    ) -> Result<Progress, Error> {
        let record = self.quarantine.quarantine(
            rid,
            kind,
            step,
            Some(&format!("{}@{}", unit.kind, unit.position)),
            &failed.evidence(),
            LocalTime::now(),
        )?;
        Ok(Progress::Quarantined(record))
    }
}

/// A namespace check in progress.
struct Pass {
    namespace: NodeId,
    version: Oid,
    authority: Authority,
    signed: Signed,
    from: Checkpoint,
    /// The check's proof, once it ended stale: the next unit re-signs.
    complete: Option<Complete>,
}

/// Where a COB cache rebuild stands.
enum Rebuild {
    /// The next batch is to be listed.
    List,
    /// A batch's COBs are being materialized.
    Batch(Batch),
    /// Every COB is staged: the cache is to be published.
    Publish,
}

/// A batch in progress: its COBs left to materialize, its rows so far, and
/// where it stands.
struct Batch {
    ids: VecDeque<ObjectId>,
    /// Whether COBs of its kind remain after it.
    more: bool,
    rows: Vec<cache::Row>,
    at: cache::Checkpoint,
    /// How many of its COBs have been materialized.
    taken: usize,
}

/// The step of a repair that runs in its smallest form, because the last
/// process ended during one of its units, and for how many more pieces: as
/// many as that unit held in its usual form.
enum Small {
    /// The check of this namespace, one ref a unit.
    Namespace { namespace: NodeId, left: usize },
    /// The cache rebuild, one COB a batch.
    Cache { left: usize },
}

/// What a repair knows once it has begun.
struct Begun {
    repo: Repository,
    version: Oid,
    done: BTreeSet<Step>,
    small: Option<Small>,
}

/// What a repair did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Did {
    /// Ref lock files removed.
    pub locks: usize,
    /// Namespace checks finished.
    pub namespaces: usize,
    /// Whether it re-signed the running identity's namespace.
    pub resigned: bool,
    /// Whether it published a rebuilt cache.
    pub cache: bool,
}

/// The repair of one repository, one unit a [`step`](Self::step): its ref
/// lock files, if asked; the namespaces it is given; and its COB cache, if
/// asked. Each unit's work is recorded, so a repair cut off resumes where it
/// stopped, in a new `Repair` of the same repository.
pub struct Repair {
    rid: RepoId,
    locks: bool,
    namespaces: VecDeque<NodeId>,
    cache: bool,
    publication: Publication,
    begun: Option<Begun>,
    pass: Option<Pass>,
    rebuild: Rebuild,
    did: Did,
}

impl Repair {
    /// The repair of `rid` at a start: its ref lock files; and, when the dirty
    /// marker was present and names `dirty`, those namespaces and its COB
    /// cache.
    pub fn start(rid: RepoId, dirty: Option<&BTreeSet<NodeId>>) -> Self {
        Self {
            rid,
            locks: true,
            namespaces: dirty.into_iter().flatten().copied().collect(),
            cache: dirty.is_some(),
            publication: Publication::Start,
            begun: None,
            pass: None,
            rebuild: Rebuild::List,
            did: Did::default(),
        }
    }

    /// The repair of `rid` online, while the node runs, after an uncertain
    /// write by `own`, the running identity: its namespace, then its COB
    /// cache, whose publication deletes the repository's progress. The host
    /// runs it with the repository gated, and the dirty marker present.
    pub fn online(rid: RepoId, own: NodeId) -> Self {
        Self {
            rid,
            locks: false,
            namespaces: [own].into(),
            cache: true,
            publication: Publication::Online,
            begun: None,
            pass: None,
            rebuild: Rebuild::List,
            did: Did::default(),
        }
    }

    /// The repository it repairs.
    pub fn rid(&self) -> RepoId {
        self.rid
    }

    /// What it has done so far.
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// Runs the repair's next unit.
    pub fn step<S: crypto::Signer>(&mut self, cx: &mut Context<'_, S>) -> Result<Progress, Error> {
        let Some(begun) = &mut self.begun else {
            return self.begin(cx);
        };
        if self.locks && !begun.done.contains(&Step::RefLocks) {
            return self.ref_locks(cx);
        }
        if !begun.done.contains(&Step::Namespaces) {
            if self.pass.is_some() || !self.namespaces.is_empty() {
                return self.namespace(cx);
            }
            // An online repair records no step: its namespace is the running
            // identity's alone, and a start's marker may name more.
            if self.publication == Publication::Start {
                cx.state.finish(&self.rid, Step::Namespaces)?;
            }
            begun.done.insert(Step::Namespaces);
        }
        if self.cache && !begun.done.contains(&Step::Cache) {
            return self.rebuild(cx);
        }
        Ok(Progress::Done)
    }

    /// Opens the repository and begins, or resumes, its repair at its
    /// version, as a unit.
    fn begin<S>(&mut self, cx: &mut Context<'_, S>) -> Result<Progress, Error> {
        super::enable_fsync()?;
        let rid = self.rid;
        // The unit the last process ended during, if it is this repository's:
        // read before this repair's first unit could take it.
        let small = cx
            .state
            .interrupted()
            .filter(|interrupted| interrupted.unit.rid == rid)
            .and_then(|interrupted| small(&interrupted.unit));
        let unit = Unit {
            rid,
            kind: kind::BEGIN.to_owned(),
            position: String::new(),
        };
        let storage = cx.storage;
        let ran = cx.unit(&unit, |state| {
            let repo = match storage.repository(rid) {
                Ok(repo) => repo,
                Err(e) => return Ok(Err(e.to_string())),
            };
            let version = match state::version(&repo) {
                Ok(version) => version,
                Err(e) => return Ok(Err(e.to_string())),
            };
            let done = state.begin(&rid, version)?;
            Ok(Ok(Begun {
                repo,
                version,
                done,
                small,
            }))
        })?;
        match ran {
            Ran::Done(begun) => {
                self.begun = Some(begun);
                Ok(Progress::More)
            }
            Ran::Failed(failed) => {
                cx.quarantined(rid, quarantine::Kind::Namespace, BEGIN_STEP, &unit, failed)
            }
            Ran::Stopped(ending) => Ok(Progress::Stopped(ending)),
        }
    }

    /// Removes the repository's ref lock files, as a unit.
    fn ref_locks<S>(&mut self, cx: &mut Context<'_, S>) -> Result<Progress, Error> {
        let rid = self.rid;
        let begun = self.begun.as_mut().ok_or(Error::NotBegun)?;
        let unit = Unit {
            rid,
            kind: kind::REF_LOCKS.to_owned(),
            position: String::new(),
        };
        let path = begun.repo.path().to_path_buf();
        let ran = cx.unit(&unit, |state| {
            let removed = match super::remove_ref_locks(&path) {
                Ok(removed) => removed,
                Err(e) => return Ok(Err(e.to_string())),
            };
            state.finish(&rid, Step::RefLocks)?;
            Ok(Ok(removed))
        })?;
        match ran {
            Ran::Done(removed) => {
                begun.done.insert(Step::RefLocks);
                self.did.locks += removed;
                Ok(Progress::More)
            }
            Ran::Failed(failed) => cx.quarantined(
                rid,
                quarantine::Kind::Namespace,
                Step::RefLocks.as_str(),
                &unit,
                failed,
            ),
            Ran::Stopped(ending) => Ok(Progress::Stopped(ending)),
        }
    }

    /// The next unit of the namespace checks.
    fn namespace<S: crypto::Signer>(&mut self, cx: &mut Context<'_, S>) -> Result<Progress, Error> {
        let rid = self.rid;
        let begun = self.begun.as_mut().ok_or(Error::NotBegun)?;
        let signer = cx.signer;
        let step = Step::Namespaces.as_str();

        // Begin the next namespace's check: its version, its authority, its
        // checkpoint, and its signed refs, loaded once for the pass.
        let Some(pass) = &mut self.pass else {
            let Some(&namespace) = self.namespaces.front() else {
                return Ok(Progress::More);
            };
            let unit = Unit {
                rid,
                kind: kind::NAMESPACE_BEGIN.to_owned(),
                position: namespace.to_string(),
            };
            let authority = Authority::of(&namespace, signer.map(|signer| signer.public_key()));
            let repo = &begun.repo;
            let ran = cx.unit(&unit, |state| {
                let version = match namespace::version(repo, &namespace) {
                    Ok(version) => version,
                    Err(e) => return Ok(Err(e.to_string())),
                };
                let from = state
                    .checkpoint(&rid, &namespace, version, authority)?
                    .unwrap_or_default();
                Ok(Signed::load(repo, &namespace)
                    .map(|signed| (version, from, signed))
                    .map_err(|e| e.to_string()))
            })?;
            return match ran {
                Ran::Done((version, from, signed)) => {
                    self.namespaces.pop_front();
                    self.pass = Some(Pass {
                        namespace,
                        version,
                        authority,
                        signed,
                        from,
                        complete: None,
                    });
                    Ok(Progress::More)
                }
                Ran::Failed(failed) => {
                    cx.quarantined(rid, quarantine::Kind::Namespace, step, &unit, failed)
                }
                Ran::Stopped(ending) => Ok(Progress::Stopped(ending)),
            };
        };

        // The check found the namespace stale: re-sign it, with its own key.
        if pass.complete.is_some() {
            if let Some(ending) = cx.stop.now() {
                return Ok(Progress::Stopped(ending));
            }
            let Some(complete) = pass.complete.take() else {
                return Ok(Progress::More);
            };
            let unit = Unit {
                rid,
                kind: kind::RESIGN.to_owned(),
                position: pass.namespace.to_string(),
            };
            let storage = cx.storage;
            let done = &begun.done;
            let ran = cx.run_unit(&unit, |state| {
                let Some(signer) = signer else {
                    return Ok(Err("no key to re-sign with".to_owned()));
                };
                if let Err(e) = namespace::resign(storage, rid, complete, signer) {
                    return Ok(Err(e.to_string()));
                }
                // The refs changed, and with them the repository's version:
                // its repair goes on at the new one, with what it finished
                // before recorded again.
                let version = match storage
                    .repository(rid)
                    .map_err(|e| e.to_string())
                    .and_then(|repo| state::version(&repo).map_err(|e| e.to_string()))
                {
                    Ok(version) => version,
                    Err(e) => return Ok(Err(e)),
                };
                state.begin(&rid, version)?;
                if done.contains(&Step::RefLocks) {
                    state.finish(&rid, Step::RefLocks)?;
                }
                Ok(Ok(version))
            })?;
            return match ran {
                Ran::Done(version) => {
                    begun.version = version;
                    self.did.namespaces += 1;
                    self.did.resigned = true;
                    self.pass = None;
                    Ok(Progress::More)
                }
                Ran::Failed(failed) => {
                    cx.quarantined(rid, quarantine::Kind::Namespace, step, &unit, failed)
                }
                Ran::Stopped(ending) => Ok(Progress::Stopped(ending)),
            };
        }

        // The check's next refs, from its checkpoint.
        let limit = match &mut begun.small {
            Some(Small::Namespace { namespace, left })
                if *namespace == pass.namespace && *left > 0 =>
            {
                *left -= 1;
                1
            }
            _ => namespace::UNIT_REFS,
        };
        let unit = Unit {
            rid,
            kind: kind::NAMESPACE.to_owned(),
            position: format!(
                "{}:{}",
                pass.namespace,
                pass.from.after.as_ref().map_or("", |after| after.as_str())
            ),
        };
        let repo = &begun.repo;
        let (namespace, version, authority) = (pass.namespace, pass.version, pass.authority);
        let (signed, from) = (&pass.signed, &pass.from);
        let ran = cx.unit(&unit, |state| {
            let check = match namespace::check(repo, signed, authority, from, limit) {
                Ok(check) => check,
                Err(e) => return Ok(Err(e.to_string())),
            };
            if let Check::Continue(next) = &check {
                state.save_checkpoint(&rid, &namespace, version, authority, next)?;
            }
            Ok(Ok(check))
        })?;
        match ran {
            Ran::Done(Check::Continue(next)) => {
                pass.from = next;
                Ok(Progress::More)
            }
            Ran::Done(Check::Clean) => {
                self.did.namespaces += 1;
                self.pass = None;
                Ok(Progress::More)
            }
            Ran::Done(Check::Stale(complete)) => {
                pass.complete = Some(complete);
                Ok(Progress::More)
            }
            Ran::Done(Check::Quarantine(problem)) => cx.quarantined(
                rid,
                quarantine::Kind::Namespace,
                step,
                &unit,
                Failed::Error(format!("{problem:?}")),
            ),
            Ran::Failed(failed) => {
                cx.quarantined(rid, quarantine::Kind::Namespace, step, &unit, failed)
            }
            Ran::Stopped(ending) => Ok(Progress::Stopped(ending)),
        }
    }

    /// The next unit of the COB cache rebuild.
    fn rebuild<S>(&mut self, cx: &mut Context<'_, S>) -> Result<Progress, Error> {
        let rid = self.rid;
        let begun = self.begun.as_mut().ok_or(Error::NotBegun)?;
        let publication = self.publication;
        let version = begun.version;
        let step = Step::Cache.as_str();

        match &mut self.rebuild {
            Rebuild::List => {
                let at = cx
                    .state
                    .cache_checkpoint(&rid, version)?
                    .unwrap_or_default();
                let limit = match &mut begun.small {
                    Some(Small::Cache { left }) if *left > 0 => {
                        *left -= 1;
                        1
                    }
                    _ => cache::BATCH_COBS,
                };
                let unit = Unit {
                    rid,
                    kind: kind::CACHE_LIST.to_owned(),
                    position: cache_position(at.kind, at.after.as_ref()),
                };
                let repo = &begun.repo;
                match cx.unit(&unit, |_| Ok(list(repo, at, limit)))? {
                    Ran::Done(Some(batch)) => self.rebuild = Rebuild::Batch(batch),
                    Ran::Done(None) => self.rebuild = Rebuild::Publish,
                    Ran::Failed(failed) => {
                        return cx.quarantined(rid, quarantine::Kind::Cache, step, &unit, failed);
                    }
                    Ran::Stopped(ending) => return Ok(Progress::Stopped(ending)),
                }
                Ok(Progress::More)
            }
            Rebuild::Batch(batch) => {
                // The batch's next COB, materialized.
                if let Some(&id) = batch.ids.front() {
                    let kind = batch.at.kind;
                    let unit = Unit {
                        rid,
                        kind: kind::CACHE.to_owned(),
                        position: cache_position(kind, Some(&id)),
                    };
                    let repo = &begun.repo;
                    let ran = cx.unit(&unit, |_| {
                        Ok(cache::materialize(repo, kind, id).map_err(|e| e.to_string()))
                    })?;
                    return match ran {
                        Ran::Done(row) => {
                            batch.ids.pop_front();
                            batch.rows.extend(row);
                            batch.at.after = Some(id);
                            batch.taken += 1;
                            Ok(Progress::More)
                        }
                        Ran::Failed(failed) => {
                            cx.quarantined(rid, quarantine::Kind::Cache, step, &unit, failed)
                        }
                        Ran::Stopped(ending) => {
                            // Cut off: what the batch materialized is committed
                            // with its checkpoint, in the time kept for it.
                            if batch.taken > 0 {
                                let rows = std::mem::take(&mut batch.rows);
                                let at = batch.at.clone();
                                if let Some(progress) = commit(cx, rid, version, rows, at)? {
                                    return Ok(progress);
                                }
                            }
                            self.rebuild = Rebuild::List;
                            Ok(Progress::Stopped(ending))
                        }
                    };
                }
                // The batch is done: commit it with the next checkpoint.
                let next = match (batch.more, batch.at.kind.next()) {
                    (false, Some(kind)) => cache::Checkpoint { kind, after: None },
                    _ => batch.at.clone(),
                };
                let rows = std::mem::take(&mut batch.rows);
                if let Some(progress) = commit(cx, rid, version, rows, next)? {
                    return Ok(progress);
                }
                self.rebuild = Rebuild::List;
                Ok(Progress::More)
            }
            Rebuild::Publish => {
                let unit = Unit {
                    rid,
                    kind: kind::PUBLISH.to_owned(),
                    position: String::new(),
                };
                let ran = cx.unit(&unit, |state| {
                    state.publish(&rid, publication)?;
                    Ok(Ok(()))
                })?;
                match ran {
                    Ran::Done(()) => {
                        begun.done.insert(Step::Cache);
                        self.did.cache = true;
                        Ok(Progress::Done)
                    }
                    Ran::Failed(failed) => {
                        cx.quarantined(rid, quarantine::Kind::Cache, step, &unit, failed)
                    }
                    Ran::Stopped(ending) => Ok(Progress::Stopped(ending)),
                }
            }
        }
    }
}

/// Commits a batch's `rows` with the checkpoint `next`, as a unit that runs
/// whatever the stop says: the work it records is done. `Some` if it
/// quarantined the repository instead.
fn commit<S>(
    cx: &mut Context<'_, S>,
    rid: RepoId,
    version: Oid,
    rows: Vec<cache::Row>,
    next: cache::Checkpoint,
) -> Result<Option<Progress>, Error> {
    let unit = Unit {
        rid,
        kind: kind::CACHE_COMMIT.to_owned(),
        position: cache_position(next.kind, next.after.as_ref()),
    };
    let ran = cx.run_unit(&unit, |state| {
        state.stage(&rid, version, &rows, &next)?;
        Ok(Ok(()))
    })?;
    match ran {
        Ran::Done(()) => Ok(None),
        Ran::Failed(failed) => cx
            .quarantined(
                rid,
                quarantine::Kind::Cache,
                Step::Cache.as_str(),
                &unit,
                failed,
            )
            .map(Some),
        Ran::Stopped(ending) => Ok(Some(Progress::Stopped(ending))),
    }
}

/// The next batch of COBs after `at`, at most `limit`, of its kind or a
/// later one: `None` once none remains.
fn list(
    repo: &Repository,
    mut at: cache::Checkpoint,
    limit: usize,
) -> Result<Option<Batch>, String> {
    loop {
        let (ids, more) =
            cache::next(repo, at.kind, at.after.as_ref(), limit).map_err(|e| e.to_string())?;
        if !ids.is_empty() {
            return Ok(Some(Batch {
                ids: ids.into(),
                more,
                rows: Vec::new(),
                at,
                taken: 0,
            }));
        }
        match at.kind.next() {
            Some(kind) => at = cache::Checkpoint { kind, after: None },
            None => return Ok(None),
        }
    }
}

fn cache_position(kind: cache::Kind, after: Option<&ObjectId>) -> String {
    format!(
        "{kind}:{}",
        after.map(ToString::to_string).unwrap_or_default()
    )
}

/// The step that runs in its smallest form after `unit` was cut off, if
/// any: a namespace's check, or the cache rebuild. Every other unit is
/// already one piece.
fn small(unit: &Unit) -> Option<Small> {
    match unit.kind.as_str() {
        kind::NAMESPACE => {
            let (namespace, _) = unit.position.split_once(':')?;
            Some(Small::Namespace {
                namespace: NodeId::from_str(namespace).ok()?,
                left: namespace::UNIT_REFS,
            })
        }
        kind::CACHE_LIST | kind::CACHE | kind::CACHE_COMMIT => Some(Small::Cache {
            left: cache::BATCH_COBS,
        }),
        _ => None,
    }
}

/// Reconciles `storage` at a start, before a node runs on it: its temporary
/// clones and its repositories' ref lock files; and, when the dirty marker
/// was present and names `dirty`, those namespaces in every repository, and
/// every COB cache. A repository already quarantined is left as it is.
///
/// It turns libgit2's fsync on first ([`super::enable_fsync`]). Once every
/// repair is done, or its repository quarantined, it clears the progress
/// state, before it returns. Stopped by `cx.stop`, it keeps it, and the next
/// run resumes.
pub fn run<S: crypto::Signer>(
    cx: &mut Context<'_, S>,
    dirty: Option<&BTreeSet<NodeId>>,
) -> Result<Report, Error> {
    super::enable_fsync()?;
    let mut report = Report {
        ending: Ending::Done,
        dirty: dirty.is_some(),
        clones: 0,
        left: 0,
        locks: 0,
        namespaces: 0,
        resigned: Vec::new(),
        caches: 0,
        newly_quarantined: Vec::new(),
        quarantined: 0,
        first: Vec::new(),
    };
    report.ending = run_units(cx, dirty, &mut report)?;
    if report.ending == Ending::Done {
        cx.state.clear()?;
    }
    report.quarantined = cx.quarantine.count()?;
    report.first = cx.quarantine.page(0, REPORTED)?;
    Ok(report)
}

fn run_units<S: crypto::Signer>(
    cx: &mut Context<'_, S>,
    dirty: Option<&BTreeSet<NodeId>>,
    report: &mut Report,
) -> Result<Ending, Error> {
    let path = cx.storage.path().to_path_buf();
    let (clones, left) = super::temporary_clones(&path)?;
    report.left = left;
    for (rid, name) in clones {
        let unit = Unit {
            rid,
            kind: kind::CLONE.to_owned(),
            position: name.to_string_lossy().into_owned(),
        };
        let ran = cx.unit(&unit, |_| {
            Ok(super::remove_temporary_clone(&path, &name).map_err(|e| e.to_string()))
        })?;
        match ran {
            Ran::Done(true) => report.clones += 1,
            Ran::Done(false) => report.left += 1,
            // A temporary clone isn't its repository: what can't remove it
            // is outside any one repository.
            Ran::Failed(Failed::Error(reason)) => return Err(Error::Clone { name, reason }),
            Ran::Failed(Failed::Poison) => {
                return Err(Error::Poison {
                    kind: unit.kind,
                    position: unit.position,
                });
            }
            Ran::Stopped(ending) => return Ok(ending),
        }
    }

    for rid in super::repositories(&path)? {
        if cx.quarantine.get(&rid)?.is_some() {
            continue;
        }
        let mut repair = Repair::start(rid, dirty);
        let ending = loop {
            match repair.step(cx)? {
                Progress::More => {}
                Progress::Done => break None,
                Progress::Quarantined(_) => {
                    report.newly_quarantined.push(rid);
                    break None;
                }
                Progress::Stopped(ending) => break Some(ending),
            }
        };
        let did = repair.did();
        report.locks += did.locks;
        report.namespaces += did.namespaces;
        if did.resigned {
            report.resigned.push(rid);
        }
        report.caches += usize::from(did.cache);
        if let Some(ending) = ending {
            return Ok(ending);
        }
    }
    Ok(Ending::Done)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fs;
    use std::ops::ControlFlow;
    use std::path::PathBuf;

    use super::*;
    use crate::cob::migrate;
    use crate::cob::patch::MergeTarget;
    use crate::crypto::{Signer as _, SigningKey};
    use crate::git;
    use crate::storage::git::reconcile::cache::Kind as Cob;
    use crate::test::fixtures;
    use crate::{cob, issue, patch, test};

    /// What the watch saw: every unit that started, in order, and how many
    /// ended. It sets its token as the `n`th unit of a kind starts, if asked,
    /// so that the run stops after that unit.
    #[derive(Default)]
    struct Log {
        units: RefCell<Vec<Unit>>,
        ended: Cell<usize>,
        cancel: Option<(&'static str, usize, Arc<AtomicBool>)>,
    }

    impl Watch for Log {
        fn started(&self, unit: &Unit) {
            let mut units = self.units.borrow_mut();
            units.push(unit.clone());
            if let Some((kind, n, token)) = &self.cancel
                && units.iter().filter(|u| u.kind == *kind).count() == *n
            {
                token.store(true, Ordering::Release);
            }
        }

        fn ended(&self) {
            self.ended.set(self.ended.get() + 1);
        }
    }

    impl Log {
        /// A log that sets `stop`'s token as the `n`th unit of `kind` starts.
        fn cancelling(stop: &Stop, kind: &'static str, n: usize) -> Self {
            Self {
                cancel: Some((kind, n, stop.cancel.clone())),
                ..Self::default()
            }
        }

        fn len(&self) -> usize {
            self.units.borrow().len()
        }

        fn kinds(&self) -> Vec<String> {
            self.units.borrow().iter().map(|u| u.kind.clone()).collect()
        }

        /// The positions of the units of `kind`, in order.
        fn positions(&self, kind: &str) -> Vec<String> {
            self.units
                .borrow()
                .iter()
                .filter(|u| u.kind == kind)
                .map(|u| u.position.clone())
                .collect()
        }

        /// How many units of any of `kinds` started.
        fn count(&self, kinds: &[&str]) -> usize {
            self.units
                .borrow()
                .iter()
                .filter(|u| kinds.contains(&u.kind.as_str()))
                .count()
        }
    }

    struct Fixture {
        alice: test::setup::NodeWithRepo,
        cache: cob::cache::StoreWriter,
        /// The cache database, with the progress in it.
        db: PathBuf,
        /// The quarantine record.
        record: PathBuf,
    }

    /// Alice's repository, with three issues and two patches, and an empty
    /// cache.
    fn fixture() -> Fixture {
        let alice = test::setup::NodeWithRepo::default();
        issues(&alice.repo, &alice.signer, ["First", "Second", "Third"]);
        {
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
        let db = alice.root.join(cob::cache::COBS_DB_FILE);
        let cache = cob::cache::StoreWriter::open(&db)
            .unwrap()
            .with_migrations(migrate::ignore)
            .unwrap();
        let record = alice.root.join(quarantine::QUARANTINE_DB_FILE);
        Fixture {
            alice,
            cache,
            db,
            record,
        }
    }

    fn issues<'a>(
        repo: &Repository,
        signer: &SigningKey,
        titles: impl IntoIterator<Item = &'a str>,
    ) {
        let mut issues = issue::Cache::no_cache(repo, signer).unwrap();
        for title in titles {
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
    }

    impl Fixture {
        fn rid(&self) -> RepoId {
            self.alice.repo.id
        }

        fn nid(&self) -> NodeId {
            *self.alice.signer.public_key()
        }

        fn storage(&self) -> &Storage {
            &self.alice.storage
        }

        fn repo(&self) -> Repository {
            self.storage().repository(self.rid()).unwrap()
        }

        /// A run, as a new process starts it, with `signer`'s key, and with
        /// the dirty marker present and naming `dirty` if it is `Some`.
        fn try_run(
            &self,
            dirty: Option<&[NodeId]>,
            signer: &SigningKey,
            stop: &Stop,
            log: &Log,
        ) -> Result<Report, Error> {
            let mut state = State::open(&self.db).unwrap();
            let mut quarantine = Quarantine::open(&self.record).unwrap();
            let dirty = dirty.map(|dirty| dirty.iter().copied().collect::<BTreeSet<_>>());
            let mut cx = Context {
                storage: self.storage(),
                state: &mut state,
                quarantine: &mut quarantine,
                signer: Some(signer),
                stop,
                watch: log,
            };
            run(&mut cx, dirty.as_ref())
        }

        fn run(
            &self,
            dirty: Option<&[NodeId]>,
            signer: &SigningKey,
            stop: &Stop,
            log: &Log,
        ) -> Report {
            self.try_run(dirty, signer, stop, log).unwrap()
        }

        /// A run with Alice's key, the marker naming her, and no stop.
        fn run_as_alice(&self, log: &Log) -> Report {
            self.run(
                Some(&[self.nid()]),
                &self.alice.signer,
                &Stop::default(),
                log,
            )
        }

        /// A ref of `namespace`, set without signing it.
        fn unsigned(&self, namespace: &NodeId) {
            let repo = self.repo();
            let head = repo
                .backend
                .refname_to_id(&format!("refs/namespaces/{}/refs/heads/master", self.nid()))
                .unwrap();
            repo.backend
                .reference(
                    &format!("refs/namespaces/{namespace}/refs/heads/unsigned"),
                    head,
                    true,
                    "test",
                )
                .unwrap();
        }

        fn sigrefs(&self, namespace: &NodeId) -> Option<git::raw::Oid> {
            self.repo()
                .backend
                .refname_to_id(&format!("refs/namespaces/{namespace}/refs/rad/sigrefs"))
                .ok()
        }

        /// The check of `namespace`, run to its end.
        fn check(&self, namespace: &NodeId, authority: Authority) -> Check {
            let repo = self.repo();
            let signed = Signed::load(&repo, namespace).unwrap();
            let mut from = Checkpoint::default();
            loop {
                match namespace::check(&repo, &signed, authority, &from, namespace::UNIT_REFS)
                    .unwrap()
                {
                    Check::Continue(next) => from = next,
                    end => return end,
                }
            }
        }

        /// The repository's COBs of `kind`, in order.
        fn ids(&self, kind: Cob) -> Vec<ObjectId> {
            cache::next(&self.repo(), kind, None, cache::BATCH_COBS)
                .unwrap()
                .0
        }

        fn live(&self, rid: RepoId) -> BTreeMap<(Cob, String), String> {
            rows(&self.cache, rid)
        }

        /// A ref lock file a killed update left in the repository.
        fn lock(&self) -> PathBuf {
            let lock = self.repo().path().join(format!(
                "refs/namespaces/{}/refs/heads/master.lock",
                self.nid()
            ));
            fs::create_dir_all(lock.parent().unwrap()).unwrap();
            fs::write(&lock, b"").unwrap();
            lock
        }

        /// A temporary clone a killed clone left.
        fn clone(&self) -> PathBuf {
            let clone = self
                .storage()
                .path()
                .join(format!("{}.tmp", self.rid().canonical()));
            fs::create_dir_all(clone.join("objects")).unwrap();
            fs::write(clone.join("objects/x"), b"").unwrap();
            clone
        }

        /// `unit` recorded in progress by `processes` that each ended during
        /// it.
        fn cut_off(&self, unit: &Unit, processes: u32) {
            for _ in 0..processes {
                State::open(&self.db).unwrap().start(unit).unwrap();
            }
        }

        fn version(&self) -> Oid {
            state::version(&self.repo()).unwrap()
        }
    }

    fn rows(cache: &cob::cache::StoreWriter, rid: RepoId) -> BTreeMap<(Cob, String), String> {
        let mut rows = BTreeMap::new();
        for kind in Cob::ALL {
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
    fn written_all(repo: &Repository) -> BTreeMap<(Cob, String), String> {
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

    fn position(kind: Cob, id: &ObjectId) -> String {
        format!("{kind}:{id}")
    }

    #[test]
    fn a_dirty_start_repairs_each_step_and_clears_its_progress() {
        let f = fixture();
        let (rid, nid) = (f.rid(), f.nid());
        let (clone, lock) = (f.clone(), f.lock());
        // Not a clone's name: left alone.
        fs::write(f.storage().path().join("notes.txt"), b"").unwrap();
        // Alice was killed between a ref and its signing.
        f.unsigned(&nid);
        let signed = f.sigrefs(&nid);

        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert_eq!(
            report,
            Report {
                ending: Ending::Done,
                dirty: true,
                clones: 1,
                left: 1,
                locks: 1,
                namespaces: 1,
                resigned: vec![rid],
                caches: 1,
                newly_quarantined: vec![],
                quarantined: 0,
                first: vec![],
            }
        );
        assert!(!clone.exists());
        assert!(!lock.exists());
        assert!(f.storage().path().join("notes.txt").exists());
        // Re-signed over its current refs.
        assert_ne!(f.sigrefs(&nid), signed);
        assert_eq!(f.check(&nid, Authority::Owner), Check::Clean);
        // The cache is what heartwood's own rebuild writes.
        let live = f.live(rid);
        assert_eq!(live.len(), 5);
        assert_eq!(live, written_all(&f.repo()));
        // Every unit ended, and the progress is cleared.
        assert_eq!(log.ended.get(), log.len());
        let mut state = State::open(&f.db).unwrap();
        assert_eq!(state.in_progress().unwrap(), None);
        assert!(state.begin(&rid, f.version()).unwrap().is_empty());
    }

    #[test]
    fn a_clean_start_removes_clones_and_ref_locks_only() {
        let f = fixture();
        let (rid, nid) = (f.rid(), f.nid());
        let (clone, lock) = (f.clone(), f.lock());
        f.unsigned(&nid);

        let log = Log::default();
        let report = f.run(None, &f.alice.signer, &Stop::default(), &log);
        assert_eq!(report.ending, Ending::Done);
        assert!(!report.dirty);
        assert_eq!((report.clones, report.locks), (1, 1));
        assert_eq!((report.namespaces, report.caches), (0, 0));
        assert!(!clone.exists());
        assert!(!lock.exists());
        // Neither its namespace nor its cache is touched.
        assert!(matches!(f.check(&nid, Authority::Owner), Check::Stale(_)));
        assert!(f.live(rid).is_empty());
        assert_eq!(log.kinds(), [kind::CLONE, kind::BEGIN, kind::REF_LOCKS]);
    }

    #[test]
    fn an_earlier_identity_s_refs_its_key_didn_t_sign_quarantine_its_repository() {
        let f = fixture();
        let (rid, alice) = (f.rid(), f.nid());
        f.unsigned(&alice);
        let signed = f.sigrefs(&alice);
        // Alice's vault is gone: the start runs with a throwaway key, which
        // owns no namespace.
        let throwaway = SigningKey::mock(0x42);

        let report = f.run(
            Some(&[alice, *throwaway.public_key()]),
            &throwaway,
            &Stop::default(),
            &Log::default(),
        );
        assert_eq!(report.ending, Ending::Done);
        assert_eq!(report.newly_quarantined, [rid]);
        assert_eq!((report.quarantined, report.first.len()), (1, 1));
        let record = &report.first[0];
        assert_eq!(record.rid, rid);
        assert_eq!(record.kind, quarantine::Kind::Namespace);
        assert_eq!(record.step, "namespaces");
        assert_eq!(record.unit, Some(format!("namespace@{alice}:")));
        assert!(record.evidence.contains("Unsigned"), "{}", record.evidence);
        // Nothing was signed, and its cache wasn't rebuilt.
        assert!(report.resigned.is_empty());
        assert_eq!(f.sigrefs(&alice), signed);
        assert_eq!(report.caches, 0);
        assert!(f.live(rid).is_empty());

        // From then on it is left as it is, whatever the key.
        let lock = f.lock();
        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert!(report.newly_quarantined.is_empty());
        assert_eq!(report.quarantined, 1);
        assert!(lock.exists());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn a_run_past_its_cutoff_starts_no_unit() {
        let f = fixture();
        let clone = f.clone();
        let stop = Stop {
            cutoff: Some(Instant::now()),
            ..Stop::default()
        };
        let log = Log::default();
        let report = f.run(Some(&[f.nid()]), &f.alice.signer, &stop, &log);
        assert_eq!(report.ending, Ending::Deadline);
        assert_eq!(log.len(), 0);
        assert!(clone.exists());
    }

    #[test]
    fn a_stopped_run_finishes_its_unit_commits_its_batch_and_the_next_resumes() {
        let f = fixture();
        let rid = f.rid();
        let (issues, patches) = (f.ids(Cob::Issue), f.ids(Cob::Patch));
        assert_eq!((issues.len(), patches.len()), (3, 2));
        let stop = Stop::default();
        // Shutdown arrives during the second COB.
        let log = Log::cancelling(&stop, kind::CACHE, 2);
        let report = f.run(Some(&[f.nid()]), &f.alice.signer, &stop, &log);
        assert_eq!(report.ending, Ending::Cancelled);
        assert_eq!((report.namespaces, report.caches), (1, 0));
        // The COB finished, and the batch so far was committed with its
        // checkpoint; then nothing more.
        let kinds = log.kinds();
        assert_eq!(
            kinds[kinds.len() - 3..],
            [kind::CACHE, kind::CACHE, kind::CACHE_COMMIT]
        );
        assert_eq!(
            log.positions(kind::CACHE_COMMIT),
            [position(Cob::Issue, &issues[1])]
        );
        assert!(f.live(rid).is_empty(), "published before it was done");
        assert_eq!(
            State::open(&f.db)
                .unwrap()
                .cache_checkpoint(&rid, f.version())
                .unwrap(),
            Some(cache::Checkpoint {
                kind: Cob::Issue,
                after: Some(issues[1]),
            })
        );

        // The next run resumes there.
        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert_eq!(report.ending, Ending::Done);
        assert_eq!((report.locks, report.namespaces, report.caches), (0, 0, 1));
        assert_eq!(
            log.count(&[kind::REF_LOCKS, kind::NAMESPACE_BEGIN, kind::NAMESPACE]),
            0
        );
        assert_eq!(
            log.positions(kind::CACHE_LIST)[0],
            position(Cob::Issue, &issues[1])
        );
        assert_eq!(
            log.positions(kind::CACHE),
            [
                position(Cob::Issue, &issues[2]),
                position(Cob::Patch, &patches[0]),
                position(Cob::Patch, &patches[1]),
            ]
        );
        assert_eq!(f.live(rid), written_all(&f.repo()));
    }

    #[test]
    fn a_re_signed_repository_s_progress_holds_at_its_new_version() {
        let f = fixture();
        let (rid, nid) = (f.rid(), f.nid());
        f.unsigned(&nid);
        let issues = f.ids(Cob::Issue);
        let stop = Stop::default();
        let log = Log::cancelling(&stop, kind::CACHE, 1);
        let report = f.run(Some(&[nid]), &f.alice.signer, &stop, &log);
        assert_eq!(report.ending, Ending::Cancelled);
        assert_eq!(report.resigned, [rid]);

        // Re-signing changed the repository's version; what its repair
        // finished holds at the new one.
        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert_eq!(report.ending, Ending::Done);
        assert!(report.resigned.is_empty());
        assert_eq!(report.caches, 1);
        assert_eq!(
            log.count(&[
                kind::REF_LOCKS,
                kind::NAMESPACE_BEGIN,
                kind::NAMESPACE,
                kind::RESIGN
            ]),
            0
        );
        assert_eq!(
            log.positions(kind::CACHE_LIST)[0],
            position(Cob::Issue, &issues[0])
        );
        assert_eq!(f.check(&nid, Authority::Owner), Check::Clean);
        assert_eq!(f.live(rid), written_all(&f.repo()));
    }

    #[test]
    fn a_unit_cut_off_runs_again_in_its_smallest_form() {
        let f = fixture();
        let (rid, nid) = (f.rid(), f.nid());
        let names = f.repo().references_of(&nid).unwrap().len() - 1;
        assert!(names > 2, "{names}");

        // In the usual form, one unit checks the namespace, and two batches
        // and a last listing rebuild the cache.
        let log = Log::default();
        f.run_as_alice(&log);
        assert_eq!(log.positions(kind::NAMESPACE), [format!("{nid}:")]);
        assert_eq!(log.positions(kind::CACHE_LIST).len(), 3);

        // The last process ended during the namespace's first unit: one ref a
        // unit, for the refs it held.
        let unit = Unit {
            rid,
            kind: kind::NAMESPACE.to_owned(),
            position: format!("{nid}:"),
        };
        f.cut_off(&unit, 1);
        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert!(report.newly_quarantined.is_empty());
        let units = log.positions(kind::NAMESPACE);
        assert_eq!(units.len(), names);
        assert_eq!(units[0], format!("{nid}:"));
        // The cache isn't in its smallest form.
        assert_eq!(log.positions(kind::CACHE_LIST).len(), 3);

        // The last process ended during a COB: one COB a batch.
        let issues = f.ids(Cob::Issue);
        let unit = Unit {
            rid,
            kind: kind::CACHE.to_owned(),
            position: position(Cob::Issue, &issues[0]),
        };
        f.cut_off(&unit, 1);
        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert!(report.newly_quarantined.is_empty());
        assert_eq!(log.positions(kind::NAMESPACE).len(), 1);
        assert_eq!(log.positions(kind::CACHE_LIST).len(), 5 + 1);
        assert_eq!(f.live(rid), written_all(&f.repo()));
    }

    #[test]
    fn a_unit_in_progress_when_two_processes_ended_quarantines_its_repository() {
        let f = fixture();
        let rid = f.rid();
        let unit = Unit {
            rid,
            kind: kind::CACHE_LIST.to_owned(),
            position: "issue:".to_owned(),
        };
        f.cut_off(&unit, 2);
        let log = Log::default();
        let report = f.run_as_alice(&log);
        assert_eq!(report.ending, Ending::Done);
        assert_eq!(report.newly_quarantined, [rid]);
        let record = &report.first[0];
        assert_eq!(record.kind, quarantine::Kind::Cache);
        assert_eq!(record.step, "cache");
        assert_eq!(record.unit.as_deref(), Some("cache-list@issue:"));
        assert_eq!(record.evidence, "in progress when two processes ended");
        // It didn't run a third time; the namespace before it was checked.
        assert_eq!(log.positions(kind::CACHE_LIST).len(), 0);
        assert_eq!(report.namespaces, 1);
        assert!(f.live(rid).is_empty());
    }

    #[test]
    fn a_temporary_clone_in_progress_when_two_processes_ended_fails_the_run() {
        let f = fixture();
        let clone = f.clone();
        let unit = Unit {
            rid: f.rid(),
            kind: kind::CLONE.to_owned(),
            position: format!("{}.tmp", f.rid().canonical()),
        };
        f.cut_off(&unit, 2);
        for _ in 0..2 {
            let result = f.try_run(
                Some(&[f.nid()]),
                &f.alice.signer,
                &Stop::default(),
                &Log::default(),
            );
            assert!(
                matches!(&result, Err(Error::Poison { kind, .. }) if kind == kind::CLONE),
                "{result:?}"
            );
            assert!(clone.exists());
        }
    }

    #[test]
    fn a_unit_that_fails_quarantines_its_repository_and_the_run_goes_on() {
        let f = fixture();
        let (rid, nid) = (f.rid(), f.nid());
        let other = {
            crate::storage::git::transport::local::register(f.storage().clone());
            let (working, _) = fixtures::repository(f.alice.root.join("other"));
            crate::rad::init(
                &working,
                "other".try_into().unwrap(),
                "",
                git::fmt::refname!("master"),
                crate::identity::Visibility::default(),
                &f.alice.signer,
                f.storage(),
            )
            .unwrap()
            .0
        };
        issues(
            &f.storage().repository(other).unwrap(),
            &f.alice.signer,
            ["Elsewhere"],
        );
        // The first issue's ref points at a blob.
        let issues = f.ids(Cob::Issue);
        let repo = f.repo();
        let blob = repo.backend.blob(b"not a COB").unwrap();
        repo.backend
            .reference(
                &format!(
                    "refs/namespaces/{nid}/refs/cobs/{}/{}",
                    issue::TYPENAME.as_str(),
                    issues[0]
                ),
                blob,
                true,
                "test",
            )
            .unwrap();

        let report = f.run_as_alice(&Log::default());
        assert_eq!(report.ending, Ending::Done);
        assert_eq!(report.newly_quarantined, [rid]);
        let record = &report.first[0];
        assert_eq!(record.kind, quarantine::Kind::Cache);
        assert_eq!(record.step, "cache");
        assert_eq!(
            record.unit,
            Some(format!("cache@{}", position(Cob::Issue, &issues[0])))
        );
        assert!(
            record.evidence.contains("doesn't load"),
            "{}",
            record.evidence
        );
        assert!(f.live(rid).is_empty());
        // The other repository was repaired.
        assert_eq!(report.caches, 1);
        let live = f.live(other);
        assert_eq!(live.len(), 1);
        assert_eq!(live, written_all(&f.storage().repository(other).unwrap()));
    }

    #[test]
    fn an_online_repair_runs_one_unit_a_step_and_deletes_its_progress() {
        let f = fixture();
        let (rid, nid) = (f.rid(), f.nid());
        f.unsigned(&nid);
        let mut state = State::open(&f.db).unwrap();
        let mut quarantine = Quarantine::open(&f.record).unwrap();
        let (stop, log) = (Stop::default(), Log::default());
        let mut cx = Context {
            storage: f.storage(),
            state: &mut state,
            quarantine: &mut quarantine,
            signer: Some(&f.alice.signer),
            stop: &stop,
            watch: &log,
        };
        let mut repair = Repair::online(rid, nid);
        for steps in 1.. {
            assert!(steps < 64, "a repair of five COBs ran on");
            let before = log.len();
            let progress = repair.step(&mut cx).unwrap();
            assert_eq!(
                log.len(),
                before + 1,
                "a step ran {} units",
                log.len() - before
            );
            if log.kinds().last().map(String::as_str) == Some(kind::CACHE_LIST) {
                // An online repair records no step.
                let steps = State::open(&f.db)
                    .unwrap()
                    .begin(&rid, f.version())
                    .unwrap();
                assert!(!steps.contains(&Step::Namespaces), "{steps:?}");
            }
            match progress {
                Progress::More => {}
                Progress::Done => break,
                other => panic!("{other:?}"),
            }
        }
        assert!(repair.did().resigned);
        assert!(repair.did().cache);
        assert_eq!(log.count(&[kind::BEGIN, kind::REF_LOCKS, kind::PUBLISH]), 2);
        assert_eq!(f.check(&nid, Authority::Owner), Check::Clean);
        assert_eq!(f.live(rid), written_all(&f.repo()));
        // Its progress was deleted with its publication.
        assert!(state.begin(&rid, f.version()).unwrap().is_empty());
    }
}
