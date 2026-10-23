//! The COB cache's rebuild: in bounded batches that resume where they
//! stopped, published at once.
//!
//! heartwood's own `write_all` clears a repository's cache rows and writes
//! them again in place, so a reader can see the cache half-built. Here, each
//! batch's COBs are materialized into a staging table, `rebuild_staging`, and
//! staged with the batch's checkpoint in one durable transaction. Once every
//! COB is staged, publication swaps the repository's live rows for the staged
//! ones in one more ([`super::state::State::publish`]). Readers see the old
//! cache, then the new one.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::cob;
use crate::cob::{ObjectId, TypeName};
use crate::git;
use crate::git::fmt::RefStr;
use crate::issue;
use crate::patch;
use crate::storage::git::Repository;

/// COBs a batch stages at most, in its usual form. Its smallest form stages
/// one.
pub const BATCH_COBS: usize = 64;

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
    #[error("invalid cache rebuild: {0}")]
    Invalid(String),
}

/// The next COBs of `kind` in `repo` after `after`, at most `limit`, in the
/// order of their IDs, and whether more remain. Its ref names stream past, as
/// libgit2 yields them: no more than `limit + 1` IDs are held at once.
pub fn next(
    repo: &Repository,
    kind: Kind,
    after: Option<&ObjectId>,
    limit: usize,
) -> Result<(Vec<ObjectId>, bool), Error> {
    let limit = limit.max(1);
    let marker = format!("refs/cobs/{}/", kind.typename());
    let mut ids = BTreeSet::<ObjectId>::new();
    for name in repo.backend.references()?.names() {
        let name = name?;
        if !name.contains(&marker) {
            continue;
        }
        let Ok(name) = RefStr::try_from_str(name) else {
            continue;
        };
        let Some((typename, id)) = cob::object::parse_refstr(&name) else {
            continue;
        };
        if &typename != kind.typename()
            || after.is_some_and(|after| id <= *after)
            || (ids.len() > limit && ids.last().is_some_and(|last| id >= *last))
        {
            continue;
        }
        ids.insert(id);
        if ids.len() > limit + 1 {
            ids.pop_last();
        }
    }
    let more = ids.len() > limit;
    Ok((ids.into_iter().take(limit).collect(), more))
}

/// Materializes the COB `id` of `kind`: its row, with its JSON as the cache
/// writes it. `None` if it no longer exists. One unit of a rebuild.
pub fn materialize(repo: &Repository, kind: Kind, id: ObjectId) -> Result<Option<Row>, Error> {
    let failed = |e: cob::error::Retrieve| Error::Cob {
        kind,
        id,
        reason: e.to_string(),
    };
    let json = match kind {
        Kind::Issue => cob::get::<issue::Issue, _>(repo, kind.typename(), &id)
            .map_err(failed)?
            .map(|cob| serde_json::to_string(&cob.object))
            .transpose()?,
        Kind::Patch => cob::get::<patch::Patch, _>(repo, kind.typename(), &id)
            .map_err(failed)?
            .map(|cob| serde_json::to_string(&cob.object))
            .transpose()?,
    };
    Ok(json.map(|json| Row { kind, id, json }))
}

/// One batch of the rebuild of `repo`'s cache, at its input `version`: up to
/// `limit` COBs after `from`, materialized one at a time, then staged with
/// the next checkpoint in one durable transaction. Kinds follow each other;
/// after the last COB of the last kind, it is [`Batch::Staged`].
pub fn batch(
    repo: &Repository,
    state: &mut super::state::State,
    version: git::Oid,
    from: &Checkpoint,
    limit: usize,
) -> Result<Batch, Error> {
    let limit = limit.max(1);
    let mut at = from.clone();
    let mut rows = Vec::new();
    let mut taken = 0;
    let end = loop {
        let (ids, more) = next(repo, at.kind, at.after.as_ref(), limit - taken)?;
        for id in ids {
            if let Some(row) = materialize(repo, at.kind, id)? {
                rows.push(row);
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
    state.stage(&repo.id, version, &rows, &at)?;
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

        /// Every batch of a rebuild from `from`, with `limit` COBs each: how
        /// many it took. More batches than COBs, and two more, fail the test.
        fn rebuild(&mut self, mut from: Checkpoint, limit: usize) -> usize {
            let version = self.version();
            for batches in 1..=5 + 2 {
                match batch(&self.alice.repo, &mut self.state, version, &from, limit).unwrap() {
                    Batch::Continue(next) => from = next,
                    Batch::Staged => return batches,
                }
            }
            panic!("a rebuild of five COBs ran past seven batches")
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
        // Three batches of two, the last one patch; the cache is unchanged
        // meanwhile.
        let mut from = Checkpoint::default();
        let mut batches = 0;
        loop {
            batches += 1;
            assert!(batches <= 7);
            match batch(&f.alice.repo, &mut f.state, version, &from, 2).unwrap() {
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
    }

    #[test]
    fn a_rebuild_resumes_where_it_stopped() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        let Batch::Continue(at) = batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            1,
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
        batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            2,
        )
        .unwrap();
        assert!(f.state.cache_checkpoint(&rid, version).unwrap().is_some());

        // Another version: the staging and the checkpoint are discarded.
        let other = git::Oid::from(git::raw::Oid::from_bytes(&[7; 20]).unwrap());
        f.state.begin(&rid, other).unwrap();
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), None);
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
    fn a_cob_that_doesn_t_load_is_an_error() {
        let mut f = fixture();
        let rid = f.repo().id;
        let (ids, _) = next(f.repo(), Kind::Issue, None, BATCH_COBS).unwrap();
        assert_eq!(ids.len(), 3);
        // The first issue's ref points at a blob.
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
        assert!(matches!(
            materialize(f.repo(), Kind::Issue, ids[0]),
            Err(Error::Cob {
                kind: Kind::Issue,
                ..
            })
        ));
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        assert!(matches!(
            batch(
                &f.alice.repo,
                &mut f.state,
                version,
                &Checkpoint::default(),
                BATCH_COBS
            ),
            Err(Error::Cob { .. })
        ));
        // Nothing of the batch was staged.
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), None);
    }

    #[test]
    fn cobs_are_listed_in_order_after_a_checkpoint() {
        let f = fixture();
        let (all, more) = next(f.repo(), Kind::Issue, None, BATCH_COBS).unwrap();
        assert!(!more);
        assert!(all.windows(2).all(|w| w[0] < w[1]));
        let (first, more) = next(f.repo(), Kind::Issue, None, 2).unwrap();
        assert!(more);
        assert_eq!(first, all[..2]);
        let (rest, more) = next(f.repo(), Kind::Issue, Some(&first[1]), 2).unwrap();
        assert!(!more);
        assert_eq!(rest, all[2..]);
        assert_eq!(
            next(f.repo(), Kind::Patch, None, BATCH_COBS)
                .unwrap()
                .0
                .len(),
            2
        );
    }

    #[test]
    fn a_cache_checkpoint_holds_at_its_version_only() {
        let mut f = fixture();
        let rid = f.repo().id;
        let version = f.version();
        f.state.begin(&rid, version).unwrap();
        let Batch::Continue(at) = batch(
            &f.alice.repo,
            &mut f.state,
            version,
            &Checkpoint::default(),
            1,
        )
        .unwrap() else {
            panic!("staged at once")
        };
        let other = git::Oid::from(git::raw::Oid::from_bytes(&[7; 20]).unwrap());
        assert_eq!(f.state.cache_checkpoint(&rid, version).unwrap(), Some(at));
        assert_eq!(f.state.cache_checkpoint(&rid, other).unwrap(), None);
    }

    // libgit2 yields loose refs before packed ones, so a later ID may sort
    // first: the listing still takes the next IDs in order.
    #[test]
    fn cobs_are_listed_in_order_loose_and_packed() {
        let f = fixture();
        let (loose, _) = next(f.repo(), Kind::Issue, None, BATCH_COBS).unwrap();
        let head = f.repo().backend.head().unwrap().target().unwrap();
        let path = f.repo().backend.path().join("packed-refs");
        let mut packed = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| String::from("# pack-refs with: peeled fully-peeled sorted \n"));
        let low = (1..=3)
            .map(|i| ObjectId::from_str(&format!("{i:040x}")).unwrap())
            .collect::<Vec<_>>();
        for id in &low {
            packed.push_str(&format!(
                "{head} refs/namespaces/{}/refs/cobs/{}/{id}\n",
                f.alice.signer.public_key(),
                issue::TYPENAME.as_str()
            ));
        }
        std::fs::write(&path, packed).unwrap();
        let (first, more) = next(f.repo(), Kind::Issue, None, 2).unwrap();
        assert!(more);
        assert_eq!(first, low[..2]);
        let (all, _) = next(f.repo(), Kind::Issue, None, BATCH_COBS).unwrap();
        let mut expected = low.clone();
        expected.extend(loose);
        assert_eq!(all, expected);
    }
}
