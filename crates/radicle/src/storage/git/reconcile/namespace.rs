//! Checks of a namespace's refs against its signed refs, in units, and the
//! re-signing of a namespace by its own key.
//!
//! A kill between a ref update and its signing leaves a namespace whose refs
//! its `rad/sigrefs` doesn't sign. The namespace's own key may re-sign it
//! over its current refs, once every one of them has been checked and points
//! at an object the repository has. No other key ever signs it: a namespace
//! no key here may sign, whose refs don't match its signed refs, is left as
//! it is, for its repository to be quarantined.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use thiserror::Error;

use crate::crypto;
use crate::git;
use crate::git::Oid;
use crate::git::fmt::{RefStr, RefString};
use crate::prelude::{NodeId, RepoId};
use crate::storage::git::{Repository, Storage};
use crate::storage::refs::SignedRefs;
use crate::storage::{RepositoryError, SignRepository as _, WriteStorage as _};

use super::fsync_enabled;

/// The refs one unit of a check takes at most, in its usual form. Its
/// smallest form takes one.
pub const UNIT_REFS: usize = 1024;

/// Who may sign a namespace that a check finds stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Its own key, which the process signs with: the running identity's
    /// namespace.
    Owner,
    /// No key here: the check only reads.
    None,
}

impl Authority {
    /// The authority over `namespace` of a process that signs with the key of
    /// `signer`, if any.
    pub fn of(namespace: &NodeId, signer: Option<&NodeId>) -> Self {
        if signer == Some(namespace) {
            Self::Owner
        } else {
            Self::None
        }
    }
}

/// Where a check of one namespace stands between its units.
///
/// It holds only while the namespace's [`version`] is the one the check
/// began with, and its [`Authority`] is unchanged: otherwise, the check
/// starts over.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checkpoint {
    /// The last ref checked, in the order of their names. `None` before the
    /// first unit.
    pub after: Option<RefString>,
    /// Whether a ref checked so far differs from the signed refs. Only ever
    /// set under [`Authority::Owner`].
    pub stale: bool,
}

/// What one unit of a check found.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    /// Refs remain: the next unit runs from this checkpoint.
    Continue(Checkpoint),
    /// Every ref is signed, at its target, and points at an object the
    /// repository has.
    Clean,
    /// Every ref points at an object the repository has, but the refs differ
    /// from the signed refs, and the namespace is the signer's: [`resign`]
    /// it, with this proof that the check is complete.
    Stale(Complete),
    /// The namespace doesn't verify, and can't be re-signed: its repository
    /// is to be quarantined as `namespace`. Nothing was changed.
    Quarantine(Problem),
}

/// Why a namespace doesn't verify: the evidence a quarantine keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// Its `rad/sigrefs` doesn't load, or doesn't verify.
    Unverified { reason: String },
    /// A ref its signed refs don't sign.
    Unsigned { refname: RefString, target: Oid },
    /// A ref whose target isn't the signed one.
    Mismatched {
        refname: RefString,
        signed: Oid,
        target: Oid,
    },
    /// A signed ref the namespace doesn't have.
    Missing { refname: RefString, signed: Oid },
    /// A ref whose target the repository doesn't have.
    MissingObject { refname: RefString, target: Oid },
}

/// An error that kept a unit from running.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] crate::storage::Error),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Git(#[from] git::raw::Error),
    #[error("fsync is off: reconciliation turns it on (`enable_fsync`) before it signs")]
    FsyncOff,
    #[error("the key of {signer} may not sign the namespace of {namespace}")]
    NotOwner { namespace: NodeId, signer: NodeId },
    /// The namespace's refs changed since its check: it has to be checked
    /// again.
    #[error("the refs of {namespace} changed since its check")]
    Changed { namespace: NodeId },
}

/// Proof that a check of a namespace ran to its end and found it stale: what
/// [`resign`] takes. Only [`check`] makes one, in a pass's last unit, bound to
/// the namespace and its [`version`] then.
///
/// A pass is only as complete as the checkpoints it resumed from: the
/// reconcile state that keeps them binds each to the namespace's version.
#[derive(Debug, PartialEq, Eq)]
pub struct Complete {
    namespace: NodeId,
    version: Oid,
}

impl Complete {
    /// The namespace found stale.
    pub fn namespace(&self) -> &NodeId {
        &self.namespace
    }

    /// Its version when its check ended.
    pub fn version(&self) -> Oid {
        self.version
    }
}

/// A namespace's signed refs, read and verified once for a whole pass of its
/// check, and the commit they were read at: every unit compares against them.
/// A pass of the check starts over if its `rad/sigrefs` moves, as the
/// namespace's [`version`] then changes; a unit that finds it moved stops.
#[derive(Debug)]
pub struct Signed {
    namespace: NodeId,
    state: SignedState,
}

#[derive(Debug)]
enum SignedState {
    /// Verified, at this commit.
    Verified {
        at: Oid,
        refs: BTreeMap<RefString, Oid>,
    },
    /// The namespace has no `rad/sigrefs`.
    Absent,
    /// Its `rad/sigrefs` doesn't load, or doesn't verify.
    Unverified(String),
}

impl Signed {
    /// Reads and verifies `namespace`'s signed refs in `repo`: once a pass.
    pub fn load(repo: &Repository, namespace: &NodeId) -> Result<Self, Error> {
        let state = match SignedRefs::load(*namespace, repo) {
            Ok(Some(signed)) => SignedState::Verified {
                at: signed.at,
                refs: BTreeMap::from(signed.refs().clone()),
            },
            Ok(None) => SignedState::Absent,
            Err(err) => SignedState::Unverified(err.to_string()),
        };
        Ok(Self {
            namespace: *namespace,
            state,
        })
    }

    /// The namespace they are the signed refs of.
    pub fn namespace(&self) -> &NodeId {
        &self.namespace
    }

    fn refs(&self) -> Option<&BTreeMap<RefString, Oid>> {
        match &self.state {
            SignedState::Verified { refs, .. } => Some(refs),
            SignedState::Absent | SignedState::Unverified(_) => None,
        }
    }

    fn at(&self) -> Option<Oid> {
        match &self.state {
            SignedState::Verified { at, .. } => Some(*at),
            SignedState::Absent | SignedState::Unverified(_) => None,
        }
    }
}

/// The prefix of `namespace`'s refs.
fn prefix(namespace: &NodeId) -> String {
    format!("refs/namespaces/{namespace}/")
}

/// Refs under it a namespace's check and version leave out, as
/// `ReadRepository::references_of` leaves them out.
const TMP_HEADS: &str = "refs/tmp/heads/";

/// The signed refs' own ref, within a namespace.
const SIGREFS: &str = "refs/rad/sigrefs";

/// The names of `namespace`'s refs in `repo`, within the namespace, as libgit2
/// yields them, in no particular order: none is held but the one `each` is
/// given, and none is parsed.
fn each_name(
    repo: &Repository,
    namespace: &NodeId,
    mut each: impl FnMut(&str),
) -> Result<(), Error> {
    let prefix = prefix(namespace);
    for name in repo.backend.references_glob(&format!("{prefix}*"))?.names() {
        let name = name?;
        if let Some(name) = name.strip_prefix(&prefix)
            && !name.starts_with(TMP_HEADS)
        {
            each(name);
        }
    }
    Ok(())
}

/// The target of `namespace`'s ref `name` in `repo`, if it has one.
fn target(repo: &Repository, namespace: &NodeId, name: &str) -> Result<Option<Oid>, Error> {
    let reference = match repo
        .backend
        .find_reference(&format!("{}{name}", prefix(namespace)))
    {
        Ok(reference) => reference,
        Err(e) if e.code() == git::raw::ErrorCode::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let target = match reference.target() {
        Some(target) => target,
        None => reference
            .resolve()?
            .target()
            .ok_or(crate::storage::Error::InvalidRef)?,
    };
    Ok(Some(target.into()))
}

/// The version of `namespace`'s refs in `repo`: a fingerprint of every ref's
/// name and target, `rad/sigrefs` included, that tells an accidental change
/// apart, such as a write a kill left part way.
///
/// It is the exclusive or of each ref's own hash, over `name target`, and
/// their count, hashed: independent of the order libgit2 yields refs in, so
/// no ref is held but the one it hashes. A ref name has no space.
///
/// It is not an authentication boundary: chosen sets of refs can be made to
/// share one (a generalized birthday search). It relies on design 0008's
/// single writer: the home's lock, the repository gate, and no `rad` CLI
/// running at the same time, so nothing can swap in another set of refs
/// while a checkpoint or a [`Complete`] holds it. If that boundary ever
/// widens, it has to become a collision-resistant digest.
pub fn version(repo: &Repository, namespace: &NodeId) -> Result<Oid, Error> {
    let prefix = prefix(namespace);
    let mut sum = [0u8; 20];
    let mut count = 0u64;
    for reference in repo.backend.references_glob(&format!("{prefix}*"))? {
        let reference = reference?;
        let Ok(full) = reference.name() else {
            return Err(crate::storage::Error::InvalidRef.into());
        };
        let Some(name) = full.strip_prefix(&prefix) else {
            continue;
        };
        if name.starts_with(TMP_HEADS) {
            continue;
        }
        let target = match reference.target() {
            Some(target) => target,
            None => reference
                .resolve()?
                .target()
                .ok_or(crate::storage::Error::InvalidRef)?,
        };
        let text = format!("{name} {target}");
        let hash = git::raw::Oid::hash_object(git::raw::ObjectType::Blob, text.as_bytes())?;
        for (sum, byte) in sum.iter_mut().zip(hash.as_bytes()) {
            *sum ^= byte;
        }
        count += 1;
    }
    let mut text = sum.iter().map(|b| format!("{b:02x}")).collect::<String>();
    text.push_str(&format!(" {count}"));
    let hash = git::raw::Oid::hash_object(git::raw::ObjectType::Blob, text.as_bytes())?;
    Ok(hash.into())
}

/// One unit of the check of a namespace in `repo` against its `signed`
/// refs, which the caller loaded once for the pass ([`Signed::load`]): at
/// most `limit` refs (one if `limit` is zero), after `from`'s, in the order of
/// their names. The names are those of the namespace's refs, `rad/sigrefs`
/// aside, and those of its signed refs.
///
/// Each ref must point at an object the repository has, or the namespace is
/// quarantined. A ref that is unsigned, at another target than its signed
/// one, or signed but absent quarantines the namespace too, unless the
/// namespace is the signer's: then it only marks the namespace stale, to be
/// re-signed once every ref has been checked. The last unit of a stale pass
/// returns the [`Complete`] proof [`resign`] takes.
///
/// A unit holds no more than `limit + 1` refs at once. It still reads every
/// ref of the namespace, to find the next ones after `from`, as libgit2
/// yields them in no order; that is a string comparison each, and libgit2's
/// own reading of `packed-refs`. Signed refs aren't read again: if
/// `rad/sigrefs` moved since they were, the unit stops with
/// [`Error::Changed`].
///
/// A namespace with no refs and no `rad/sigrefs` is clean. Nothing in the
/// repository changes.
pub fn check(
    repo: &Repository,
    signed: &Signed,
    authority: Authority,
    from: &Checkpoint,
    limit: usize,
) -> Result<Check, Error> {
    let namespace = signed.namespace;
    if let SignedState::Unverified(reason) = &signed.state {
        return Ok(Check::Quarantine(Problem::Unverified {
            reason: reason.clone(),
        }));
    }
    let limit = limit.max(1);
    let after = from.after.as_ref();

    // The names of the first `limit + 1` of the namespace's refs after
    // `from`: held as they stream past, the largest let go.
    let mut current = BTreeSet::<String>::new();
    each_name(repo, &namespace, |name| {
        if name == SIGREFS
            || after.is_some_and(|after| name <= after.as_str())
            || (current.len() > limit && current.last().is_some_and(|last| name >= last.as_str()))
        {
            return;
        }
        current.insert(name.to_owned());
        if current.len() > limit + 1 {
            current.pop_last();
        }
    })?;
    if target(repo, &namespace, SIGREFS)? != signed.at() {
        return Err(Error::Changed { namespace });
    }
    let current = current
        .into_iter()
        .map(|name| {
            let target = target(repo, &namespace, &name)?;
            let name = RefString::try_from(name)
                .map_err(|e| crate::storage::Error::Ref(crate::git::RefError::from(e)))?;
            Ok((name, target))
        })
        .collect::<Result<BTreeMap<RefString, Option<Oid>>, Error>>()?;
    let bound = match after {
        Some(after) => Bound::Excluded(after.as_refstr()),
        None => Bound::Unbounded,
    };
    // And of its signed refs.
    let signed_after = signed
        .refs()
        .into_iter()
        .flat_map(|refs| refs.range::<RefStr, _>((bound, Bound::Unbounded)))
        .take(limit + 1)
        .map(|(name, oid)| (name.as_refstr(), *oid))
        .collect::<BTreeMap<_, _>>();
    let names = current
        .keys()
        .map(RefString::as_refstr)
        .chain(signed_after.keys().copied())
        .collect::<BTreeSet<&RefStr>>();
    let odb = repo.backend.odb()?;

    let mut stale = from.stale;
    let mut last = None;
    let mut rest = names.iter();
    for name in rest.by_ref().take(limit) {
        let target = current.get(*name).copied().flatten();
        let signed = signed_after.get(*name).copied();
        let refname = (*name).to_owned();
        let problem = match (target, signed) {
            (Some(target), _) if !odb.exists(target.into()) => {
                return Ok(Check::Quarantine(Problem::MissingObject {
                    refname,
                    target,
                }));
            }
            (Some(target), Some(signed)) if target == signed => None,
            (Some(target), Some(signed)) => Some(Problem::Mismatched {
                refname,
                signed,
                target,
            }),
            (Some(target), None) => Some(Problem::Unsigned { refname, target }),
            (None, Some(signed)) => Some(Problem::Missing { refname, signed }),
            (None, None) => None,
        };
        if let Some(problem) = problem {
            match authority {
                Authority::Owner => stale = true,
                Authority::None => return Ok(Check::Quarantine(problem)),
            }
        }
        last = Some(*name);
    }
    Ok(match (rest.next(), last) {
        (Some(_), Some(last)) => Check::Continue(Checkpoint {
            after: Some(last.to_owned()),
            stale,
        }),
        _ if stale => Check::Stale(Complete {
            namespace,
            version: version(repo, &namespace)?,
        }),
        _ => Check::Clean,
    })
}

/// Re-signs the namespace a check found stale, in the repository `rid` of
/// `storage`, over its refs as they are, with `signer`, whose key must be the
/// namespace's. It takes the check's [`Complete`] proof, and refuses with
/// [`Error::Changed`] if the namespace's version has moved since.
///
/// It refuses to sign unless libgit2's fsync is on ([`super::enable_fsync`],
/// which reconciliation calls first). It opens its own repository object,
/// whose refs it reads only now, so their updates are flushed whatever
/// repository object its caller holds: the signed refs' objects are flushed
/// before their ref is updated, and the update before this returns.
pub fn resign<S>(
    storage: &Storage,
    rid: RepoId,
    complete: Complete,
    signer: &S,
) -> Result<SignedRefs, Error>
where
    S: crypto::Signer,
{
    let namespace = complete.namespace;
    if *signer.public_key() != namespace {
        return Err(Error::NotOwner {
            namespace,
            signer: *signer.public_key(),
        });
    }
    if !fsync_enabled() {
        return Err(Error::FsyncOff);
    }
    let repo = storage.repository_mut(rid)?;
    if version(&repo, &namespace)? != complete.version {
        return Err(Error::Changed { namespace });
    }
    Ok(repo.sign_refs(signer)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;
    use std::str::FromStr as _;

    use crate::crypto::{Signer as _, SigningKey};
    use crate::storage::{ReadRepository as _, ReadStorage as _};
    use crate::test::fixtures;

    struct Fixture {
        _tmp: tempfile::TempDir,
        storage: Storage,
        rid: RepoId,
        signer: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            // As reconciliation does first, before it opens a repository.
            super::super::enable_fsync().unwrap();
            let tmp = tempfile::tempdir().unwrap();
            let signer = SigningKey::mock(0xb4);
            let storage = Storage::open(tmp.path().join("storage"), fixtures::user()).unwrap();
            let (rid, _, _, _) =
                fixtures::project(tmp.path().join("project"), &storage, &signer).unwrap();
            Self {
                _tmp: tmp,
                storage,
                rid,
                signer,
            }
        }

        fn nid(&self) -> NodeId {
            *self.signer.public_key()
        }

        fn repo(&self) -> Repository {
            self.storage.repository(self.rid).unwrap()
        }

        fn name(&self, name: &str) -> String {
            format!("refs/namespaces/{}/{name}", self.nid())
        }

        /// A ref of the namespace, set without signing it.
        fn set(&self, name: &str, target: git::raw::Oid) {
            self.repo()
                .backend
                .reference(&self.name(name), target, true, "test")
                .unwrap();
        }

        fn target(&self, name: &str) -> git::raw::Oid {
            self.repo().backend.refname_to_id(&self.name(name)).unwrap()
        }

        /// The namespace's `refs/heads/master` commit's tree: an object the
        /// repository has, that no ref points at.
        fn other_object(&self) -> git::raw::Oid {
            let repo = self.repo();
            let commit = repo
                .backend
                .find_commit(self.target("refs/heads/master"))
                .unwrap();
            commit.tree_id()
        }

        /// Every unit of a check, run to its end, with `limit` refs each.
        fn run(&self, authority: Authority, limit: usize) -> (Check, usize) {
            run(
                &self.repo(),
                &self.nid(),
                authority,
                Checkpoint::default(),
                limit,
            )
        }

        /// A check's proof that the namespace is stale.
        fn complete(&self) -> Complete {
            match self.run(Authority::Owner, UNIT_REFS).0 {
                Check::Stale(complete) => complete,
                other => panic!("{other:?}"),
            }
        }
    }

    /// Every unit of the check of `namespace`, from `from`, with `limit` refs
    /// each: its end, and how many units it took. More units than the
    /// namespace has names, and one more, fail the test rather than run on.
    fn run(
        repo: &Repository,
        namespace: &NodeId,
        authority: Authority,
        mut from: Checkpoint,
        limit: usize,
    ) -> (Check, usize) {
        let signed = Signed::load(repo, namespace).unwrap();
        let mut names = signed.refs().map_or(0, BTreeMap::len);
        each_name(repo, namespace, |_| names += 1).unwrap();
        for units in 1..=names + 2 {
            match check(repo, &signed, authority, &from, limit).unwrap() {
                Check::Continue(next) => {
                    assert!(next.after > from.after, "{next:?} after {from:?}");
                    from = next;
                }
                end => return (end, units),
            }
        }
        panic!("a check of {names} names ran past {} units", names + 2)
    }

    fn refname(name: &str) -> RefString {
        RefString::try_from(name).unwrap()
    }

    #[test]
    fn a_signed_namespace_is_clean_in_units_of_any_size() {
        let f = Fixture::new();
        let signed = f.repo().references_of(&f.nid()).unwrap().len() - 1;
        assert_eq!(signed, 4);
        for authority in [Authority::Owner, Authority::None] {
            assert_eq!(f.run(authority, UNIT_REFS), (Check::Clean, 1));
            // The smallest form: one ref a unit.
            assert_eq!(f.run(authority, 1), (Check::Clean, signed));
            assert_eq!(f.run(authority, 0), (Check::Clean, signed));
            assert_eq!(f.run(authority, 3), (Check::Clean, 2));
        }
    }

    #[test]
    fn a_namespace_without_refs_is_clean() {
        let f = Fixture::new();
        let stranger = *SigningKey::mock(0x01).public_key();
        let repo = f.repo();
        for authority in [Authority::of(&stranger, Some(&stranger)), Authority::None] {
            assert_eq!(
                run(
                    &repo,
                    &stranger,
                    authority,
                    Checkpoint::default(),
                    UNIT_REFS
                ),
                (Check::Clean, 1)
            );
        }
    }

    #[test]
    fn the_authority_is_the_namespace_s_own_key_only() {
        let f = Fixture::new();
        let nid = f.nid();
        let other = *SigningKey::mock(0x01).public_key();
        assert_eq!(Authority::of(&nid, Some(&nid)), Authority::Owner);
        assert_eq!(Authority::of(&nid, Some(&other)), Authority::None);
        assert_eq!(Authority::of(&nid, None), Authority::None);
    }

    #[test]
    fn an_unsigned_ref_is_stale_for_its_owner_and_quarantined_for_anyone_else() {
        let f = Fixture::new();
        let master = f.target("refs/heads/master");
        // A ref a kill left unsigned, just after its update.
        f.set("refs/heads/topic", master);
        let sigrefs = f.target("refs/rad/sigrefs");

        assert_eq!(
            f.run(Authority::None, UNIT_REFS).0,
            Check::Quarantine(Problem::Unsigned {
                refname: refname("refs/heads/topic"),
                target: master.into(),
            })
        );
        let complete = f.complete();
        // Checking signs nothing.
        assert_eq!(f.target("refs/rad/sigrefs"), sigrefs);

        resign(&f.storage, f.rid, complete, &f.signer).unwrap();
        assert_ne!(f.target("refs/rad/sigrefs"), sigrefs);
        for authority in [Authority::Owner, Authority::None] {
            assert_eq!(f.run(authority, UNIT_REFS).0, Check::Clean);
        }
    }

    #[test]
    fn a_moved_ref_is_stale_for_its_owner_and_quarantined_for_anyone_else() {
        let f = Fixture::new();
        let master = f.target("refs/heads/master");
        let parent = f
            .repo()
            .backend
            .find_commit(master)
            .unwrap()
            .parent_id(0)
            .unwrap();
        f.set("refs/heads/master", parent);

        assert_eq!(
            f.run(Authority::None, 1).0,
            Check::Quarantine(Problem::Mismatched {
                refname: refname("refs/heads/master"),
                signed: master.into(),
                target: parent.into(),
            })
        );
        assert!(matches!(f.run(Authority::Owner, 1).0, Check::Stale(_)));
        resign(&f.storage, f.rid, f.complete(), &f.signer).unwrap();
        assert_eq!(f.run(Authority::None, 1).0, Check::Clean);
    }

    #[test]
    fn a_deleted_ref_is_stale_for_its_owner_and_quarantined_for_anyone_else() {
        let f = Fixture::new();
        let master = f.target("refs/heads/master");
        f.repo()
            .backend
            .find_reference(&f.name("refs/heads/master"))
            .unwrap()
            .delete()
            .unwrap();

        assert_eq!(
            f.run(Authority::None, UNIT_REFS).0,
            Check::Quarantine(Problem::Missing {
                refname: refname("refs/heads/master"),
                signed: master.into(),
            })
        );
        resign(&f.storage, f.rid, f.complete(), &f.signer).unwrap();
        assert_eq!(f.run(Authority::None, UNIT_REFS).0, Check::Clean);
    }

    #[test]
    fn refs_without_signed_refs_are_stale_for_their_owner_only() {
        let f = Fixture::new();
        f.repo()
            .backend
            .find_reference(&f.name("refs/rad/sigrefs"))
            .unwrap()
            .delete()
            .unwrap();
        assert!(matches!(
            f.run(Authority::None, UNIT_REFS).0,
            Check::Quarantine(Problem::Unsigned { .. })
        ));
        resign(&f.storage, f.rid, f.complete(), &f.signer).unwrap();
        assert_eq!(f.run(Authority::None, UNIT_REFS).0, Check::Clean);
    }

    /// Writes a loose ref by hand: libgit2 won't point one at a missing object.
    fn write_loose_ref(repo: &Path, name: &str, target: &str) {
        let path = repo.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("{target}\n")).unwrap();
    }

    #[test]
    fn a_ref_to_a_missing_object_is_quarantined_even_for_its_owner() {
        let missing = "0123456789abcdef0123456789abcdef01234567";
        let quarantined = Check::Quarantine(Problem::MissingObject {
            refname: refname("refs/tags/zz"),
            target: Oid::from_str(missing).unwrap(),
        });
        for authority in [Authority::Owner, Authority::None] {
            let f = Fixture::new();
            write_loose_ref(f.repo().path(), &f.name("refs/tags/zz"), missing);
            assert_eq!(f.run(authority, UNIT_REFS).0, quarantined, "{authority:?}");
        }
        // Its name is last, after a stale ref: the owner's check, which found
        // the namespace stale, still quarantines it, and signs nothing.
        let f = Fixture::new();
        f.set("refs/heads/master", f.other_object());
        write_loose_ref(f.repo().path(), &f.name("refs/tags/zz"), missing);
        let sigrefs = f.target("refs/rad/sigrefs");
        assert_eq!(f.run(Authority::Owner, 1).0, quarantined);
        assert_eq!(f.target("refs/rad/sigrefs"), sigrefs);
    }

    #[test]
    fn signed_refs_that_dont_load_are_quarantined_even_for_their_owner() {
        let f = Fixture::new();
        let blob = f.repo().backend.blob(b"not signed refs").unwrap();
        f.set("refs/rad/sigrefs", blob);
        for authority in [Authority::Owner, Authority::None] {
            assert!(matches!(
                f.run(authority, UNIT_REFS).0,
                Check::Quarantine(Problem::Unverified { .. })
            ));
        }
    }

    #[test]
    fn a_checkpoint_carries_staleness_to_the_last_unit() {
        let f = Fixture::new();
        // `refs/heads/master` is moved; it sorts before the refs after it.
        f.set("refs/heads/master", f.other_object());
        let repo = f.repo();
        let nid = f.nid();
        let signed = Signed::load(&repo, &nid).unwrap();
        let first = check(&repo, &signed, Authority::Owner, &Checkpoint::default(), 2).unwrap();
        let Check::Continue(from) = first else {
            panic!("{first:?}")
        };
        assert!(from.stale);
        // The next units find nothing more, but the namespace stays stale.
        assert!(matches!(
            run(&repo, &nid, Authority::Owner, from, 2).0,
            Check::Stale(_)
        ));
        // A checkpoint past the moved ref doesn't see it: why a checkpoint
        // holds only while the namespace's version is unchanged.
        let clean = Checkpoint {
            after: Some(refname("refs/heads/master")),
            stale: false,
        };
        assert_eq!(run(&repo, &nid, Authority::None, clean, 1).0, Check::Clean);
    }

    #[test]
    fn the_version_changes_with_any_ref() {
        let f = Fixture::new();
        let nid = f.nid();
        let before = version(&f.repo(), &nid).unwrap();
        assert_eq!(version(&f.repo(), &nid).unwrap(), before);
        let master = f.target("refs/heads/master");
        f.set("refs/heads/topic", master);
        let topic = version(&f.repo(), &nid).unwrap();
        assert_ne!(topic, before);
        f.set("refs/heads/topic", f.other_object());
        assert_ne!(version(&f.repo(), &nid).unwrap(), topic);
        // Another namespace's refs aren't its.
        let stranger = *SigningKey::mock(0x01).public_key();
        let empty = version(&f.repo(), &stranger).unwrap();
        f.set("refs/heads/other", master);
        assert_eq!(version(&f.repo(), &stranger).unwrap(), empty);
    }

    #[test]
    fn no_key_but_the_namespace_s_own_signs_it() {
        let f = Fixture::new();
        f.set("refs/heads/topic", f.target("refs/heads/master"));
        let sigrefs = f.target("refs/rad/sigrefs");
        let other = SigningKey::mock(0x01);
        assert!(matches!(
            resign(&f.storage, f.rid, f.complete(), &other),
            Err(Error::NotOwner { .. })
        ));
        assert_eq!(f.target("refs/rad/sigrefs"), sigrefs);
        // Nor does the namespace's own key sign another's, though a check
        // under the wrong authority found it stale.
        let theirs = format!("refs/namespaces/{}/refs/heads/x", other.public_key());
        let repo = f.repo();
        repo.backend
            .reference(&theirs, f.target("refs/heads/master"), true, "test")
            .unwrap();
        let (Check::Stale(complete), _) = run(
            &repo,
            other.public_key(),
            Authority::Owner,
            Checkpoint::default(),
            UNIT_REFS,
        ) else {
            panic!("not stale")
        };
        assert!(matches!(
            resign(&f.storage, f.rid, complete, &f.signer),
            Err(Error::NotOwner { .. })
        ));
        let theirs = format!("refs/namespaces/{}/refs/rad/sigrefs", other.public_key());
        assert!(f.repo().backend.find_reference(&theirs).is_err());
    }

    // Review of heartwood #6, round 1: a stale namespace is re-signed only
    // once a check has run to its end. Its first unit, which found a stale
    // ref, gives no proof to re-sign with, and the pass ends quarantined at a
    // missing object after it.
    #[test]
    fn a_namespace_is_re_signed_only_after_a_whole_check() {
        let f = Fixture::new();
        let missing = "0123456789abcdef0123456789abcdef01234567";
        f.set("refs/aaa/stale", f.target("refs/heads/master"));
        write_loose_ref(f.repo().path(), &f.name("refs/zzz/missing"), missing);
        let repo = f.repo();
        let signed = Signed::load(&repo, &f.nid()).unwrap();
        // The first unit: a checkpoint, no proof.
        let first = check(&repo, &signed, Authority::Owner, &Checkpoint::default(), 1).unwrap();
        assert!(
            matches!(&first, Check::Continue(from) if from.stale),
            "{first:?}"
        );
        // The whole pass: quarantined, so nothing to re-sign with.
        assert_eq!(
            f.run(Authority::Owner, 1).0,
            Check::Quarantine(Problem::MissingObject {
                refname: refname("refs/zzz/missing"),
                target: Oid::from_str(missing).unwrap(),
            })
        );
    }

    // Review of heartwood #6, round 1: refs that changed after the check
    // aren't signed.
    #[test]
    fn a_namespace_changed_since_its_check_isn_t_signed() {
        let f = Fixture::new();
        f.set("refs/heads/topic", f.target("refs/heads/master"));
        let complete = f.complete();
        assert_eq!(complete.namespace(), &f.nid());
        assert_eq!(complete.version(), version(&f.repo(), &f.nid()).unwrap());
        let sigrefs = f.target("refs/rad/sigrefs");
        // Since the check, another ref moved.
        f.set("refs/heads/topic", f.other_object());
        assert!(matches!(
            resign(&f.storage, f.rid, complete, &f.signer),
            Err(Error::Changed { .. })
        ));
        assert_eq!(f.target("refs/rad/sigrefs"), sigrefs);
    }

    // Review of heartwood #6, round 1: a unit that finds `rad/sigrefs` moved
    // since the pass read the signed refs stops.
    #[test]
    fn a_unit_stops_if_the_signed_refs_moved() {
        let f = Fixture::new();
        let repo = f.repo();
        let signed = Signed::load(&repo, &f.nid()).unwrap();
        f.set("refs/heads/topic", f.target("refs/heads/master"));
        f.storage
            .repository_mut(f.rid)
            .unwrap()
            .sign_refs(&f.signer)
            .unwrap();
        assert!(matches!(
            check(&repo, &signed, Authority::None, &Checkpoint::default(), 1),
            Err(Error::Changed { .. })
        ));
    }

    #[test]
    fn fsync_turns_on_once() {
        super::super::enable_fsync().unwrap();
        assert!(fsync_enabled());
        super::super::enable_fsync().unwrap();
        assert!(fsync_enabled());
    }

    /// Writes `count` refs of the namespace, all at the namespace's
    /// `refs/heads/master` commit, into the repository's `packed-refs`, as
    /// `git pack-refs` would.
    fn pack_refs(f: &Fixture, count: usize) {
        let master = f.target("refs/heads/master");
        let mut packed = String::from("# pack-refs with: peeled fully-peeled sorted \n");
        let mut names = (0..count)
            .map(|i| f.name(&format!("refs/heads/bulk/{i:06}")))
            .collect::<Vec<_>>();
        names.sort();
        for name in names {
            packed.push_str(&format!("{master} {name}\n"));
        }
        std::fs::write(f.repo().path().join("packed-refs"), packed).unwrap();
    }

    // Review of heartwood #6, round 1: a unit holds no more refs than it
    // checks, and reads the signed refs not at all. With 100,000 packed refs,
    // a one-ref unit took 0.15 to 0.3 s in a debug build here (0.07 to 0.14 s
    // in release), well inside the watchdog's 30 s; the check that loaded and
    // verified the whole namespace every unit took 2.2 s.
    //
    // The bound is relative, so that it holds on a slow machine as on a fast
    // one: each unit takes less than half of the work the old units each
    // repeated, every ref read into a map and the signed refs read and
    // verified, timed here first. The old check fails it.
    #[test]
    fn a_unit_s_work_doesn_t_grow_with_the_namespace() {
        let f = Fixture::new();
        pack_refs(&f, 100_000);
        let repo = f.repo();
        let nid = f.nid();
        let start = std::time::Instant::now();
        let all = repo.references_of(&nid).unwrap();
        let signed = Signed::load(&repo, &nid).unwrap();
        let whole = start.elapsed();
        assert!(all.len() > 100_000);
        let mut from = Checkpoint::default();
        for _ in 0..3 {
            let start = std::time::Instant::now();
            let unit = check(&repo, &signed, Authority::Owner, &from, 1).unwrap();
            let took = start.elapsed();
            eprintln!(
                "a one-ref unit of 100,000 refs took {took:?}, the whole namespace {whole:?}"
            );
            assert!(
                took < whole / 2,
                "a one-ref unit took {took:?}, the whole namespace {whole:?}"
            );
            let Check::Continue(next) = unit else {
                panic!("{unit:?}")
            };
            from = next;
        }
    }

    // Review of heartwood #6, round 1: libgit2 yields loose refs before packed
    // ones, so a later name may sort first. Every unit still takes the next
    // names in order, and every name is checked once.
    #[test]
    fn a_check_visits_every_name_in_order_loose_and_packed() {
        let f = Fixture::new();
        pack_refs(&f, 10);
        // A loose ref sorting after them all, and one before.
        f.set("refs/zzz/last", f.target("refs/heads/master"));
        f.set("refs/aaa/first", f.target("refs/heads/master"));
        let repo = f.repo();
        let nid = f.nid();
        let signed = Signed::load(&repo, &nid).unwrap();
        let mut names = Vec::new();
        each_name(&repo, &nid, |name| {
            if name != SIGREFS {
                names.push(name.to_owned())
            }
        })
        .unwrap();
        names.extend(signed.refs().unwrap().keys().map(|name| name.to_string()));
        names.sort();
        names.dedup();

        let mut from = Checkpoint::default();
        let mut visited = Vec::new();
        let end = loop {
            match check(&repo, &signed, Authority::Owner, &from, 1).unwrap() {
                Check::Continue(next) => {
                    visited.push(next.after.as_ref().unwrap().to_string());
                    from = next;
                }
                end => break end,
            }
            assert!(visited.len() <= names.len(), "{visited:?}");
        };
        assert!(matches!(end, Check::Stale(_)), "{end:?}");
        // The last unit checks the last name, and returns no checkpoint.
        assert_eq!(visited, names[..names.len() - 1]);
    }
}
