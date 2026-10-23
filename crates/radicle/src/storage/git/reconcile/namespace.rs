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
use crate::storage::refs::{SIGREFS_BRANCH, SignedRefs};
use crate::storage::{
    ReadRepository as _, RepositoryError, SignRepository as _, WriteStorage as _,
};

use super::{FsyncError, enable_fsync};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    /// Refs remain: the next unit runs from this checkpoint.
    Continue(Checkpoint),
    /// Every ref is signed, at its target, and points at an object the
    /// repository has.
    Clean,
    /// Every ref points at an object the repository has, but the refs differ
    /// from the signed refs, and the namespace is the signer's: [`resign`]
    /// it.
    Stale,
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
    #[error(transparent)]
    Fsync(#[from] FsyncError),
    #[error("the key of {signer} may not sign the namespace of {namespace}")]
    NotOwner { namespace: NodeId, signer: NodeId },
}

/// The version of `namespace`'s refs in `repo`: a hash over every ref's name
/// and target, `rad/sigrefs` included. Any change to a ref changes it.
pub fn version(repo: &Repository, namespace: &NodeId) -> Result<Oid, Error> {
    let mut text = String::new();
    for (name, target) in repo.references_of(namespace)? {
        // A ref name has no space or line feed.
        text.push_str(name.as_str());
        text.push(' ');
        text.push_str(&target.to_string());
        text.push('\n');
    }
    let hash = git::raw::Oid::hash_object(git::raw::ObjectType::Blob, text.as_bytes())?;
    Ok(hash.into())
}

/// One unit of the check of `namespace` in `repo`: at most `limit` refs (one
/// if `limit` is zero), after `from`'s, in the order of their names. The
/// names are those of the namespace's refs, `rad/sigrefs` aside, and those
/// of its signed refs.
///
/// Each ref must point at an object the repository has, or the namespace is
/// quarantined. A ref that is unsigned, at another target than its signed
/// one, or signed but absent quarantines the namespace too, unless the
/// namespace is the signer's: then it only marks the namespace stale, to be
/// re-signed once every ref has been checked.
///
/// A namespace with no refs and no `rad/sigrefs` is clean. Nothing in the
/// repository changes.
pub fn check(
    repo: &Repository,
    namespace: &NodeId,
    authority: Authority,
    from: &Checkpoint,
    limit: usize,
) -> Result<Check, Error> {
    let sigrefs = SIGREFS_BRANCH.to_ref_string();
    let refs = BTreeMap::from(repo.references_of(namespace)?);
    let signed = match SignedRefs::load(*namespace, repo) {
        Ok(signed) => signed.map(|signed| BTreeMap::from(signed.refs().clone())),
        Err(err) => {
            return Ok(Check::Quarantine(Problem::Unverified {
                reason: err.to_string(),
            }));
        }
    };
    let names = refs
        .keys()
        .filter(|name| **name != sigrefs)
        .chain(signed.iter().flat_map(BTreeMap::keys))
        .map(RefString::as_refstr)
        .collect::<BTreeSet<&RefStr>>();
    let after = match &from.after {
        Some(after) => Bound::Excluded(after.as_refstr()),
        None => Bound::Unbounded,
    };
    let odb = repo.backend.odb()?;

    let mut stale = from.stale;
    let mut last = None;
    let mut rest = names.range::<&RefStr, _>((after, Bound::Unbounded));
    for name in rest.by_ref().take(limit.max(1)) {
        let target = refs.get(*name).copied();
        let signed = signed
            .as_ref()
            .and_then(|signed| signed.get(*name))
            .copied();
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
        _ if stale => Check::Stale,
        _ => Check::Clean,
    })
}

/// Re-signs `namespace` in the repository `rid` of `storage` over its refs as
/// they are, with `signer`, whose key must be the namespace's: once a check of
/// it ended [`Check::Stale`].
///
/// libgit2's fsync is turned on first ([`enable_fsync`]), and the repository
/// opened afresh: the signed refs' objects are flushed before their ref is
/// updated, and the update is flushed before this returns.
pub fn resign<S>(
    storage: &Storage,
    rid: RepoId,
    namespace: &NodeId,
    signer: &S,
) -> Result<SignedRefs, Error>
where
    S: crypto::Signer,
{
    if signer.public_key() != namespace {
        return Err(Error::NotOwner {
            namespace: *namespace,
            signer: *signer.public_key(),
        });
    }
    enable_fsync()?;
    let repo = storage.repository_mut(rid)?;
    Ok(repo.sign_refs(signer)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;
    use std::str::FromStr as _;

    use crate::crypto::{Signer as _, SigningKey};
    use crate::storage::ReadStorage as _;
    use crate::test::fixtures;

    struct Fixture {
        _tmp: tempfile::TempDir,
        storage: Storage,
        rid: RepoId,
        signer: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
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
            let repo = self.repo();
            let mut from = Checkpoint::default();
            for units in 1.. {
                match check(&repo, &self.nid(), authority, &from, limit).unwrap() {
                    Check::Continue(next) => {
                        assert!(next.after > from.after, "{next:?} after {from:?}");
                        from = next;
                    }
                    end => return (end, units),
                }
            }
            unreachable!()
        }
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
                check(
                    &repo,
                    &stranger,
                    authority,
                    &Checkpoint::default(),
                    UNIT_REFS
                )
                .unwrap(),
                Check::Clean
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
        assert_eq!(f.run(Authority::Owner, UNIT_REFS).0, Check::Stale);
        // Checking signs nothing.
        assert_eq!(f.target("refs/rad/sigrefs"), sigrefs);

        resign(&f.storage, f.rid, &f.nid(), &f.signer).unwrap();
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
        assert_eq!(f.run(Authority::Owner, 1).0, Check::Stale);
        resign(&f.storage, f.rid, &f.nid(), &f.signer).unwrap();
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
        assert_eq!(f.run(Authority::Owner, UNIT_REFS).0, Check::Stale);
        resign(&f.storage, f.rid, &f.nid(), &f.signer).unwrap();
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
        assert_eq!(f.run(Authority::Owner, UNIT_REFS).0, Check::Stale);
        resign(&f.storage, f.rid, &f.nid(), &f.signer).unwrap();
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
        let first = check(&repo, &nid, Authority::Owner, &Checkpoint::default(), 2).unwrap();
        let Check::Continue(from) = first else {
            panic!("{first:?}")
        };
        assert!(from.stale);
        // The next units find nothing more, but the namespace stays stale.
        let mut from = from;
        let end = loop {
            match check(&repo, &nid, Authority::Owner, &from, 2).unwrap() {
                Check::Continue(next) => from = next,
                end => break end,
            }
        };
        assert_eq!(end, Check::Stale);
        // A checkpoint past the moved ref doesn't see it: why a checkpoint
        // holds only while the namespace's version is unchanged.
        let clean = Checkpoint {
            after: Some(refname("refs/heads/master")),
            stale: false,
        };
        let mut from = clean;
        let end = loop {
            match check(&repo, &nid, Authority::None, &from, 1).unwrap() {
                Check::Continue(next) => from = next,
                end => break end,
            }
        };
        assert_eq!(end, Check::Clean);
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
            resign(&f.storage, f.rid, &f.nid(), &other),
            Err(Error::NotOwner { .. })
        ));
        assert_eq!(f.target("refs/rad/sigrefs"), sigrefs);
        // Nor does the namespace's own key sign another's.
        assert!(matches!(
            resign(&f.storage, f.rid, other.public_key(), &f.signer),
            Err(Error::NotOwner { .. })
        ));
        let theirs = format!("refs/namespaces/{}/refs/rad/sigrefs", other.public_key());
        assert!(f.repo().backend.find_reference(&theirs).is_err());
    }

    #[test]
    fn fsync_turns_on() {
        enable_fsync().unwrap();
        enable_fsync().unwrap();
    }
}
