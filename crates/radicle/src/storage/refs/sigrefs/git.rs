//! Signed References are encoded in the Git commit graph.
//! This module provides traits for interacting with a Git
//! repository to read and write data for Signed References.

pub mod object;
pub mod reference;

#[cfg(test)]
mod properties;

use crypto::PublicKey;
use radicle_git_metadata::author::Author;
use radicle_git_metadata::author::Time;

/// Convenience type that corresponds to an [`Author`].
///
/// Most users will want to instantiate this via [`Committer::from_env_or_now`],
/// which automatically constructs a stable [`Author`] for tests as well.
///
/// Otherwise, an [`Author`] can be provided via [`Committer::new`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Committer {
    pub author: Author,
}

impl Committer {
    const NAME: &str = "radicle";

    /// Construct a [`Committer`] using the timestamp found at
    /// [`GIT_COMMITTER_DATE`],
    ///
    /// If [`GIT_COMMITTER_DATE`] is unset, it uses the current system
    /// time.
    ///
    /// The given [`PublicKey`] is always used for the email.
    ///
    /// In test code, [`Committer::stable`] is returned.
    ///
    /// [`GIT_COMMITTER_DATE`]: crate::profile::env::GIT_COMMITTER_DATE
    pub fn from_env_or_now(public_key: &PublicKey) -> Self {
        #[cfg(any(test, feature = "test"))]
        return Self::stable(public_key);

        #[cfg(not(any(test, feature = "test")))]
        {
            use crate::profile::env::GIT_COMMITTER_DATE;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            let timestamp = committer_time(std::env::var(GIT_COMMITTER_DATE), now);
            Self::from_key_and_time(public_key, timestamp)
        }
    }

    /// Provide a stable [`Committer`] with the same `name`, `email`, and `time`
    /// values.
    ///
    /// The [`Time`] value is constructed using the same seconds value used for
    /// other tests. These values are set via the `RAD_LOCAL_TIME` environment
    /// variable.
    #[cfg(any(test, feature = "test"))]
    pub fn stable(public_key: &PublicKey) -> Self {
        Self::from_key_and_time(public_key, 1671125284)
    }

    /// Construct a [`Committer`] with the provided [`Author`].
    pub fn new(author: Author) -> Self {
        Self { author }
    }

    pub fn into_inner(self) -> Author {
        self.author
    }

    fn from_key_and_time(public_key: &PublicKey, timestamp: i64) -> Self {
        Self::new(Author {
            name: Self::NAME.to_string(),
            email: public_key.to_human(),
            time: Time::new(timestamp, 0),
        })
    }
}

/// The committer time `value` gives, in seconds since the epoch, or `now`'s.
/// A value that isn't an integer (git takes other date formats too), or isn't
/// Unicode, is ignored with a warning: never a panic.
#[cfg_attr(any(test, feature = "test"), allow(dead_code))]
fn committer_time(value: Result<String, std::env::VarError>, now: u64) -> i64 {
    use crate::profile::env::GIT_COMMITTER_DATE;

    let seconds = match value {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(seconds) => seconds,
            Err(e) => {
                log::warn!(target: "radicle", "Ignoring `{GIT_COMMITTER_DATE}`, whose value {s:?} isn't a time in seconds: {e}");
                now
            }
        },
        Err(std::env::VarError::NotPresent) => now,
        Err(std::env::VarError::NotUnicode(_)) => {
            log::warn!(target: "radicle", "Ignoring `{GIT_COMMITTER_DATE}`: it isn't valid Unicode");
            now
        }
    };
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

mod git2_impls {
    //! [`git2::Repository`] implementations of the [`object`] and [`reference`] traits.
    //!
    //! [`object`]: super::object
    //! [`reference`]: super::reference

    use std::path::Path;

    use radicle_oid::Oid;

    use crate::git;

    use super::object;
    use super::object::{RefsEntry, SignatureEntry};
    use super::reference;

    impl object::Reader for git2::Repository {
        fn read_commit(&self, oid: &Oid) -> Result<Option<Vec<u8>>, object::error::ReadCommit> {
            use object::error::ReadCommit;

            let odb = self.odb().map_err(ReadCommit::other)?;
            let object = odb.read(git2::Oid::from(*oid));
            match object {
                Ok(object) => {
                    if object.kind() != git2::ObjectType::Commit {
                        return Err(ReadCommit::incorrect_object_error(*oid, object.kind()));
                    }
                    Ok(Some(object.data().to_vec()))
                }
                Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
                Err(e) => Err(ReadCommit::other(e)),
            }
        }

        fn read_blob(
            &self,
            oid: &Oid,
            path: &Path,
        ) -> Result<Option<object::Blob>, object::error::ReadBlob> {
            use object::error::ReadBlob;

            let commit = match self.find_commit(git2::Oid::from(*oid)) {
                Ok(c) => c,
                Err(e) if e.code() == git2::ErrorCode::NotFound => {
                    return Err(ReadBlob::commit_not_found_error(*oid));
                }
                Err(e) => return Err(ReadBlob::other(e)),
            };

            let tree = commit.tree().map_err(ReadBlob::other)?;

            let entry = match tree.get_path(path) {
                Ok(e) => e,
                Err(e) if e.code() == git2::ErrorCode::NotFound => return Ok(None),
                Err(e) => return Err(ReadBlob::other(e)),
            };

            let object = entry.to_object(self).map_err(ReadBlob::other)?;
            let blob = object.as_blob().ok_or(ReadBlob::incorrect_object_error(
                *oid,
                path.to_path_buf(),
                object.kind().unwrap_or(git2::ObjectType::Any),
            ))?;

            Ok(Some(object::Blob {
                oid: blob.id().into(),
                bytes: blob.content().to_vec(),
            }))
        }
    }

    impl object::Writer for git2::Repository {
        fn write_tree(
            &self,
            refs: RefsEntry,
            signature: SignatureEntry,
        ) -> Result<Oid, object::error::WriteTree> {
            use object::error::WriteTree;

            let odb = self.odb().map_err(WriteTree::write_error)?;

            let refs_oid = odb
                .write(git2::ObjectType::Blob, &refs.content)
                .map_err(WriteTree::refs_error)?;

            let sig_oid = odb
                .write(git2::ObjectType::Blob, &signature.content)
                .map_err(WriteTree::signature_error)?;

            let mut builder = self.treebuilder(None).map_err(WriteTree::write_error)?;

            builder
                .insert(&refs.path, refs_oid, git2::FileMode::Blob.into())
                .map_err(WriteTree::refs_error)?;

            builder
                .insert(&signature.path, sig_oid, git2::FileMode::Blob.into())
                .map_err(WriteTree::signature_error)?;

            let tree_oid = builder.write().map_err(WriteTree::write_error)?;

            Ok(Oid::from(tree_oid))
        }

        fn write_commit(&self, bytes: &[u8]) -> Result<Oid, object::error::WriteCommit> {
            use object::error::WriteCommit;

            let odb = self.odb().map_err(WriteCommit::other)?;

            let oid = odb
                .write(git2::ObjectType::Commit, bytes)
                .map_err(WriteCommit::other)?;

            Ok(Oid::from(oid))
        }
    }

    impl reference::Reader for git2::Repository {
        fn find_reference(
            &self,
            reference: &git::fmt::Namespaced,
        ) -> Result<Option<Oid>, reference::error::FindReference> {
            match self.refname_to_id(reference.as_str()) {
                Ok(oid) => Ok(Some(Oid::from(oid))),
                Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
                Err(e) => Err(reference::error::FindReference::other(e)),
            }
        }
    }

    impl reference::Writer for git2::Repository {
        fn write_reference(
            &self,
            reference: &git::fmt::Namespaced,
            commit: Oid,
            parent: Option<Oid>,
            reflog: String,
        ) -> Result<(), reference::error::WriteReference> {
            let new = git2::Oid::from(commit);

            match parent {
                Some(parent) => {
                    let old = git2::Oid::from(parent);
                    // The old OID provides a guard, which gives us a compare-and-swap —
                    // the write will fail if the ref has moved since we read it.
                    self.reference_matching(reference.as_str(), new, true, old, &reflog)
                        .map_err(reference::error::WriteReference::other)?;
                }
                None => {
                    self.reference(reference.as_str(), new, false, &reflog)
                        .map_err(reference::error::WriteReference::other)?;
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod committer_time_test {
    use std::env::VarError;

    use super::committer_time;

    // Security R-14: `GIT_COMMITTER_DATE` that isn't an integer, such as one of
    // git's own date formats, falls back to now rather than panicking.
    #[test]
    fn a_committer_date_that_isn_t_an_integer_is_now() {
        assert_eq!(committer_time(Ok("1671125284".to_owned()), 7), 1671125284);
        assert_eq!(committer_time(Ok("2005-04-07T22:13:13".to_owned()), 7), 7);
        assert_eq!(committer_time(Ok("@1112911993 +0200".to_owned()), 7), 7);
        assert_eq!(committer_time(Err(VarError::NotPresent), 7), 7);
        assert_eq!(committer_time(Ok(u64::MAX.to_string()), 7), i64::MAX);
    }
}
