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
///
/// It is read as git reads `GIT_COMMITTER_DATE`, by gitoxide's parser
/// ([`gix_date::parse`]): git's raw format, with or without its `@`
/// (`@1112911993 +0200`), a Unix time, ISO 8601, RFC 2822, and git's other
/// formats. Its zone is dropped, as before: a committer's time is in UTC. An
/// empty value is now, as it is for git.
///
/// A value the parser refuses, or that isn't Unicode, is ignored with a
/// warning, never a panic. A relative date ("2 days ago") is one, as it is
/// for git there. So is a value the parser reads but git refuses
/// ([`refused_by_git`]).
#[cfg_attr(any(test, feature = "test"), allow(dead_code))]
fn committer_time(value: Result<String, std::env::VarError>, now: u64) -> i64 {
    use crate::profile::env::GIT_COMMITTER_DATE;

    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let value = match value {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return now,
        Err(std::env::VarError::NotUnicode(_)) => {
            log::warn!(target: "radicle", "Ignoring `{GIT_COMMITTER_DATE}`: it isn't valid Unicode");
            return now;
        }
    };
    let date = value.trim();
    if date.is_empty() {
        return now;
    }
    // Git's `@` marks its raw format, or a Unix time, as one.
    let marked = date.strip_prefix('@').map(str::trim_start);
    let date = marked.unwrap_or(date);
    if let Some(refusal) = refused_by_git(date, marked.is_some()) {
        log::warn!(target: "radicle", "Ignoring `{GIT_COMMITTER_DATE}`, whose value {value:?} git refuses: {refusal}");
        return now;
    }
    match gix_date::parse(date, None) {
        Ok(time) => time.seconds,
        Err(e) => {
            log::warn!(target: "radicle", "Ignoring `{GIT_COMMITTER_DATE}`, whose value {value:?} isn't a date: {e}");
            now
        }
    }
}

/// Why git refuses `date`, a committer date that gix-date reads, with its
/// `@` taken off (`marked`): a Unix time with a sign; one of fewer than nine
/// digits, outside git's raw format (`@<seconds> <zone>`, whatever the
/// seconds); and a date with no time.
#[cfg_attr(any(test, feature = "test"), allow(dead_code))]
fn refused_by_git(date: &str, marked: bool) -> Option<&'static str> {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let mut fields = date.split_whitespace();
    let first = fields.next()?;
    let (zone, rest) = (fields.next(), fields.next());

    let signed = |s: &str| s.len() > 1 && s.starts_with(['+', '-']) && digits(&s[1..]);

    // A Unix time, alone or with a zone, as gix-date reads one.
    let unsigned = first.strip_prefix(['+', '-']).unwrap_or(first);
    if digits(unsigned) && rest.is_none() && zone.is_none_or(signed) {
        if unsigned.len() != first.len() {
            return Some("a time with a sign");
        }
        // Git's raw format: one space, then a zone of a sign and four digits.
        let raw =
            marked && zone.is_some_and(|zone| zone.len() == 5 && date == format!("{first} {zone}"));
        if !raw && unsigned.len() < 9 {
            return Some("a time of fewer than nine digits, outside git's raw format");
        }
        return None;
    }
    if zone.is_none() && date.split('-').count() == 3 && date.split('-').all(digits) {
        return Some("a date with no time");
    }
    None
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

    /// A time that stands for now.
    const NOW: u64 = 7;

    /// What `git var GIT_COMMITTER_IDENT` makes of `date` as its committer
    /// date: its time in seconds, or `None` if git refuses it.
    fn git_time(date: &str) -> Option<i64> {
        let output = std::process::Command::new("git")
            .args(["var", "GIT_COMMITTER_IDENT"])
            .env("GIT_COMMITTER_NAME", "radicle")
            .env("GIT_COMMITTER_EMAIL", "radicle@localhost")
            .env("GIT_COMMITTER_DATE", date)
            .output()
            .expect("git runs");
        if !output.status.success() {
            return None;
        }
        let ident = String::from_utf8(output.stdout).unwrap();
        // `<name> <<email>> <seconds> <zone>`.
        let mut fields = ident.trim_end().rsplit(' ');
        let _zone = fields.next();
        Some(fields.next().unwrap().parse().unwrap())
    }

    // Review of heartwood #14, round 1: `GIT_COMMITTER_DATE` is read as git
    // reads it, against git itself: its raw format, a Unix time, ISO 8601 and
    // RFC 2822 give git's time, and what git refuses is now.
    #[test]
    fn a_committer_date_is_read_as_git_reads_it() {
        let read = [
            // Git's raw format, and a Unix time.
            "1112911993 +0200",
            "@1112911993 +0200",
            "@1112911993",
            "1112911993",
            " 1112911993 ",
            "@ 1112911993",
            "100000000 +0200",
            "@100000000",
            // Git's raw format takes any number of seconds.
            "@1000 +0200",
            "@0 +0000",
            // ISO 8601.
            "2005-04-07T22:13:13 +0200",
            "2005-04-07T22:13:13+02:00",
            "2005-04-07 22:13:13 +0200",
            "2005-04-07T22:13:13Z",
            "2005-04-07T22:13:13.5+02:00",
            "2005.04.07 22:13:13 +0200",
            // RFC 2822, and git's own format.
            "Thu, 07 Apr 2005 22:13:13 +0200",
            "Thu, 7 Apr 2005 22:13:13 +0200",
            "7 Apr 2005 22:13:13 +0200",
            "Thu Apr 7 22:13:13 2005 +0200",
        ];
        let refused = [
            "not a date",
            "now",
            "yesterday",
            "2 days ago",
            "@",
            "18446744073709551615",
            // gix-date reads these, and git doesn't: a time with a sign, one
            // of fewer than nine digits outside the raw format, and a date
            // with no time.
            "-1000",
            "+0200",
            "+1112911993",
            "-1112911993",
            "@-1000 +0000",
            "0",
            "1000",
            "99999999",
            "@1000",
            "@99999999",
            "1000 +0200",
            "99999999 +0200",
            "@1000  +0200",
            "2005-04-07",
            "2005-4-7",
        ];
        for date in read {
            let git = git_time(date).unwrap_or_else(|| panic!("git refuses {date:?}"));
            assert_eq!(committer_time(Ok(date.to_owned()), NOW), git, "{date:?}");
        }
        for date in refused {
            assert_eq!(git_time(date), None, "git reads {date:?}");
            assert_eq!(
                committer_time(Ok(date.to_owned()), NOW),
                NOW as i64,
                "{date:?}"
            );
        }
    }

    // Security R-14: a committer date that is unset, empty or not Unicode is
    // now, and never a panic.
    #[test]
    fn a_committer_date_that_isn_t_there_is_now() {
        assert_eq!(committer_time(Err(VarError::NotPresent), NOW), NOW as i64);
        assert_eq!(committer_time(Ok(String::new()), NOW), NOW as i64);
        assert_eq!(committer_time(Ok("  ".to_owned()), NOW), NOW as i64);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let value = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
            assert_eq!(
                committer_time(Err(VarError::NotUnicode(value)), NOW),
                NOW as i64
            );
        }
        assert_eq!(
            committer_time(Err(VarError::NotPresent), u64::MAX),
            i64::MAX
        );
    }
}
