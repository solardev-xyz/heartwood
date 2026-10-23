//! Repairs for a storage that a killed process may have left part way
//! through an operation, before a node runs on it again.
//!
//! Each function is one unit of that repair: idempotent, and safe to run
//! again after a kill at any point. Run them only while no node runs on the
//! storage, since they remove what a live operation would still be using.

pub mod namespace;

use std::ffi::{OsString, c_int};
use std::path::Path;
use std::{fs, io};

use crate::prelude::RepoId;

use super::TempRepository;

/// Turns on libgit2's fsync for this process: from then on, every loose
/// object, pack and loose ref it writes, and their directories, are flushed
/// to disk as they are written, so a written object is durable before a ref
/// that points at it is updated. It stays on: nothing here turns it off.
///
/// A loose ref is flushed only by a repository opened after this is called,
/// since libgit2 reads the setting when it opens a repository's refs.
pub fn enable_fsync() -> Result<(), FsyncError> {
    libgit2_sys::init();
    // SAFETY: with `GIT_OPT_ENABLE_FSYNC_GITDIR`, `git_libgit2_opts` reads
    // exactly one more argument, an `int`, which is passed; libgit2 is
    // initialized above.
    let code = unsafe {
        libgit2_sys::git_libgit2_opts(
            libgit2_sys::GIT_OPT_ENABLE_FSYNC_GITDIR as c_int,
            1 as c_int,
        )
    };
    if code < 0 {
        return Err(FsyncError(code));
    }
    Ok(())
}

/// libgit2 refused to turn fsync on, with this error code.
#[derive(Debug, thiserror::Error)]
#[error("libgit2 refused to turn fsync on (error {0})")]
pub struct FsyncError(pub c_int);

/// The extension the storage once gave temporary clones.
const LEGACY_TEMP_EXT: &str = "lock";

/// Ref lock files at a repository's root, besides those under `refs/`.
const ROOT_LOCKS: [&str; 3] = ["packed-refs.lock", "HEAD.lock", "config.lock"];

/// What [`remove_temporary_clones`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TemporaryClones {
    /// The repositories whose temporary clones were removed.
    pub removed: Vec<RepoId>,
    /// Entries with an extension that were left alone: neither a temporary
    /// clone's name, nor a directory.
    pub left: usize,
}

/// Removes the temporary clones a killed clone or fetch left in `storage`:
/// directories directly under it named `<RID>.tmp`, as [`TempRepository`]
/// names them, or `<RID>.lock`, as the storage once did, where `<RID>`
/// parses as a repository ID.
///
/// An entry is removed only once `lstat` shows a real directory, and the
/// removal follows no symbolic links. Any other entry with an extension,
/// a symbolic link with a clone's name included, is left alone and
/// counted.
pub fn remove_temporary_clones(storage: &Path) -> io::Result<TemporaryClones> {
    let mut done = TemporaryClones::default();
    for entry in fs::read_dir(storage)? {
        let path = entry?.path();
        let Some(ext) = path.extension() else {
            continue;
        };
        let rid = (ext == TempRepository::EXT || ext == LEGACY_TEMP_EXT)
            .then(|| path.file_stem())
            .flatten()
            .and_then(|stem| RepoId::try_from(OsString::from(stem)).ok());
        let Some(rid) = rid else {
            done.left += 1;
            continue;
        };
        if !fs::symlink_metadata(&path)?.file_type().is_dir() {
            done.left += 1;
            continue;
        }
        // Follows no symbolic links: one found inside is removed, not its
        // target, and so is the clone's own path if it was swapped for one.
        fs::remove_dir_all(&path)?;
        done.removed.push(rid);
    }
    Ok(done)
}

/// Removes the ref lock files a killed update left in the repository at
/// `repo`: regular files named `*.lock` under `refs/`, and
/// `packed-refs.lock`, `HEAD.lock` and `config.lock` at its root. A lock file
/// is an update that never committed, so its ref keeps its old value. Git
/// refuses a ref name any of whose components ends in `.lock`, so no file
/// removed under `refs/` is a ref.
///
/// Symbolic links are neither followed nor removed. Returns how many lock
/// files were removed.
pub fn remove_ref_locks(repo: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for name in ROOT_LOCKS {
        let path = repo.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => {
                fs::remove_file(&path)?;
                removed += 1;
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let refs = repo.join("refs");
    match fs::symlink_metadata(&refs) {
        Ok(meta) if meta.file_type().is_dir() => removed += remove_locks_under(&refs)?,
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(removed)
}

/// Removes the regular files named `*.lock` in `dir` and the directories
/// under it, descending into real directories only.
fn remove_locks_under(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        // Doesn't follow a symbolic link.
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            removed += remove_locks_under(&path)?;
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "lock") {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::arbitrary;

    fn rid() -> RepoId {
        arbitrary::r#gen(1)
    }

    fn file(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
    }

    #[test]
    fn temporary_clones_are_removed_and_nothing_else() {
        let storage = tempfile::tempdir().unwrap();
        let root = storage.path();
        let (a, b, repo, other) = (rid(), rid(), rid(), rid());
        // Two temporary clones, one in the legacy form.
        file(&root.join(format!("{}.tmp/objects/x", a.canonical())));
        file(&root.join(format!("{}.lock/HEAD", b.canonical())));
        // A repository, and entries a clone's name doesn't fit.
        file(&root.join(repo.canonical()).join("HEAD"));
        file(&root.join("other.bak/x"));
        file(&root.join(format!("{}.bak/x", other.canonical())));
        file(&root.join("not-a-rid.tmp/x"));
        file(&root.join(format!("{}.tmp", repo.canonical())));

        let done = remove_temporary_clones(root).unwrap();
        let mut removed = done.removed.clone();
        removed.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(removed, expected);
        assert_eq!(done.left, 4);
        assert!(root.join(repo.canonical()).join("HEAD").exists());
        assert!(root.join("other.bak/x").exists());
        assert!(root.join(format!("{}.bak/x", other.canonical())).exists());
        assert!(root.join("not-a-rid.tmp/x").exists());
        assert!(root.join(format!("{}.tmp", repo.canonical())).is_file());
        assert!(!root.join(format!("{}.tmp", a.canonical())).exists());
        assert!(!root.join(format!("{}.lock", b.canonical())).exists());

        // Again: nothing more to do.
        let again = remove_temporary_clones(root).unwrap();
        assert!(again.removed.is_empty());
        assert_eq!(again.left, 4);
    }

    #[test]
    fn a_clone_a_killed_process_left_is_removed() {
        use crate::storage::ReadRepository as _;

        let tmp = tempfile::tempdir().unwrap();
        let storage =
            super::super::Storage::open(tmp.path(), crate::test::fixtures::user()).unwrap();
        let rid = rid();
        // Named as `TempRepository` names it, and left as a killed clone
        // leaves it: it has no destructor of its own.
        let clone = storage.temporary_repository(rid).unwrap();
        let path = clone.as_ref().path().to_path_buf();
        drop(clone);
        assert!(path.is_dir());

        let done = remove_temporary_clones(storage.path()).unwrap();
        assert_eq!(
            done,
            TemporaryClones {
                removed: vec![rid],
                left: 0
            }
        );
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_temporary_clone_follows_no_symbolic_link() {
        use std::os::unix::fs::symlink;

        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("kept"));
        let root = storage.path();
        let (linked, holding) = (rid(), rid());
        // A clone's name that is a link to a directory elsewhere: left, and
        // its target kept.
        symlink(
            outside.path(),
            root.join(format!("{}.tmp", linked.canonical())),
        )
        .unwrap();
        // A clone holding a link to a directory elsewhere: removed, and the
        // link's target kept.
        let clone = root.join(format!("{}.tmp", holding.canonical()));
        fs::create_dir(&clone).unwrap();
        symlink(outside.path(), clone.join("link")).unwrap();

        let done = remove_temporary_clones(root).unwrap();
        assert_eq!(done.removed, vec![holding]);
        assert_eq!(done.left, 1);
        assert!(outside.path().join("kept").exists());
        assert!(fs::symlink_metadata(root.join(format!("{}.tmp", linked.canonical()))).is_ok());
    }

    #[test]
    fn ref_lock_files_are_removed_and_refs_kept() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        let nid = "z6MktestB4sYCt4Yxx9CNpmrJYCk7yN3fBkcDPqvgQ2ixaWS";
        let locks = [
            root.join("refs/heads/main.lock"),
            root.join(format!("refs/namespaces/{nid}/refs/heads/topic.lock")),
            root.join("packed-refs.lock"),
            root.join("HEAD.lock"),
            root.join("config.lock"),
        ];
        let kept = [
            root.join("refs/heads/main"),
            root.join(format!("refs/namespaces/{nid}/refs/rad/sigrefs")),
            root.join("other.lock"),
            root.join("HEAD"),
            // A directory named like a lock file is walked, not removed.
            root.join("refs/heads/dir.lock/ref"),
        ];
        for path in locks.iter().chain(&kept) {
            file(path);
        }

        assert_eq!(remove_ref_locks(root).unwrap(), locks.len());
        for path in &locks {
            assert!(!path.exists(), "{}", path.display());
        }
        for path in &kept {
            assert!(path.exists(), "{}", path.display());
        }
        // Again: nothing more to do.
        assert_eq!(remove_ref_locks(root).unwrap(), 0);
    }

    #[test]
    fn a_repository_without_refs_has_no_lock_files() {
        let repo = tempfile::tempdir().unwrap();
        assert_eq!(remove_ref_locks(repo.path()).unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn ref_lock_files_follow_no_symbolic_link() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let elsewhere = outside.path().join("elsewhere.lock");
        file(&elsewhere);
        file(&outside.path().join("dir/inner.lock"));
        let root = repo.path();
        fs::create_dir_all(root.join("refs/heads")).unwrap();
        // A link named like a lock file, and a link to a directory of them:
        // neither removed nor followed.
        symlink(&elsewhere, root.join("refs/heads/main.lock")).unwrap();
        symlink(outside.path().join("dir"), root.join("refs/linked")).unwrap();
        symlink(&elsewhere, root.join("HEAD.lock")).unwrap();

        assert_eq!(remove_ref_locks(root).unwrap(), 0);
        assert!(elsewhere.exists());
        assert!(outside.path().join("dir/inner.lock").exists());
        assert!(fs::symlink_metadata(root.join("refs/heads/main.lock")).is_ok());
    }
}
