//! Repairs for a storage that a killed process may have left part way
//! through an operation, before a node runs on it again.
//!
//! Each function is one unit of that repair: idempotent, and safe to run
//! again after a kill at any point. Run them only while no node runs on the
//! storage, since they remove what a live operation would still be using.
//!
//! A unit follows the root it is given, the storage or a repository, even
//! a link: that path is the host's own choice, and a home may be linked
//! elsewhere. It follows no link under that root (see `dir`).

mod dir;

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;

use crate::prelude::RepoId;

use super::TempRepository;

use dir::{Dir, Kind};

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
/// A clone is removed only if it is a directory itself, and its removal
/// follows no links. Any other entry with an extension, a link with a
/// clone's name included, is left alone and counted. `storage` itself is
/// followed if it is a link, as every unit's root is.
pub fn remove_temporary_clones(storage: &Path) -> io::Result<TemporaryClones> {
    let mut done = TemporaryClones::default();
    let root = Dir::open_root(storage)?;
    for name in root.names()? {
        let path = Path::new(&name);
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
        if !root.remove_tree(&name)? {
            done.left += 1;
            continue;
        }
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
/// Links are never followed, and a link already there is left. `repo`
/// itself is followed if it is a link, as every unit's root is. Returns how
/// many lock files were removed.
pub fn remove_ref_locks(repo: &Path) -> io::Result<usize> {
    let root = Dir::open_root(repo)?;
    let mut removed = 0;
    for name in ROOT_LOCKS {
        let name = OsStr::new(name);
        if root.kind(name)? == Some(Kind::File) && root.remove_file(name)? {
            removed += 1;
        }
    }
    if let Some(refs) = root.open_dir(OsStr::new("refs"))? {
        removed += remove_locks_under(&refs)?;
    }
    Ok(removed)
}

/// Removes the regular files named `*.lock` in `dir` and the directories
/// under it, entering directories themselves only.
fn remove_locks_under(dir: &Dir) -> io::Result<usize> {
    let mut removed = 0;
    for name in dir.names()? {
        match dir.kind(&name)? {
            Some(Kind::Dir) => {
                if let Some(sub) = dir.open_dir(&name)? {
                    removed += remove_locks_under(&sub)?;
                }
            }
            Some(Kind::File) if Path::new(&name).extension() == Some(OsStr::new("lock")) => {
                removed += usize::from(dir.remove_file(&name)?);
            }
            _ => {}
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

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

    // Review of heartwood #5, round 1: a `refs/` directory swapped for a link
    // to elsewhere while the walk runs is never followed.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refs_directory_swapped_for_a_link_is_never_followed() {
        use std::os::unix::fs::symlink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        use rustix::fs::{CWD, RenameFlags, renameat_with};

        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let refs = repo.path().join("refs");
        let spare = repo.path().join("spare");
        fs::create_dir(&refs).unwrap();
        symlink(outside.path(), &spare).unwrap();
        let victim = outside.path().join("victim.lock");
        file(&victim);
        // `RENAME_EXCHANGE` needs a filesystem that has it.
        if let Err(e) = renameat_with(CWD, &refs, CWD, &spare, RenameFlags::EXCHANGE) {
            eprintln!("skipped: the filesystem can't exchange names: {e}");
            return;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let swaps = Arc::new(AtomicUsize::new(0));
        let swapper = {
            let (stop, swaps) = (stop.clone(), swaps.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    renameat_with(CWD, &refs, CWD, &spare, RenameFlags::EXCHANGE).unwrap();
                    swaps.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        // The walk that resolved `refs/` again by its path followed the link
        // within its first calls, in well under a second.
        for _ in 0..100_000 {
            let _ = remove_ref_locks(repo.path());
            if !victim.exists() {
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        assert!(swaps.load(Ordering::Relaxed) > 0);
        assert!(
            victim.exists(),
            "a lock file outside the repository was removed"
        );
    }

    // Review of heartwood #5, round 1: a unit's root is followed, by design.
    #[cfg(unix)]
    #[test]
    fn a_linked_root_is_followed() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let clone = rid();
        file(
            &outside
                .path()
                .join(format!("{}.tmp/objects/x", clone.canonical())),
        );
        file(&outside.path().join("repo/refs/heads/main.lock"));
        let storage = parent.path().join("storage");
        symlink(outside.path(), &storage).unwrap();

        let done = remove_temporary_clones(&storage).unwrap();
        assert_eq!(
            done,
            TemporaryClones {
                removed: vec![clone],
                left: 0
            }
        );
        assert!(
            !outside
                .path()
                .join(format!("{}.tmp", clone.canonical()))
                .exists()
        );
        assert_eq!(remove_ref_locks(&storage.join("repo")).unwrap(), 1);
        assert!(!outside.path().join("repo/refs/heads/main.lock").exists());
    }

    /// A junction at `link` to the directory `target`, as `mklink /J` makes
    /// one, with no privilege.
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J {}", link.display());
    }

    // Review of heartwood #5, round 1: a junction is never followed, on
    // Windows.
    #[cfg(windows)]
    #[test]
    fn junctions_are_never_followed() {
        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("kept.lock"));
        file(&outside.path().join("dir/inner.lock"));
        let linked = rid();
        junction(
            &storage.path().join(format!("{}.tmp", linked.canonical())),
            outside.path(),
        );
        let repo = storage.path().join("repo");
        fs::create_dir_all(repo.join("refs/heads")).unwrap();
        // `mklink` takes no `/` in a path.
        junction(
            &repo.join("refs").join("linked"),
            &outside.path().join("dir"),
        );
        junction(&repo.join("HEAD.lock"), &outside.path().join("dir"));

        let done = remove_temporary_clones(storage.path()).unwrap();
        assert_eq!(
            done,
            TemporaryClones {
                removed: vec![],
                left: 1
            }
        );
        assert_eq!(remove_ref_locks(&repo).unwrap(), 0);
        assert!(outside.path().join("kept.lock").exists());
        assert!(outside.path().join("dir/inner.lock").exists());
    }
}
