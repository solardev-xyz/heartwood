//! The directories the cleanup units walk.
//!
//! On Unix, a directory is opened once, and its entries are examined,
//! entered and removed relative to its handle: no path under the root is
//! resolved again, so an entry swapped for a link at any moment is removed
//! itself, or skipped, and never followed. Only the root is opened by its
//! path, following links.
//!
//! Elsewhere (Windows), entries are reached by their paths. Each is checked
//! again, with `lstat`, just before it is entered or removed, and links and
//! reparse points (junctions included) are skipped. A process running as the
//! same user that swaps a directory for one in that instant could still
//! redirect the walk. That process could as well delete the files itself,
//! so this is outside the boundary the units keep.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;

/// What an entry is, as `lstat` sees it: a link is neither a directory nor a
/// file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Dir,
    File,
    Other,
}

pub(super) use imp::Dir;

#[cfg(unix)]
mod imp {
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;

    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
    use rustix::io::Errno;

    use super::*;

    const OPEN: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC);

    /// An open directory.
    pub(in super::super) struct Dir(OwnedFd);

    impl Dir {
        /// Opens the directory at `path`, following links.
        pub fn open_root(path: &Path) -> io::Result<Self> {
            Ok(Self(rustix::fs::openat(CWD, path, OPEN, Mode::empty())?))
        }

        /// The names of its entries, `.` and `..` aside.
        pub fn names(&self) -> io::Result<Vec<OsString>> {
            let mut names = Vec::new();
            for entry in rustix::fs::Dir::read_from(&self.0)? {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if name != b"." && name != b".." {
                    names.push(OsStr::from_bytes(name).to_owned());
                }
            }
            Ok(names)
        }

        /// What its entry `name` is, if there is one.
        pub fn kind(&self, name: &OsStr) -> io::Result<Option<Kind>> {
            match rustix::fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Ok(Some(match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Directory => Kind::Dir,
                    FileType::RegularFile => Kind::File,
                    _ => Kind::Other,
                })),
                Err(Errno::NOENT) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// Opens its entry `name` if, as it is opened, it is a directory
        /// itself, not a link to one.
        pub fn open_dir(&self, name: &OsStr) -> io::Result<Option<Self>> {
            match rustix::fs::openat(&self.0, name, OPEN | OFlags::NOFOLLOW, Mode::empty()) {
                Ok(fd) => Ok(Some(Self(fd))),
                // A link is `ELOOP`, or `EMLINK` on the BSDs; a file, `ENOTDIR`.
                Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP | Errno::MLINK) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// Removes its entry `name`, which isn't a directory: a link is
        /// removed itself. `false` if there was none.
        pub fn remove_file(&self, name: &OsStr) -> io::Result<bool> {
            match rustix::fs::unlinkat(&self.0, name, AtFlags::empty()) {
                Ok(()) => Ok(true),
                Err(Errno::NOENT) => Ok(false),
                Err(e) => Err(e.into()),
            }
        }

        /// Removes its entry `name`, and everything in it, if it is a
        /// directory itself: `false`, and nothing removed, if it isn't.
        pub fn remove_tree(&self, name: &OsStr) -> io::Result<bool> {
            let Some(dir) = self.open_dir(name)? else {
                return Ok(false);
            };
            dir.empty()?;
            drop(dir);
            match rustix::fs::unlinkat(&self.0, name, AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => Ok(true),
                Err(e) => Err(e.into()),
            }
        }

        /// Flushes it, so that the entries removed from it are removed on
        /// disk.
        pub fn sync(&self) -> io::Result<()> {
            Ok(rustix::fs::fsync(&self.0)?)
        }

        /// Removes everything in it.
        fn empty(&self) -> io::Result<()> {
            for name in self.names()? {
                let removed = match self.kind(&name)? {
                    Some(Kind::Dir) => self.remove_tree(&name)?,
                    _ => false,
                };
                // Not a directory, or no longer one: removed itself.
                if !removed {
                    self.remove_file(&name)?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    /// A directory, by its path.
    pub(in super::super) struct Dir(PathBuf);

    impl Dir {
        /// The directory at `path`, following links.
        pub fn open_root(path: &Path) -> io::Result<Self> {
            if !fs::metadata(path)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("not a directory: {}", path.display()),
                ));
            }
            Ok(Self(path.to_path_buf()))
        }

        /// The names of its entries.
        pub fn names(&self) -> io::Result<Vec<OsString>> {
            fs::read_dir(&self.0)?
                .map(|entry| Ok(entry?.file_name()))
                .collect()
        }

        /// What its entry `name` is, if there is one: a reparse point, a
        /// junction included, is neither a directory nor a file.
        pub fn kind(&self, name: &OsStr) -> io::Result<Option<Kind>> {
            let meta = match fs::symlink_metadata(self.0.join(name)) {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            Ok(Some(
                if is_reparse_point(&meta) || meta.file_type().is_symlink() {
                    Kind::Other
                } else if meta.is_dir() {
                    Kind::Dir
                } else if meta.is_file() {
                    Kind::File
                } else {
                    Kind::Other
                },
            ))
        }

        /// Its entry `name`, if, checked again just now, it is a directory
        /// itself.
        pub fn open_dir(&self, name: &OsStr) -> io::Result<Option<Self>> {
            Ok((self.kind(name)? == Some(Kind::Dir)).then(|| Self(self.0.join(name))))
        }

        /// Removes its entry `name`, which isn't a directory: a link is
        /// removed itself. `false` if there was none.
        ///
        /// A link to a directory, or a junction, is removed as a directory is
        /// (`RemoveDirectoryW`), which removes the link and never its target:
        /// a file's removal refuses it.
        pub fn remove_file(&self, name: &OsStr) -> io::Result<bool> {
            let path = self.0.join(name);
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e),
            };
            let removed = if is_directory_link(&meta) {
                fs::remove_dir(&path)
            } else {
                fs::remove_file(&path)
            };
            match removed {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            }
        }

        /// Flushes it, so that the entries removed from it are removed on
        /// disk. A directory opened for writing, as a handle with backup
        /// semantics, flushes with `FlushFileBuffers`.
        pub fn sync(&self) -> io::Result<()> {
            sync_dir(&self.0)
        }

        /// Removes its entry `name`, and everything in it, if, checked again
        /// just now, it is a directory itself: `false`, and nothing removed,
        /// if it isn't. The removal follows no links or reparse points.
        pub fn remove_tree(&self, name: &OsStr) -> io::Result<bool> {
            let Some(dir) = self.open_dir(name)? else {
                return Ok(false);
            };
            fs::remove_dir_all(&dir.0)?;
            Ok(true)
        }
    }

    #[cfg(windows)]
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    #[cfg(windows)]
    fn is_reparse_point(meta: &fs::Metadata) -> bool {
        use std::os::windows::fs::MetadataExt as _;

        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Whether it is a reparse point that is a directory, a link to one or a
    /// junction: not followed by `symlink_metadata`.
    #[cfg(windows)]
    fn is_directory_link(meta: &fs::Metadata) -> bool {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        let attributes = meta.file_attributes();
        attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    #[cfg(windows)]
    fn sync_dir(path: &Path) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?
            .sync_all()
    }

    #[cfg(not(windows))]
    fn is_reparse_point(_: &fs::Metadata) -> bool {
        false
    }

    #[cfg(not(windows))]
    fn is_directory_link(_: &fs::Metadata) -> bool {
        false
    }

    #[cfg(not(windows))]
    fn sync_dir(_: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no directory flush on this platform",
        ))
    }
}
