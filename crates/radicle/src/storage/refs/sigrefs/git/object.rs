//! Traits for interacting with Git objects, necessary for implementing Radicle
//! Signed References.
// TODO(finto): I think these are more generally useful than just being used for
// Signed References. They might be worth moving into a crate,
// `radicle-git-traits`, but for now they can live here.

pub mod error;

use std::path::{Path, PathBuf};

use radicle_oid::Oid;

/// A Git blob object, returned by [`Reader::read_blob`].
pub struct Blob {
    /// The [`Oid`] of the Git blob.
    pub oid: Oid,
    /// The contents of the Git blob.
    pub bytes: Vec<u8>,
}

/// Git object reader, generally a Git repository, or its corresponding Object
/// Database (ODB).
pub trait Reader {
    /// Read the raw bytes of a commit object identified by `oid`.
    ///
    /// Returns `None` if no such object exists.
    ///
    /// # Errors
    ///
    /// - [`error::ReadCommit::IncorrectObject`]: the object identified by the
    ///   [`Oid`] was found, but was not a commit.
    /// - [`error::ReadCommit::Other`]: failed to read the Git commit.
    fn read_commit(&self, oid: &Oid) -> Result<Option<Vec<u8>>, error::ReadCommit>;

    /// Read the raw bytes of the blob at `path` within the tree of `commit`.
    ///
    /// Returns `None` if the path does not exist in that tree.
    ///
    /// # Errors
    ///
    /// - [`error::ReadBlob::CommitNotFound`]: failed to find the commit
    ///   identified by the [`Oid`].
    /// - [`error::ReadBlob::IncorrectObject`]: the object identified by the
    ///   [`Oid`] was found, but was not a commit.
    /// - [`error::ReadBlob::Other`]: failed to read the Git blob.
    fn read_blob(&self, commit: &Oid, path: &Path) -> Result<Option<Blob>, error::ReadBlob>;

    /// [`Reader::read_commit`], refusing a commit that takes more than
    /// `limit` bytes with [`error::ReadCommit::TooLarge`].
    ///
    /// A repository should measure the commit before it reads it, as the Git
    /// implementations do. This default reads it first, and is for readers
    /// that hold their objects in memory already.
    fn read_commit_within(
        &self,
        oid: &Oid,
        limit: u64,
    ) -> Result<Option<Vec<u8>>, error::ReadCommit> {
        let bytes = self.read_commit(oid)?;
        if let Some(bytes) = &bytes
            && bytes.len() as u64 > limit
        {
            return Err(error::ReadCommit::too_large(limit));
        }
        Ok(bytes)
    }

    /// [`Reader::read_blob`], within `limit` bytes for everything it reads to
    /// find the blob and the blob itself, refusing more with
    /// [`error::ReadBlob::TooLarge`]. It returns the blob, and how many bytes
    /// it read.
    ///
    /// A repository should measure each object before it reads it: the
    /// commit, each tree on the way to `path`, and the blob, as the Git
    /// implementations do. This default reads the blob first, counts it
    /// alone, and is for readers that hold their objects in memory already.
    fn read_blob_within(
        &self,
        commit: &Oid,
        path: &Path,
        limit: u64,
    ) -> Result<Option<(Blob, u64)>, error::ReadBlob> {
        let Some(blob) = self.read_blob(commit, path)? else {
            return Ok(None);
        };
        let size = blob.bytes.len() as u64;
        if size > limit {
            return Err(error::ReadBlob::too_large(limit));
        }
        Ok(Some((blob, size)))
    }
}

/// Input to the [`Writer::write_tree`] method.
///
/// The entry describes where in the Git tree to write the [`Refs`] content
/// blob.
///
/// [`Refs`]: crate::storage::refs::Refs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefsEntry {
    /// Path in the Git tree to write to.
    pub path: PathBuf,
    /// The contents of the Git blob.
    pub content: Vec<u8>,
}

/// Input to the [`Writer::write_tree`] method.
///
/// The entry describes where in the Git tree to write the signature content
/// blob.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignatureEntry {
    /// Path in the Git tree to write to.
    pub path: PathBuf,
    /// The contents of the Git blob.
    pub content: Vec<u8>,
}

/// Git object writer, generally a Git repository, or its corresponding Object
/// Database (ODB).
pub trait Writer {
    /// Write the [`RefsEntry`] and [`SignatureEntry`] to two separate Git blobs
    /// within a shared Git tree.
    ///
    /// Returns the [`Oid`] of the Git tree.
    ///
    /// # Errors
    ///
    /// - [`error::WriteTree::Refs`]: failed to write the references Git blob.
    /// - [`error::WriteTree::Signature`]: failed to write the signature Git blob.
    /// - [`error::WriteTree::Write`]: failed to write the Git tree.
    fn write_tree(
        &self,
        refs: RefsEntry,
        signature: SignatureEntry,
    ) -> Result<Oid, error::WriteTree>;

    /// Write the given Git commit, as bytes, to the Git object database.
    ///
    /// Returns the [`Oid`] of the Git commit.
    ///
    /// # Errors
    ///
    /// - [`error::WriteCommit`]: failed to write the Git commit.
    fn write_commit(&self, bytes: &[u8]) -> Result<Oid, error::WriteCommit>;
}
