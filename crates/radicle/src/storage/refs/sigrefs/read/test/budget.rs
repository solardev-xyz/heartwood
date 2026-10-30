//! Security R-21: a remote's old-format `rad/sigrefs` history, which every
//! reader walks, is read within a [`Budget`] of commits and bytes.

use std::path::Path;

use crypto::signature::Signer as _;
use crypto::{SigningKey, signature::Keypair as _};
use radicle_core::RepoId;
use radicle_oid::Oid;

use crate::git;
use crate::storage::refs::sigrefs::git::object::{self, Writer as _};
use crate::storage::refs::sigrefs::read::{
    Budget, MAX_HISTORY_BYTES, MAX_HISTORY_COMMITS, SignedRefsReader, Tip, error,
};
use crate::storage::refs::{REFS_BLOB_PATH, Refs, SIGNATURE_BLOB_PATH};

use super::mock;
use super::mock::{AlwaysVerify, MockRepository};

/// An old-format chain of `len` commits in the mock, oldest first: refs with
/// neither `refs/rad/root` nor a parent entry, each signed apart.
fn mock_chain(len: u32) -> (MockRepository, Oid) {
    let mut repo = MockRepository::new();
    let mut parent = None;
    let oid = |i: u32| {
        let mut bytes = [0u8; 20];
        bytes[..4].copy_from_slice(&(i + 1).to_be_bytes());
        bytes[19] = 0xaa;
        Oid::from_sha1(bytes)
    };
    for i in 0..len {
        let commit = oid(i);
        repo = repo
            .with_commit(commit, mock::commit_data(parent))
            .with_refs(commit, [(mock::refs_heads_main(), oid(i + 1_000_000))])
            .with_blob(commit, &SIGNATURE_BLOB_PATH, {
                let mut sig = vec![0u8; 64];
                sig[..4].copy_from_slice(&i.to_be_bytes());
                sig
            });
        parent = Some(commit);
    }
    (repo, parent.expect("a chain of one or more"))
}

fn read_mock(
    repo: &MockRepository,
    head: Oid,
    budget: Budget,
) -> Result<crate::storage::refs::sigrefs::VerifiedCommit, error::Read> {
    SignedRefsReader::new(mock::rid(99), Tip::Commit(head), repo, &AlwaysVerify)
        .with_budget(budget)
        .read()
}

#[test]
fn the_default_budget_is_as_documented() {
    assert_eq!(
        Budget::default(),
        Budget {
            commits: 16_384,
            bytes: 512 * 1024 * 1024,
        }
    );
    assert_eq!(Budget::DEFAULT.commits, MAX_HISTORY_COMMITS);
    assert_eq!(Budget::DEFAULT.bytes, MAX_HISTORY_BYTES);
}

#[test]
// An old-format history within the budget reads as it always did: its head.
// One a commit longer than the budget takes is refused, counting the head
// and the walk: the head is read twice, once alone and once as the walk's
// first.
fn an_old_format_history_past_its_commit_budget_is_refused() {
    let (repo, head) = mock_chain(100);
    let within = Budget {
        commits: 101,
        bytes: u64::MAX,
    };
    assert_eq!(
        read_mock(&repo, head, within).unwrap().commit().oid(),
        &head
    );
    let past = Budget {
        commits: 100,
        ..within
    };
    let err = read_mock(&repo, head, past).unwrap_err();
    assert!(
        matches!(&err, error::Read::Exhausted(e) if e.what == "commits" && e.limit == 100),
        "{err}"
    );
}

#[test]
// The byte budget is spent on every commit, refs blob and signature read, to
// the byte: a budget of exactly what the read takes passes, and one byte
// less is refused.
fn the_byte_budget_is_spent_to_the_byte() {
    use crate::storage::refs::sigrefs::git::object::Reader as _;

    let (repo, head) = mock_chain(20);
    // The head alone, then the walk over all twenty, the head among them.
    let mut chain = Vec::new();
    let mut at = Some(head);
    while let Some(commit) = at {
        chain.push(commit);
        let bytes = repo.read_commit(&commit).unwrap().unwrap();
        at = radicle_git_metadata::commit::CommitData::<Oid, Oid>::from_bytes(&bytes)
            .unwrap()
            .parents()
            .next();
    }
    let size = |commit: &Oid| {
        let blob = |path: &str| {
            repo.read_blob(commit, Path::new(path))
                .unwrap()
                .unwrap()
                .bytes
                .len() as u64
        };
        repo.read_commit(commit).unwrap().unwrap().len() as u64
            + blob(REFS_BLOB_PATH)
            + blob(SIGNATURE_BLOB_PATH)
    };
    let total = size(&head) + chain.iter().map(size).sum::<u64>();
    let budget = |bytes| Budget {
        commits: usize::MAX,
        bytes,
    };
    assert!(read_mock(&repo, head, budget(total)).is_ok());
    let err = read_mock(&repo, head, budget(total - 1)).unwrap_err();
    assert!(
        matches!(&err, error::Read::Exhausted(e) if e.what == "bytes"),
        "{err}"
    );
}

#[test]
// The byte budget is spent on what is read, and refuses what would pass it.
fn an_old_format_history_past_its_byte_budget_is_refused() {
    let (repo, head) = mock_chain(100);
    let unlimited = Budget {
        commits: usize::MAX,
        bytes: u64::MAX,
    };
    assert!(read_mock(&repo, head, unlimited).is_ok());
    let err = read_mock(
        &repo,
        head,
        Budget {
            bytes: 4_096,
            ..unlimited
        },
    )
    .unwrap_err();
    assert!(
        matches!(&err, error::Read::Exhausted(e) if e.what == "bytes" && e.limit == 4_096),
        "{err}"
    );
}

#[test]
// Security R-21: a history longer than the default budget, of a remote that
// stays on the old format, is refused once the budget is spent, on a 256 KiB
// stack, rather than walked whole. One within it reads.
fn a_long_old_format_history_is_refused_within_the_default_budget() {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let (repo, head) = mock_chain(MAX_HISTORY_COMMITS as u32 + 1);
            let err = read_mock(&repo, head, Budget::DEFAULT).unwrap_err();
            assert!(
                matches!(&err, error::Read::Exhausted(e) if e.what == "commits"),
                "{err}"
            );
            let (repo, head) = mock_chain(MAX_HISTORY_COMMITS as u32 - 1);
            assert_eq!(
                read_mock(&repo, head, Budget::DEFAULT)
                    .unwrap()
                    .commit()
                    .oid(),
                &head
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A bare repository with an old-format chain signed by `signer`, oldest
/// first: refs naming `refs/heads/main` alone, and the `i`th commit's refs
/// blob padded to `pad(i)` bytes with ref names of its own, and its message
/// to `message(i)` bytes. Its head.
fn git_chain(
    repo: &git::raw::Repository,
    signer: &SigningKey,
    len: usize,
    pad: impl Fn(usize) -> usize,
    message: impl Fn(usize) -> usize,
) -> Oid {
    let author = git::raw::Signature::now("testy", "testy@example.com").unwrap();
    let mut parent: Option<git::raw::Oid> = None;
    for i in 0..len {
        let mut entries = vec![(
            git::fmt::refname!("refs/heads/main"),
            Oid::from_sha1([(i % 250) as u8 + 1; 20]),
        )];
        // Some 4 KiB a ref, enough of them to take `pad(i)` bytes.
        let filler = "x".repeat(4_000);
        let padding = pad(i).div_ceil(4_000);
        for n in 0..padding {
            entries.push((
                git::fmt::RefString::try_from(format!("refs/heads/pad-{i}-{n}-{filler}")).unwrap(),
                Oid::from_sha1([7; 20]),
            ));
        }
        let refs = Refs::from(entries.into_iter());
        let canonical = refs.canonical();
        let signature: crypto::Signature = signer.sign(&canonical);
        let tree = repo
            .write_tree(
                object::RefsEntry {
                    path: Path::new(REFS_BLOB_PATH).to_path_buf(),
                    content: canonical,
                },
                object::SignatureEntry {
                    path: Path::new(SIGNATURE_BLOB_PATH).to_path_buf(),
                    content: signature.to_vec(),
                },
            )
            .unwrap();
        let tree = repo.find_tree(tree.into()).unwrap();
        let parents = parent.map(|p| repo.find_commit(p).unwrap());
        let commit = repo
            .commit(
                None,
                &author,
                &author,
                &format!("sigrefs{}", "x".repeat(message(i))),
                &tree,
                &parents.iter().collect::<Vec<_>>(),
            )
            .unwrap();
        parent = Some(commit);
    }
    parent.expect("a chain of one or more").into()
}

/// A repository that records the largest object it handed over.
struct Recording<'a> {
    repo: &'a git::raw::Repository,
    largest: std::cell::Cell<usize>,
}

impl Recording<'_> {
    fn saw(&self, len: usize) {
        self.largest.set(self.largest.get().max(len));
    }
}

impl object::Reader for Recording<'_> {
    fn read_commit(&self, oid: &Oid) -> Result<Option<Vec<u8>>, object::error::ReadCommit> {
        let bytes = self.repo.read_commit(oid)?;
        self.saw(bytes.as_ref().map_or(0, Vec::len));
        Ok(bytes)
    }

    fn read_blob(
        &self,
        commit: &Oid,
        path: &Path,
    ) -> Result<Option<object::Blob>, object::error::ReadBlob> {
        let blob = self.repo.read_blob(commit, path)?;
        self.saw(blob.as_ref().map_or(0, |blob| blob.bytes.len()));
        Ok(blob)
    }

    fn read_commit_within(
        &self,
        oid: &Oid,
        limit: u64,
    ) -> Result<Option<Vec<u8>>, object::error::ReadCommit> {
        let bytes = self.repo.read_commit_within(oid, limit)?;
        self.saw(bytes.as_ref().map_or(0, Vec::len));
        Ok(bytes)
    }

    fn read_blob_within(
        &self,
        commit: &Oid,
        path: &Path,
        limit: u64,
    ) -> Result<Option<(object::Blob, u64)>, object::error::ReadBlob> {
        let blob = self.repo.read_blob_within(commit, path, limit)?;
        self.saw(blob.as_ref().map_or(0, |(blob, _)| blob.bytes.len()));
        Ok(blob)
    }
}

impl crate::storage::refs::sigrefs::git::reference::Reader for Recording<'_> {
    fn find_reference(
        &self,
        reference: &git::fmt::Namespaced,
    ) -> Result<Option<Oid>, crate::storage::refs::sigrefs::git::reference::error::FindReference>
    {
        crate::storage::refs::sigrefs::git::reference::Reader::find_reference(self.repo, reference)
    }
}

#[test]
// The Git repository measures each object before it reads it: a commit, or
// a refs blob, that would pass the byte budget is refused, never read, and
// the history before it is never read either. A history within the budget
// reads, verified.
fn a_git_history_is_measured_before_it_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = git::raw::Repository::init_bare(tmp.path()).unwrap();
    let signer = SigningKey::mock(21);
    let verifier = signer.verifying_key();
    let big = |at: usize| move |i: usize| if i == at { 64 * 1024 } else { 0 };
    // The third commit from the head has a refs blob of some 64 KiB, in one
    // history, and a message of 64 KiB, in another.
    for head in [
        git_chain(&repo, &signer, 8, big(5), |_| 0),
        git_chain(&repo, &signer, 8, |_| 0, big(5)),
    ] {
        let recording = Recording {
            repo: &repo,
            largest: std::cell::Cell::new(0),
        };
        let read = |budget: Budget| {
            recording.largest.set(0);
            SignedRefsReader::new(mock::rid(99), Tip::Commit(head), &recording, &verifier)
                .with_budget(budget)
                .read()
        };
        assert_eq!(read(Budget::DEFAULT).unwrap().commit().oid(), &head);
        assert!(recording.largest.get() > 64 * 1024);
        let err = read(Budget {
            commits: MAX_HISTORY_COMMITS,
            bytes: 32 * 1024,
        })
        .unwrap_err();
        assert!(
            matches!(&err, error::Read::Exhausted(e) if e.what == "bytes"),
            "{err}"
        );
        assert!(
            recording.largest.get() < 32 * 1024,
            "an object of {} bytes was read",
            recording.largest.get()
        );
    }
}

/// The process's peak resident memory, in KiB, from `/proc/self/status`.
#[cfg(target_os = "linux")]
fn peak_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// Resets the process's peak resident memory to what it holds now.
#[cfg(target_os = "linux")]
fn reset_peak() {
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
}

/// The environment variable that names the repository a child process
/// reads.
#[cfg(target_os = "linux")]
const CHILD_REPOSITORY: &str = "RAD_SIGREFS_BUDGET_CHILD_REPOSITORY";

#[cfg(target_os = "linux")]
#[test]
// Security R-21: the byte budget is spent before memory is. A refs blob of
// 64 MiB, past a budget of 8 MiB, is refused with less than 16 MiB
// more resident, on a 256 KiB stack; reading it within a larger budget, the
// control, takes more than its size. In a process of its own, so that its
// peak memory is its alone.
fn a_refs_blob_past_the_byte_budget_is_never_read_into_memory() {
    const NAME: &str = "storage::refs::sigrefs::read::test::budget::a_refs_blob_past_the_byte_budget_is_never_read_into_memory";
    const BIG: usize = 64 * 1024 * 1024;

    let Ok(path) = std::env::var(CHILD_REPOSITORY) else {
        // The parent: it writes the history, and has a child read it.
        let tmp = tempfile::tempdir().unwrap();
        let repo = git::raw::Repository::init_bare(tmp.path()).unwrap();
        let signer = SigningKey::mock(22);
        let head = git_chain(&repo, &signer, 3, |i| if i == 1 { BIG } else { 0 }, |_| 0);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([NAME, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD_REPOSITORY, tmp.path())
            .env("RAD_SIGREFS_BUDGET_CHILD_HEAD", head.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "the child failed: {status}");
        return;
    };
    let head: Oid = std::env::var("RAD_SIGREFS_BUDGET_CHILD_HEAD")
        .unwrap()
        .parse()
        .unwrap();
    let verifier = SigningKey::mock(22).verifying_key();
    let read = move |budget: Budget| {
        let path = path.clone();
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                // The storage's repository, as `SignedRefs::load` reads it.
                let rid = RepoId::from(Oid::from_sha1([99; 20]));
                let repo = crate::storage::git::Repository {
                    id: rid,
                    backend: git::raw::Repository::open_bare(&path).unwrap(),
                };
                reset_peak();
                let before = peak_kib();
                let result = SignedRefsReader::new(rid, Tip::Commit(head), &repo, &verifier)
                    .with_budget(budget)
                    .read()
                    .map(|_| ());
                (result, peak_kib().saturating_sub(before))
            })
            .unwrap()
            .join()
            .unwrap()
    };

    let (result, grew) = read(Budget {
        commits: MAX_HISTORY_COMMITS,
        bytes: 8 * 1024 * 1024,
    });
    assert!(
        matches!(&result, Err(error::Read::Exhausted(e)) if e.what == "bytes"),
        "{result:?}"
    );
    assert!(grew < 16 * 1024, "the refused read grew by {grew} KiB");
    eprintln!("The refused read's peak memory grew by {grew} KiB.");

    let (result, grew) = read(Budget::DEFAULT);
    assert!(result.is_ok(), "{result:?}");
    assert!(
        grew > (BIG / 1024) as u64,
        "the control read grew by only {grew} KiB"
    );
    eprintln!("The control read's peak memory grew by {grew} KiB.");
}
