//! In-process Git protocol v2 `upload-pack` (the *server* side of a fetch).
//!
//! When the `serve-in-process` feature is enabled, the worker answers an
//! incoming fetch here instead of spawning `git upload-pack`. This is what
//! lets embedded hosts that cannot spawn child processes (e.g. iOS) still
//! *serve* their refs to the network — the missing half of publishing from a
//! phone.
//!
//! We only implement the subset of Git protocol v2 that the `radicle-fetch`
//! client actually drives (see `radicle-fetch/src/transport`):
//!
//!   1. **capability advertisement** — the server speaks first in v2 daemon
//!      mode, right after the `git-upload-pack <path>` request line (already
//!      consumed by the worker).
//!   2. **`ls-refs`** — list the repository's references so the client can
//!      pick its wants.
//!   3. **`fetch`** — a *single round*: the client sends every `want`/`have`
//!      and terminates with `done`, so there is no iterative negotiation. We
//!      compute `closure(wants) − closure(haves)` and stream the packfile.
//!
//! Pack generation is done in-process by libgit2 (`git2::PackBuilder` +
//! `Revwalk`): pushing the wants and hiding the haves yields exactly the
//! objects reachable from the wants but not from the haves — including the
//! trees and blobs, and excluding anything the client already has. Only the
//! thin protocol framing is hand-written, using `gix-packetline`.

use std::collections::HashSet;
use std::io::{self, Read, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use git2::{ObjectType, Oid, Repository};
use sha1::{Digest, Sha1};
use gix_packetline::blocking_io::{StreamingPeekableIter, encode};
use gix_packetline::{Channel, PacketLineRef};

use radicle::Storage;
use radicle::identity::RepoId;
use radicle::node::events::{self, Emitter};
use radicle::node::{Event, NodeId};
use radicle::storage::git::paths;

use super::upload_pack::GitRequest;

/// The pkt-line delimiter that terminates a command block (the trailing
/// `0000` flush after a `command=…` request).
const DELIMITERS: &[PacketLineRef<'static>] = &[PacketLineRef::Flush];

/// Maximum pack payload per sideband packet. A pkt-line data payload is at
/// most 65516 bytes and the leading band byte takes one of them.
const MAX_BAND_DATA: usize = 65515;

/// Flush accumulated wire output once it grows past this size, so a large
/// pack is delivered in a handful of channel writes rather than one giant
/// allocation.
const WRITE_FLUSH_THRESHOLD: usize = 64 * 1024;

/// A parsed `command=…` request: its name plus every data line that followed
/// (both the capability lines and, after the `0001` delimiter, the argument
/// lines — we scan them uniformly).
struct Command {
    name: String,
    lines: Vec<Vec<u8>>,
}

/// Serve a single incoming fetch entirely in-process.
///
/// `header` is the already-parsed `git-upload-pack` request line; `recv`
/// carries the client's commands and `send` carries our responses (both are
/// the noise-tunneled worker channels). Returns once the client signals EOF.
pub fn upload_pack<R, W>(
    remote: NodeId,
    storage: &Storage,
    emitter: &Emitter<Event>,
    header: &GitRequest,
    mut recv: R,
    mut send: W,
) -> io::Result<()>
where
    R: Read,
    W: Write,
{
    let rid = header.repo;

    // Same constraint as the spawned path: only protocol v2 is supported.
    let version = header
        .extra
        .iter()
        .find_map(|(k, v)| (k == "version").then(|| v.as_deref()).flatten());
    if version != Some("2") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only Git protocol version 2 is supported",
        ));
    }

    let git_dir = paths::repository(storage, &rid);
    let repo = Repository::open_bare(&git_dir).map_err(git_err)?;

    // 1. Capability advertisement.
    let mut out = Vec::new();
    advertise_capabilities(&mut out)?;
    send.write_all(&out)?;
    send.flush()?;

    // 2. Command loop. The client interleaves ls-refs and fetch commands
    //    across its fetch stages over this one connection, then signals EOF.
    let mut iter = StreamingPeekableIter::new(&mut recv, DELIMITERS, false);
    loop {
        let Some(cmd) = read_command(&mut iter)? else {
            break;
        };
        match cmd.name.as_str() {
            "ls-refs" => {
                let mut out = Vec::new();
                handle_ls_refs(&repo, &cmd, &mut out)?;
                send.write_all(&out)?;
                send.flush()?;
            }
            "fetch" => {
                if let Err(e) = handle_fetch(&repo, &cmd, &mut send, rid, remote, emitter) {
                    emitter.emit(
                        events::UploadPack::Error {
                            rid,
                            remote,
                            err: e.to_string(),
                        }
                        .into(),
                    );
                    return Err(e);
                }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported upload-pack command: {other}"),
                ));
            }
        }
        iter.reset_with(DELIMITERS);
    }

    emitter.emit(
        events::UploadPack::Done {
            rid,
            remote,
            status: "in-process upload-pack: success".to_string(),
        }
        .into(),
    );
    Ok(())
}

/// Write the v2 capability advertisement: `version 2` first, then the
/// capabilities the `radicle-fetch` client relies on, terminated by a flush.
fn advertise_capabilities(out: &mut Vec<u8>) -> io::Result<()> {
    encode::text_to_write(b"version 2", &mut *out)?;
    // A fixed agent string — deliberately NOT `git --version`, which would
    // shell out and defeat the whole point on a no-spawn host.
    encode::text_to_write(b"agent=radicle-libradicle", &mut *out)?;
    encode::text_to_write(b"object-format=sha1", &mut *out)?;
    encode::text_to_write(b"ls-refs=unborn", &mut *out)?;
    encode::text_to_write(b"fetch=shallow wait-for-done", &mut *out)?;
    encode::flush_to_write(&mut *out)?;
    Ok(())
}

/// Read one `command=…` block, returning `Ok(None)` when the client has
/// signalled EOF (its out-of-band "done" control message surfaces as an
/// `UnexpectedEof` on the worker channel) or sent an empty block.
fn read_command<R: Read>(iter: &mut StreamingPeekableIter<R>) -> io::Result<Option<Command>> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    loop {
        match iter.read_line() {
            Some(Ok(Ok(PacketLineRef::Data(data)))) => lines.push(data.to_vec()),
            // Delimiter (`0001`) separates capabilities from arguments; we
            // scan all data lines uniformly, so nothing else to do.
            Some(Ok(Ok(_))) => {}
            Some(Ok(Err(e))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("pkt-line decode error: {e}"),
                ));
            }
            Some(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Some(Err(e)) => return Err(e),
            // `None` means we reached the flush that ends this command block
            // (or EOF); either way the block is complete.
            None => break,
        }
    }

    let Some(first) = lines.first() else {
        return Ok(None);
    };
    let name = std::str::from_utf8(first)
        .ok()
        .and_then(|s| s.trim().strip_prefix("command=").map(str::to_string))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "expected a `command=` pkt-line")
        })?;

    Ok(Some(Command { name, lines }))
}

/// Answer `ls-refs`: advertise every reference (the client re-filters, but we
/// honour `ref-prefix` as the spec's optimization), with optional `symrefs`
/// and `peel` annotations, terminated by a flush.
fn handle_ls_refs(repo: &Repository, cmd: &Command, out: &mut Vec<u8>) -> io::Result<()> {
    let mut want_symrefs = false;
    let mut want_peel = false;
    let mut prefixes: Vec<String> = Vec::new();
    for line in &cmd.lines {
        let s = String::from_utf8_lossy(line);
        let s = s.trim();
        if s == "symrefs" {
            want_symrefs = true;
        } else if s == "peel" {
            want_peel = true;
        } else if let Some(p) = s.strip_prefix("ref-prefix ") {
            prefixes.push(p.to_string());
        }
    }

    let refs = repo.references().map_err(git_err)?;
    for r in refs {
        let r = r.map_err(git_err)?;
        let name = match r.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue, // non-UTF-8 ref name
        };
        if !prefixes.is_empty() && !prefixes.iter().any(|p| name.starts_with(p)) {
            continue;
        }

        // Resolve to a direct object id (following symbolic refs like HEAD).
        let (oid, symref_target) = match r.target() {
            Some(oid) => (oid, None),
            None => {
                let resolved = r.resolve().map_err(git_err)?;
                match resolved.target() {
                    Some(oid) => {
                        let target = r.symbolic_target().ok().flatten().map(str::to_string);
                        (oid, target)
                    }
                    None => continue, // unborn symbolic ref — skip
                }
            }
        };

        let mut line = format!("{oid} {name}");
        if want_symrefs {
            if let Some(target) = symref_target {
                line.push_str(&format!(" symref-target:{target}"));
            }
        }
        if want_peel {
            if let Ok(obj) = repo.find_object(oid, None) {
                if obj.kind() == Some(git2::ObjectType::Tag) {
                    if let Ok(peeled) = obj.peel(git2::ObjectType::Commit) {
                        line.push_str(&format!(" peeled:{}", peeled.id()));
                    }
                }
            }
        }
        encode::text_to_write(line.as_bytes(), &mut *out)?;
    }
    encode::flush_to_write(&mut *out)?;
    Ok(())
}

/// Answer a single-round `fetch`: parse the wants/haves, build the packfile
/// with libgit2, and stream it over sideband channel 1 after the `packfile`
/// section header.
fn handle_fetch<W: Write>(
    repo: &Repository,
    cmd: &Command,
    send: &mut W,
    rid: RepoId,
    remote: NodeId,
    emitter: &Emitter<Event>,
) -> io::Result<()> {
    let mut wants: Vec<Oid> = Vec::new();
    let mut haves: Vec<Oid> = Vec::new();
    for line in &cmd.lines {
        let s = String::from_utf8_lossy(line);
        let s = s.trim();
        if let Some(oid) = s.strip_prefix("want ") {
            if let Ok(oid) = Oid::from_str(oid.trim()) {
                wants.push(oid);
            }
        } else if let Some(oid) = s.strip_prefix("have ") {
            if let Ok(oid) = Oid::from_str(oid.trim()) {
                haves.push(oid);
            }
        }
    }

    // Compute the object set: everything reachable from the wants, minus
    // everything reachable from the haves. Then serialise a self-contained,
    // non-delta packfile — libgit2's packbuilder only emits `REF_DELTA`,
    // which the fetch protocol reserves for thin packs (base on the
    // receiver's side), so a gix client rejects an in-pack REF_DELTA base.
    // Full objects sidestep the delta-format question entirely.
    let want_objs = reachable_objects(&repo, &wants).map_err(git_err)?;
    let have_objs = reachable_objects(&repo, &haves).map_err(git_err)?;
    let to_send: Vec<Oid> = want_objs.difference(&have_objs).copied().collect();
    let buf = write_packfile(&repo, &to_send).map_err(git_err)?;

    // Response: `packfile` section header, then the pack over sideband ch 1.
    let mut out = Vec::with_capacity(WRITE_FLUSH_THRESHOLD + 1024);
    encode::text_to_write(b"packfile", &mut out)?;

    let mut transmitted = 0usize;
    for chunk in buf.chunks(MAX_BAND_DATA) {
        encode::band_to_write(Channel::Data, chunk, &mut out)?;
        transmitted += chunk.len();
        if out.len() >= WRITE_FLUSH_THRESHOLD {
            send.write_all(&out)?;
            send.flush()?;
            out.clear();
            emitter.emit(events::UploadPack::pack_progress(rid, remote, transmitted).into());
        }
    }
    encode::flush_to_write(&mut out)?;
    send.write_all(&out)?;
    send.flush()?;
    emitter.emit(events::UploadPack::pack_progress(rid, remote, transmitted).into());

    Ok(())
}

/// The full set of object ids reachable from `tips`: every commit reachable
/// from a committish tip, each of their trees walked down to blobs, plus any
/// non-committish tip and its closure. Deduplicated, so shared subtrees are
/// walked once.
fn reachable_objects(repo: &Repository, tips: &[Oid]) -> Result<HashSet<Oid>, git2::Error> {
    let mut objs: HashSet<Oid> = HashSet::new();
    let odb = repo.odb()?;

    // Commits first, via a revwalk (so history is followed); anything that
    // isn't a committish tip is collected directly.
    let mut walk = repo.revwalk()?;
    let mut tree_roots: Vec<Oid> = Vec::new();
    for tip in tips {
        if !odb.exists(*tip) {
            continue; // a `have` we don't actually store — skip it
        }
        if walk.push(*tip).is_ok() {
            continue;
        }
        // Non-committish tip (tag / tree / blob): collect it on its own.
        collect_non_commit(repo, *tip, &mut objs, &mut tree_roots)?;
    }
    for oid in walk {
        let oid = oid?;
        if objs.insert(oid) {
            let commit = repo.find_commit(oid)?;
            tree_roots.push(commit.tree_id());
        }
    }
    for root in tree_roots {
        collect_tree(repo, root, &mut objs)?;
    }
    Ok(objs)
}

/// Collect a non-commit tip (annotated tag, or a directly-named tree/blob)
/// and queue any tree it introduces.
fn collect_non_commit(
    repo: &Repository,
    oid: Oid,
    objs: &mut HashSet<Oid>,
    tree_roots: &mut Vec<Oid>,
) -> Result<(), git2::Error> {
    let obj = repo.find_object(oid, None)?;
    match obj.kind() {
        Some(ObjectType::Tag) => {
            objs.insert(oid);
            if let Some(tag) = obj.as_tag() {
                let target = tag.target_id();
                // Recurse into the tag's target (usually a commit).
                if repo.find_commit(target).is_ok() {
                    if objs.insert(target) {
                        tree_roots.push(repo.find_commit(target)?.tree_id());
                    }
                } else {
                    collect_non_commit(repo, target, objs, tree_roots)?;
                }
            }
        }
        Some(ObjectType::Tree) => {
            tree_roots.push(oid);
        }
        _ => {
            objs.insert(oid); // a blob, or anything else addressable
        }
    }
    Ok(())
}

/// Recursively add a tree and everything under it (subtrees and blobs),
/// skipping trees already visited.
fn collect_tree(repo: &Repository, oid: Oid, objs: &mut HashSet<Oid>) -> Result<(), git2::Error> {
    if !objs.insert(oid) {
        return Ok(()); // already walked this subtree
    }
    let tree = repo.find_tree(oid)?;
    for entry in tree.iter() {
        match entry.kind() {
            Some(ObjectType::Tree) => collect_tree(repo, entry.id(), objs)?,
            Some(ObjectType::Blob) => {
                objs.insert(entry.id());
            }
            // Gitlink (submodule) commits are not stored here; skip them.
            _ => {}
        }
    }
    Ok(())
}

/// Serialise `oids` as a self-contained, non-delta packfile: the `PACK`
/// header, one deflated full object per id, and the trailing SHA-1 of
/// everything before it.
fn write_packfile(repo: &Repository, oids: &[Oid]) -> Result<Vec<u8>, git2::Error> {
    let odb = repo.odb()?;
    let mut pack: Vec<u8> = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes()); // version 2
    pack.extend_from_slice(&(oids.len() as u32).to_be_bytes());

    for oid in oids {
        let obj = odb.read(*oid)?;
        let kind = obj.kind();
        let data = obj.data();
        write_object_header(&mut pack, object_type_id(kind), data.len());
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(data)
            .and_then(|()| encoder.finish())
            .map(|compressed| pack.extend_from_slice(&compressed))
            .map_err(|e| git2::Error::from_str(&format!("deflate object {oid}: {e}")))?;
    }

    let mut hasher = Sha1::new();
    hasher.update(&pack);
    pack.extend_from_slice(&hasher.finalize());
    Ok(pack)
}

/// The packfile object-type number for a git object kind.
fn object_type_id(kind: ObjectType) -> u8 {
    match kind {
        ObjectType::Commit => 1,
        ObjectType::Tree => 2,
        ObjectType::Blob => 3,
        ObjectType::Tag => 4,
        ObjectType::Any => 0, // unreachable for stored objects
    }
}

/// Write a packfile entry header: the variable-length type-and-size encoding
/// that precedes each object's deflated data.
fn write_object_header(out: &mut Vec<u8>, obj_type: u8, mut size: usize) {
    let mut byte = (obj_type << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    while size > 0 {
        out.push(byte | 0x80);
        byte = (size & 0x7f) as u8;
        size >>= 7;
    }
    out.push(byte);
}

/// Map a libgit2 error into an `io::Error` so the whole module speaks one
/// error type.
fn git_err(e: git2::Error) -> io::Error {
    io::Error::other(format!("git: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> git2::Signature<'static> {
        git2::Signature::new("t", "t@e", &git2::Time::new(0, 0)).unwrap()
    }

    #[test]
    fn object_header_encodes_type_and_size() {
        // blob (type 3), size 2: single byte, high bit clear.
        let mut out = Vec::new();
        write_object_header(&mut out, 3, 2);
        assert_eq!(out, vec![0b0011_0010]);

        // commit (type 1), size 200 = 0b1100_1000:
        //   low nibble = 8 → first byte (1<<4)|8 = 0x18, continuation → 0x98
        //   remaining 200>>4 = 12 → 0x0c
        let mut out = Vec::new();
        write_object_header(&mut out, 1, 200);
        assert_eq!(out, vec![0x98, 0x0c]);
    }

    #[test]
    fn reachable_objects_collects_commit_tree_blob() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let blob = repo.blob(b"hello\n").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert("hello.txt", blob, 0o100644).unwrap();
        let tree = tb.write().unwrap();
        let commit = repo
            .commit(None, &sig(), &sig(), "m", &repo.find_tree(tree).unwrap(), &[])
            .unwrap();

        let objs = reachable_objects(&repo, &[commit]).unwrap();
        assert!(objs.contains(&commit));
        assert!(objs.contains(&tree));
        assert!(objs.contains(&blob));
        assert_eq!(objs.len(), 3);
    }

    #[test]
    fn haves_prune_the_object_set() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let b1 = repo.blob(b"a").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert("a", b1, 0o100644).unwrap();
        let t1 = tb.write().unwrap();
        let c1 = repo
            .commit(None, &sig(), &sig(), "c1", &repo.find_tree(t1).unwrap(), &[])
            .unwrap();
        let b2 = repo.blob(b"b").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert("a", b1, 0o100644).unwrap();
        tb.insert("b", b2, 0o100644).unwrap();
        let t2 = tb.write().unwrap();
        let c2 = repo
            .commit(
                None,
                &sig(),
                &sig(),
                "c2",
                &repo.find_tree(t2).unwrap(),
                &[&repo.find_commit(c1).unwrap()],
            )
            .unwrap();

        let want = reachable_objects(&repo, &[c2]).unwrap();
        let have = reachable_objects(&repo, &[c1]).unwrap();
        let to_send: HashSet<Oid> = want.difference(&have).copied().collect();
        // The new commit, its tree, and the new blob are sent…
        assert!(to_send.contains(&c2));
        assert!(to_send.contains(&t2));
        assert!(to_send.contains(&b2));
        // …while the shared/older objects the peer already has are pruned.
        assert!(!to_send.contains(&c1));
        assert!(!to_send.contains(&b1));
    }

    #[test]
    fn packfile_is_valid_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let blob = repo.blob(b"hello world\n").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert("f", blob, 0o100644).unwrap();
        let tree = tb.write().unwrap();
        let commit = repo
            .commit(None, &sig(), &sig(), "m", &repo.find_tree(tree).unwrap(), &[])
            .unwrap();

        let objs: Vec<Oid> = reachable_objects(&repo, &[commit])
            .unwrap()
            .into_iter()
            .collect();
        let pack = write_packfile(&repo, &objs).unwrap();
        assert_eq!(&pack[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(pack[8..12].try_into().unwrap()), 3);

        // Index the pack into a fresh repository: libgit2 accepts it only if
        // it is a valid, self-contained packfile, and every object lands.
        let dst_dir = tempfile::tempdir().unwrap();
        let dst = git2::Repository::init_bare(dst_dir.path()).unwrap();
        {
            let odb = dst.odb().unwrap();
            let mut writer = odb.packwriter().unwrap();
            writer.write_all(&pack).unwrap();
            writer.commit().unwrap();
        }
        let odb = dst.odb().unwrap();
        assert!(odb.exists(commit));
        assert!(odb.exists(tree));
        assert!(odb.exists(blob));
    }
}
