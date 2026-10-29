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
//! The object set is computed in-process with libgit2 (`Revwalk`, then each
//! commit's tree walked down to its blobs): everything reachable from the
//! wants but not from the haves. The packfile is written by hand, one full
//! object at a time, and the protocol framing with `gix-packetline`.
//!
//! What a peer can make it do is bounded:
//! - **its request:** at most [`MAX_COMMAND_LINES`] lines and
//!   [`MAX_COMMAND_BYTES`] bytes a command;
//! - **its wants:** each must be a tip of a ref `ls-refs` advertises, or a
//!   commit reachable from one, as `git upload-pack` allows in protocol v2.
//!   Anything else in the store isn't served;
//! - **the pack:** streamed as it is written, so that one object, and one
//!   write's worth of the wire, are held at once, and stopped once it passes
//!   the stream's pack size limit. An object that alone passes it is refused
//!   before it is read;
//! - **the walk:** iterative, so a deep tree or tag chain can't overflow the
//!   stack.

use std::collections::HashSet;
use std::io::{self, Read, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use git2::{ObjectType, Oid, Repository};
use gix_packetline::blocking_io::{StreamingPeekableIter, encode};
use gix_packetline::{Channel, PacketLineRef};
use sha1::{Digest, Sha1};

use radicle::Storage;
use radicle::identity::RepoId;
use radicle::node::config::FetchPackSizeLimit;
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

/// The most lines one command may hold: a want or a have each, and far more
/// than a fetch of any repository sends.
pub const MAX_COMMAND_LINES: usize = 1 << 17;

/// The most bytes one command's lines may hold together.
pub const MAX_COMMAND_BYTES: usize = 16 << 20;

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
/// the noise-tunneled worker channels). A pack stops at `limit`. Returns once
/// the client signals EOF.
pub fn upload_pack<R, W>(
    remote: NodeId,
    storage: &Storage,
    emitter: &Emitter<Event>,
    header: &GitRequest,
    mut recv: R,
    mut send: W,
    limit: FetchPackSizeLimit,
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
        .find_map(|(k, v)| (k == "version").then_some(v.as_deref()).flatten());
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
    while let Some(cmd) = read_command(&mut iter)? {
        match cmd.name.as_str() {
            "ls-refs" => {
                let mut out = Vec::new();
                handle_ls_refs(&repo, &cmd, &mut out)?;
                send.write_all(&out)?;
                send.flush()?;
            }
            "fetch" => {
                if let Err(e) = handle_fetch(&repo, &cmd, &mut send, rid, remote, emitter, limit) {
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
    let mut bytes = 0usize;
    loop {
        match iter.read_line() {
            Some(Ok(Ok(PacketLineRef::Data(data)))) => {
                bytes = bytes.saturating_add(data.len());
                if lines.len() >= MAX_COMMAND_LINES || bytes > MAX_COMMAND_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "command too large: more than {MAX_COMMAND_LINES} lines \
                             or {MAX_COMMAND_BYTES} bytes"
                        ),
                    ));
                }
                lines.push(data.to_vec());
            }
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
        if want_symrefs && let Some(target) = symref_target {
            line.push_str(&format!(" symref-target:{target}"));
        }
        if want_peel
            && let Ok(obj) = repo.find_object(oid, None)
            && obj.kind() == Some(git2::ObjectType::Tag)
            && let Ok(peeled) = obj.peel(git2::ObjectType::Commit)
        {
            line.push_str(&format!(" peeled:{}", peeled.id()));
        }
        encode::text_to_write(line.as_bytes(), &mut *out)?;
    }
    encode::flush_to_write(&mut *out)?;
    Ok(())
}

/// Answer a single-round `fetch`: parse the wants/haves, check that each want
/// is ours to serve, and stream the packfile over sideband channel 1 after
/// the `packfile` section header.
fn handle_fetch<W: Write>(
    repo: &Repository,
    cmd: &Command,
    send: &mut W,
    rid: RepoId,
    remote: NodeId,
    emitter: &Emitter<Event>,
    limit: FetchPackSizeLimit,
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
        } else if let Some(oid) = s.strip_prefix("have ")
            && let Ok(oid) = Oid::from_str(oid.trim())
        {
            haves.push(oid);
        }
    }
    if let Some(oid) = unadvertised(repo, &wants).map_err(git_err)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("not our ref: {oid}"),
        ));
    }

    // Compute the object set: everything reachable from the wants, minus
    // everything reachable from the haves. Then serialise a self-contained,
    // non-delta packfile — libgit2's packbuilder only emits `REF_DELTA`,
    // which the fetch protocol reserves for thin packs (base on the
    // receiver's side), so a gix client rejects an in-pack REF_DELTA base.
    // Full objects sidestep the delta-format question entirely.
    let want_objs = reachable_objects(repo, &wants).map_err(git_err)?;
    let have_objs = reachable_objects(repo, &haves).map_err(git_err)?;
    let to_send: Vec<Oid> = want_objs.difference(&have_objs).copied().collect();
    drop((want_objs, have_objs));

    // Response: `packfile` section header, then the pack over sideband ch 1,
    // written as it is made.
    let mut out = Vec::with_capacity(WRITE_FLUSH_THRESHOLD + MAX_BAND_DATA + 16);
    encode::text_to_write(b"packfile", &mut out)?;
    let mut progress =
        |sent| emitter.emit(events::UploadPack::pack_progress(rid, remote, sent).into());
    let mut band = Sideband::new(send, out, limit, &mut progress);
    write_packfile(repo, &to_send, &mut band)?;
    band.finish()
}

/// The refs `ls-refs` advertises, by their targets: each ref's object, a
/// symbolic ref's resolved one, and an annotated tag's peeled commit too.
fn advertised(repo: &Repository) -> Result<HashSet<Oid>, git2::Error> {
    let mut tips = HashSet::new();
    for r in repo.references()? {
        let r = r?;
        // `ls-refs` leaves out a name that isn't UTF-8.
        if r.name().is_err() {
            continue;
        }
        let oid = match r.target() {
            Some(oid) => oid,
            None => match r.resolve().ok().and_then(|resolved| resolved.target()) {
                Some(oid) => oid,
                None => continue,
            },
        };
        tips.insert(oid);
        if let Ok(peeled) = repo
            .find_object(oid, None)
            .and_then(|obj| obj.peel(ObjectType::Commit))
        {
            tips.insert(peeled.id());
        }
    }
    Ok(tips)
}

/// The first of `wants` that isn't ours to serve, if any: one that is neither
/// an advertised ref's tip ([`advertised`]) nor a commit reachable from one.
/// `git upload-pack` allows the same in protocol v2, where `ls-refs` and
/// `fetch` may come apart; nothing else in the store is served.
fn unadvertised(repo: &Repository, wants: &[Oid]) -> Result<Option<Oid>, git2::Error> {
    let tips = advertised(repo)?;
    let mut pending: HashSet<Oid> = wants
        .iter()
        .copied()
        .filter(|want| !tips.contains(want))
        .collect();
    if pending.is_empty() {
        return Ok(None);
    }
    // Only a commit can be reachable without being a tip here.
    if let Some(want) = pending
        .iter()
        .find(|want| repo.find_commit(**want).is_err())
    {
        return Ok(Some(*want));
    }
    let mut walk = repo.revwalk()?;
    for tip in &tips {
        if repo.find_commit(*tip).is_ok() {
            walk.push(*tip)?;
        }
    }
    for oid in walk {
        pending.remove(&oid?);
        if pending.is_empty() {
            return Ok(None);
        }
    }
    Ok(pending.into_iter().next())
}

/// The full set of object ids reachable from `tips`: every commit reachable
/// from a committish tip, each of their trees walked down to blobs, every
/// annotated tag on the way to a tip's target, and any tree or blob tip with
/// its closure. Deduplicated, so shared subtrees are walked once. The walk is
/// iterative: no tree or tag chain is too deep for it.
fn reachable_objects(repo: &Repository, tips: &[Oid]) -> Result<HashSet<Oid>, git2::Error> {
    let mut objs: HashSet<Oid> = HashSet::new();
    let odb = repo.odb()?;

    // Commits first, via a revwalk (so history is followed). A tag is
    // collected, and peeled, down to its target.
    let mut walk = repo.revwalk()?;
    let mut tree_roots: Vec<Oid> = Vec::new();
    for tip in tips {
        if !odb.exists(*tip) {
            continue; // a `have` we don't actually store — skip it
        }
        let mut oid = *tip;
        loop {
            let obj = repo.find_object(oid, None)?;
            match obj.kind() {
                Some(ObjectType::Tag) => {
                    if !objs.insert(oid) {
                        break; // its chain is collected already
                    }
                    match obj.as_tag() {
                        Some(tag) => oid = tag.target_id(),
                        None => break,
                    }
                }
                Some(ObjectType::Commit) => {
                    walk.push(oid)?;
                    break;
                }
                Some(ObjectType::Tree) => {
                    tree_roots.push(oid);
                    break;
                }
                _ => {
                    objs.insert(oid); // a blob, or anything else addressable
                    break;
                }
            }
        }
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

/// Add a tree and everything under it (subtrees and blobs), skipping trees
/// already visited, with a stack of its own rather than recursion.
fn collect_tree(repo: &Repository, root: Oid, objs: &mut HashSet<Oid>) -> Result<(), git2::Error> {
    let mut stack = vec![root];
    while let Some(oid) = stack.pop() {
        if !objs.insert(oid) {
            continue; // already walked this subtree
        }
        let tree = repo.find_tree(oid)?;
        for entry in tree.iter() {
            match entry.kind() {
                Some(ObjectType::Tree) => stack.push(entry.id()),
                Some(ObjectType::Blob) => {
                    objs.insert(entry.id());
                }
                // Gitlink (submodule) commits are not stored here; skip them.
                _ => {}
            }
        }
    }
    Ok(())
}

/// Write `oids` as a self-contained, non-delta packfile into `pack`: the
/// `PACK` header, one deflated full object per id, read one at a time, and
/// [`Sideband::finish`] adds the trailing SHA-1. An object that alone passes
/// the pack's limit is refused before it is read.
fn write_packfile<W: Write>(
    repo: &Repository,
    oids: &[Oid],
    pack: &mut Sideband<'_, W>,
) -> io::Result<()> {
    let odb = repo.odb().map_err(git_err)?;
    let count = u32::try_from(oids.len())
        .map_err(|_| io::Error::other(format!("too many objects for a pack: {}", oids.len())))?;
    pack.write_all(b"PACK")?;
    pack.write_all(&2u32.to_be_bytes())?; // version 2
    pack.write_all(&count.to_be_bytes())?;

    let mut header = Vec::with_capacity(16);
    for oid in oids {
        let (size, _) = odb.read_header(*oid).map_err(git_err)?;
        if pack.limit.exceeded_by(size) {
            return Err(pack.too_large());
        }
        let obj = odb.read(*oid).map_err(git_err)?;
        let data = obj.data();
        header.clear();
        write_object_header(&mut header, object_type_id(obj.kind()), data.len());
        pack.write_all(&header)?;
        let mut encoder = ZlibEncoder::new(&mut *pack, Compression::default());
        encoder.write_all(data)?;
        encoder.finish()?;
    }
    Ok(())
}

/// A packfile as it is written, over sideband channel 1: its bytes are hashed
/// and framed in pkt-lines of at most [`MAX_BAND_DATA`], and the pkt-lines
/// written to `send` once they pass [`WRITE_FLUSH_THRESHOLD`]. It holds no
/// more than that, and one pkt-line's data. It fails once the pack passes
/// `limit`.
struct Sideband<'a, W: Write> {
    send: &'a mut W,
    /// Pkt-lines not yet written.
    out: Vec<u8>,
    /// Pack bytes not yet framed: less than one pkt-line's data.
    pending: Vec<u8>,
    hasher: Sha1,
    /// Pack bytes so far.
    sent: usize,
    limit: FetchPackSizeLimit,
    progress: &'a mut dyn FnMut(usize),
}

impl<'a, W: Write> Sideband<'a, W> {
    /// A pack written after `out`, the wire output so far.
    fn new(
        send: &'a mut W,
        out: Vec<u8>,
        limit: FetchPackSizeLimit,
        progress: &'a mut dyn FnMut(usize),
    ) -> Self {
        Self {
            send,
            out,
            pending: Vec::with_capacity(MAX_BAND_DATA),
            hasher: Sha1::new(),
            sent: 0,
            limit,
            progress,
        }
    }

    fn too_large(&self) -> io::Error {
        io::Error::other(format!(
            "the pack passes the limit of {} for an upload",
            self.limit
        ))
    }

    /// Frames `bytes` of the pack, written or not, as pkt-lines.
    fn frame(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let room = MAX_BAND_DATA - self.pending.len();
            let (now, rest) = bytes.split_at(room.min(bytes.len()));
            self.pending.extend_from_slice(now);
            bytes = rest;
            if self.pending.len() == MAX_BAND_DATA {
                self.band()?;
            }
        }
        Ok(())
    }

    /// Frames the pending bytes as one pkt-line, and writes the pkt-lines
    /// once they pass the threshold.
    fn band(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        encode::band_to_write(Channel::Data, &self.pending, &mut self.out)?;
        self.pending.clear();
        if self.out.len() >= WRITE_FLUSH_THRESHOLD {
            self.send.write_all(&self.out)?;
            self.send.flush()?;
            self.out.clear();
            (self.progress)(self.sent);
        }
        Ok(())
    }

    /// Ends the pack with the SHA-1 of everything before it, and the
    /// response with a flush.
    fn finish(mut self) -> io::Result<()> {
        let digest = std::mem::take(&mut self.hasher).finalize();
        self.sent = self.sent.saturating_add(digest.len());
        if self.limit.exceeded_by(self.sent) {
            return Err(self.too_large());
        }
        self.frame(&digest)?;
        self.band()?;
        encode::flush_to_write(&mut self.out)?;
        self.send.write_all(&self.out)?;
        self.send.flush()?;
        (self.progress)(self.sent);
        Ok(())
    }
}

impl<W: Write> Write for Sideband<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sent = self.sent.saturating_add(buf.len());
        if self.limit.exceeded_by(self.sent) {
            return Err(self.too_large());
        }
        self.hasher.update(buf);
        self.frame(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
            .commit(
                None,
                &sig(),
                &sig(),
                "m",
                &repo.find_tree(tree).unwrap(),
                &[],
            )
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
            .commit(
                None,
                &sig(),
                &sig(),
                "c1",
                &repo.find_tree(t1).unwrap(),
                &[],
            )
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

    /// A commit with `files` blobs of `size` bytes each, hard to compress.
    fn commit_with(repo: &Repository, files: usize, size: usize) -> Oid {
        let mut tb = repo.treebuilder(None).unwrap();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for i in 0..files {
            let data: Vec<u8> = (0..size)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let blob = repo.blob(&data).unwrap();
            tb.insert(format!("f{i}"), blob, 0o100644).unwrap();
        }
        let tree = tb.write().unwrap();
        repo.commit(
            None,
            &sig(),
            &sig(),
            "m",
            &repo.find_tree(tree).unwrap(),
            &[],
        )
        .unwrap()
    }

    /// Every write to it, as it came.
    #[derive(Default)]
    struct Sink {
        writes: Vec<Vec<u8>>,
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The pack of `oids` as [`Sideband`] streams it with `limit`: the
    /// writes it made, and how it ended.
    fn stream(
        repo: &Repository,
        oids: &[Oid],
        limit: FetchPackSizeLimit,
    ) -> (Sink, io::Result<()>) {
        let mut sink = Sink::default();
        let mut progress = |_| {};
        let result = {
            let mut band = Sideband::new(&mut sink, Vec::new(), limit, &mut progress);
            write_packfile(repo, oids, &mut band).and_then(|()| band.finish())
        };
        (sink, result)
    }

    /// The pack bytes of channel 1 in `wire`, its pkt-lines demultiplexed.
    fn demux(wire: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            let len =
                usize::from_str_radix(std::str::from_utf8(&wire[at..at + 4]).unwrap(), 16).unwrap();
            if len == 0 {
                at += 4;
                continue;
            }
            assert_eq!(wire[at + 4], 1, "not channel 1");
            pack.extend_from_slice(&wire[at + 5..at + len]);
            at += len;
        }
        pack
    }

    /// Indexes `pack` into a new repository: libgit2 accepts it only if it is
    /// a valid, self-contained packfile.
    fn index(pack: &[u8]) -> (tempfile::TempDir, Repository) {
        let dir = tempfile::tempdir().unwrap();
        let dst = git2::Repository::init_bare(dir.path()).unwrap();
        {
            let odb = dst.odb().unwrap();
            let mut writer = odb.packwriter().unwrap();
            writer.write_all(pack).unwrap();
            writer.commit().unwrap();
        }
        (dir, dst)
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
            .commit(
                None,
                &sig(),
                &sig(),
                "m",
                &repo.find_tree(tree).unwrap(),
                &[],
            )
            .unwrap();

        let objs: Vec<Oid> = reachable_objects(&repo, &[commit])
            .unwrap()
            .into_iter()
            .collect();
        let (sink, result) = stream(&repo, &objs, FetchPackSizeLimit::default());
        result.unwrap();
        let pack = demux(&sink.writes.concat());
        assert_eq!(&pack[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(pack[8..12].try_into().unwrap()), 3);

        let (_dir, dst) = index(&pack);
        let odb = dst.odb().unwrap();
        assert!(odb.exists(commit));
        assert!(odb.exists(tree));
        assert!(odb.exists(blob));
    }

    // Security R-10: the pack is written to the wire as it is made, in writes
    // of a bounded size, not built whole first.
    #[test]
    fn a_pack_is_streamed_in_bounded_writes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let commit = commit_with(&repo, 128, 16 * 1024);
        let objs: Vec<Oid> = reachable_objects(&repo, &[commit])
            .unwrap()
            .into_iter()
            .collect();
        let (sink, result) = stream(&repo, &objs, FetchPackSizeLimit::default());
        result.unwrap();
        let total: usize = sink.writes.iter().map(Vec::len).sum();
        assert!(total > 1 << 20, "{total}");
        assert!(sink.writes.len() > 8, "{} writes", sink.writes.len());
        let largest = sink.writes.iter().map(Vec::len).max().unwrap();
        assert!(
            largest <= WRITE_FLUSH_THRESHOLD + MAX_BAND_DATA + 5,
            "a write of {largest} bytes"
        );
        let pack = demux(&sink.writes.concat());
        let (_dir, dst) = index(&pack);
        assert!(dst.odb().unwrap().exists(commit));
    }

    // Security R-10: a pack stops at the stream's limit, and an object that
    // alone passes it is refused.
    #[test]
    fn a_pack_stops_at_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let commit = commit_with(&repo, 32, 16 * 1024);
        let objs: Vec<Oid> = reachable_objects(&repo, &[commit])
            .unwrap()
            .into_iter()
            .collect();
        let limit = FetchPackSizeLimit::kibibytes(128);
        let (sink, result) = stream(&repo, &objs, limit);
        assert!(
            result.is_err(),
            "a pack of 512 KiB passed a limit of 128 KiB"
        );
        let total: usize = sink.writes.iter().map(Vec::len).sum();
        assert!(total <= 128 * 1024 + 64, "{total} bytes written");

        let big = repo.blob(&vec![7u8; 256 * 1024]).unwrap();
        let (sink, result) = stream(&repo, &[big], limit);
        assert!(result.is_err());
        assert!(sink.writes.is_empty());
    }

    // Security R-10: a want must be an advertised ref's tip, or a commit
    // reachable from one. Nothing else in the store is served.
    #[test]
    fn only_advertised_refs_and_their_history_are_wantable() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let blob = repo.blob(b"a").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert("a", blob, 0o100644).unwrap();
        let tree = repo.find_tree(tb.write().unwrap()).unwrap();
        let c0 = repo.commit(None, &sig(), &sig(), "c0", &tree, &[]).unwrap();
        let c0c = repo.find_commit(c0).unwrap();
        let c1 = repo
            .commit(None, &sig(), &sig(), "c1", &tree, &[&c0c])
            .unwrap();
        let c1c = repo.find_commit(c1).unwrap();
        let c2 = repo
            .commit(
                Some("refs/heads/main"),
                &sig(),
                &sig(),
                "c2",
                &tree,
                &[&c1c],
            )
            .unwrap();
        // A commit no ref reaches.
        let loose = repo
            .commit(None, &sig(), &sig(), "loose", &tree, &[])
            .unwrap();
        // An annotated tag, under a ref.
        let tag = repo
            .tag(
                "v1",
                &repo.find_object(c1, None).unwrap(),
                &sig(),
                "v1",
                false,
            )
            .unwrap();

        // Tips, and a commit in their history that is none.
        assert_eq!(unadvertised(&repo, &[c2, c1, tag, c0]).unwrap(), None);
        assert_eq!(unadvertised(&repo, &[c2, loose]).unwrap(), Some(loose));
        assert_eq!(unadvertised(&repo, &[blob]).unwrap(), Some(blob));
        assert_eq!(unadvertised(&repo, &[tree.id()]).unwrap(), Some(tree.id()));

        // A fetch that wants one is refused, with nothing sent.
        let fetch = |want: Oid| {
            let cmd = Command {
                name: "fetch".to_owned(),
                lines: vec![
                    b"command=fetch".to_vec(),
                    format!("want {c2}").into_bytes(),
                    format!("want {want}").into_bytes(),
                    b"done".to_vec(),
                ],
            };
            let mut sink = Sink::default();
            let result = handle_fetch(
                &repo,
                &cmd,
                &mut sink,
                radicle::test::arbitrary::r#gen(1),
                radicle::test::arbitrary::r#gen(1),
                &Emitter::default(),
                FetchPackSizeLimit::default(),
            );
            (result, sink.writes.concat())
        };
        let (result, sent) = fetch(loose);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(io::ErrorKind::PermissionDenied)
        );
        assert!(sent.is_empty());
        let (result, sent) = fetch(c0);
        result.unwrap();
        // After the `packfile` section header.
        let header = usize::from_str_radix(std::str::from_utf8(&sent[..4]).unwrap(), 16).unwrap();
        assert_eq!(&sent[4..header], b"packfile\n");
        let pack = demux(&sent[header..]);
        let (_dir, dst) = index(&pack);
        assert!(dst.odb().unwrap().exists(c0));
    }

    // An annotated tag wanted brings the tag itself, with its commit's closure.
    #[test]
    fn an_annotated_tag_brings_itself() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let commit = commit_with(&repo, 1, 8);
        let tag = repo
            .tag(
                "v1",
                &repo.find_object(commit, None).unwrap(),
                &sig(),
                "v1",
                false,
            )
            .unwrap();
        let objs = reachable_objects(&repo, &[tag]).unwrap();
        assert!(objs.contains(&tag));
        assert!(objs.contains(&commit));
        assert_eq!(objs.len(), 4);
    }

    // Security R-10: the tree walk keeps a stack of its own, so a deep tree
    // can't overflow the thread's.
    #[test]
    fn a_deep_tree_is_walked_without_recursion() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let mut tree = {
            let mut tb = repo.treebuilder(None).unwrap();
            tb.insert("f", repo.blob(b"x").unwrap(), 0o100644).unwrap();
            tb.write().unwrap()
        };
        const DEPTH: usize = 4_000;
        for _ in 0..DEPTH {
            let mut tb = repo.treebuilder(None).unwrap();
            tb.insert("d", tree, 0o040000).unwrap();
            tree = tb.write().unwrap();
        }
        let commit = repo
            .commit(
                None,
                &sig(),
                &sig(),
                "m",
                &repo.find_tree(tree).unwrap(),
                &[],
            )
            .unwrap();
        let path = dir.path().to_path_buf();
        // A small stack, as a worker's could be.
        let objs = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let repo = git2::Repository::open_bare(path).unwrap();
                reachable_objects(&repo, &[commit]).unwrap().len()
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(objs, DEPTH + 3);
    }

    // Security R-10: a command's lines are bounded, in number and in bytes.
    #[test]
    fn a_command_too_large_is_refused() {
        let command = |lines: usize, size: usize| {
            let mut wire = Vec::new();
            encode::text_to_write(b"command=fetch", &mut wire).unwrap();
            let line = vec![b'x'; size];
            for _ in 0..lines {
                encode::data_to_write(&line, &mut wire).unwrap();
            }
            encode::flush_to_write(&mut wire).unwrap();
            let mut recv = wire.as_slice();
            let mut iter = StreamingPeekableIter::new(&mut recv, DELIMITERS, false);
            read_command(&mut iter).map(|cmd| cmd.map(|cmd| cmd.lines.len()))
        };
        assert_eq!(command(1_000, 48).unwrap(), Some(1_001));
        assert!(command(MAX_COMMAND_LINES, 8).is_err());
        assert!(command(MAX_COMMAND_BYTES / 60_000 + 1, 60_000).is_err());
    }
}
