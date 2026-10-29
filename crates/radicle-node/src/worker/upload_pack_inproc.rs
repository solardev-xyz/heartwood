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

/// The most objects one command may walk: refs advertised, commits walked,
/// and the trees, blobs and tags visited, for its wants and haves together.
/// A command that needs more is refused. So what one upload holds is bounded
/// whatever the repository's size.
pub const MAX_WALK: usize = 1 << 20;

/// How long one command's walk may take.
const WALK_TIME: std::time::Duration = std::time::Duration::from_secs(120);

/// The largest commit, tree or tag body a walk reads. The pack's own limit
/// applies too: it reads none past the smaller.
pub const MAX_METADATA_OBJECT: usize = 32 << 20;

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
            "ls-refs" => handle_ls_refs(&repo, &cmd, &mut send)?,
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
/// and `peel` annotations, terminated by a flush. The advertisement is
/// written as it is made, a write's worth at a time, whatever the number of
/// refs.
fn handle_ls_refs<W: Write>(repo: &Repository, cmd: &Command, send: &mut W) -> io::Result<()> {
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

    let walk = Walk::new(repo, MAX_WALK, MAX_METADATA_OBJECT)?;
    let mut out = Vec::with_capacity(WRITE_FLUSH_THRESHOLD + 1024);
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
        if want_peel && let Some(peeled) = walk.peeled(oid)? {
            line.push_str(&format!(" peeled:{peeled}"));
        }
        encode::text_to_write(line.as_bytes(), &mut out)?;
        if out.len() >= WRITE_FLUSH_THRESHOLD {
            send.write_all(&out)?;
            send.flush()?;
            out.clear();
        }
    }
    encode::flush_to_write(&mut out)?;
    send.write_all(&out)?;
    send.flush()?;
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
    // One walk for the whole command: its checks and its objects share one
    // allowance, and read no body past the pack's limit.
    let mut walk = Walk::new(repo, MAX_WALK, allowance(limit))?;
    if let Some(oid) = unadvertised(&mut walk, &wants)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("not our ref: {oid}"),
        ));
    }

    // Compute the object set: everything reachable from the wants that the
    // client doesn't have. Then serialise a self-contained, non-delta
    // packfile — libgit2's packbuilder only emits `REF_DELTA`, which the
    // fetch protocol reserves for thin packs (base on the receiver's side),
    // so a gix client rejects an in-pack REF_DELTA base. Full objects
    // sidestep the delta-format question entirely.
    let to_send = objects_to_send(&mut walk, &wants, &haves)?;

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

/// The largest body a walk for a pack of `limit` reads.
fn allowance(limit: FetchPackSizeLimit) -> usize {
    usize::try_from(limit.as_u64())
        .unwrap_or(usize::MAX)
        .min(MAX_METADATA_OBJECT)
}

/// What one command may walk, and read: `left` more objects, until its
/// deadline; and no body larger than its `allowance`. Kinds and sizes come
/// from the store's headers, without reading the body.
struct Walk<'r> {
    repo: &'r Repository,
    odb: git2::Odb<'r>,
    left: usize,
    deadline: std::time::Instant,
    allowance: usize,
}

impl<'r> Walk<'r> {
    fn new(repo: &'r Repository, budget: usize, allowance: usize) -> io::Result<Self> {
        Ok(Self {
            repo,
            odb: repo.odb().map_err(git_err)?,
            left: budget,
            deadline: std::time::Instant::now() + WALK_TIME,
            allowance,
        })
    }

    /// Takes one more object of the walk's allowance.
    fn step(&mut self) -> io::Result<()> {
        if self.left == 0 {
            return Err(io::Error::other(format!(
                "the command needs more than {MAX_WALK} objects walked"
            )));
        }
        self.left -= 1;
        if self.left.is_multiple_of(1024) && std::time::Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the command's walk took too long",
            ));
        }
        Ok(())
    }

    /// The kind of `oid`, from its header, without reading it: `None` if the
    /// store hasn't it.
    fn kind(&self, oid: Oid) -> io::Result<Option<ObjectType>> {
        match self.odb.read_header(oid) {
            Ok((_, kind)) => Ok(Some(kind)),
            Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
            Err(e) => Err(git_err(e)),
        }
    }

    /// Checks, from its header, that the body of `oid` may be read.
    fn readable(&self, oid: Oid) -> io::Result<()> {
        let (size, _) = self.odb.read_header(oid).map_err(git_err)?;
        if size > self.allowance {
            return Err(io::Error::other(format!(
                "the object {oid} is too large to read: {size} bytes"
            )));
        }
        #[cfg(test)]
        tests::READ.with(|read| read.set(read.get() + size));
        Ok(())
    }

    fn commit(&self, oid: Oid) -> io::Result<git2::Commit<'r>> {
        self.readable(oid)?;
        self.repo.find_commit(oid).map_err(git_err)
    }

    fn tree(&self, oid: Oid) -> io::Result<git2::Tree<'r>> {
        self.readable(oid)?;
        self.repo.find_tree(oid).map_err(git_err)
    }

    /// The target of the annotated tag `oid`.
    fn tag_target(&self, oid: Oid) -> io::Result<Oid> {
        self.readable(oid)?;
        let tag = self.repo.find_tag(oid).map_err(git_err)?;
        Ok(tag.target_id())
    }

    /// The commit an annotated tag `oid` peels to, if it is one and does.
    fn peeled(&self, mut oid: Oid) -> io::Result<Option<Oid>> {
        if self.kind(oid)? != Some(ObjectType::Tag) {
            return Ok(None);
        }
        // A chain of tags, followed in a loop: no deeper than the walk's
        // allowance, each a body read.
        for _ in 0..MAX_WALK {
            match self.kind(oid)? {
                Some(ObjectType::Tag) => oid = self.tag_target(oid)?,
                Some(ObjectType::Commit) => return Ok(Some(oid)),
                _ => return Ok(None),
            }
        }
        Ok(None)
    }
}

/// The refs `ls-refs` advertises, by their targets: each ref's object, a
/// symbolic ref's resolved one, and an annotated tag's peeled commit too.
fn advertised(walk: &mut Walk) -> io::Result<HashSet<Oid>> {
    let mut tips = HashSet::new();
    for r in walk.repo.references().map_err(git_err)? {
        let r = r.map_err(git_err)?;
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
        walk.step()?;
        tips.insert(oid);
        if let Some(peeled) = walk.peeled(oid)? {
            tips.insert(peeled);
        }
    }
    Ok(tips)
}

/// The first of `wants` that isn't ours to serve, if any: one that is neither
/// an advertised ref's tip ([`advertised`]) nor a commit reachable from one.
/// `git upload-pack` allows the same in protocol v2, where `ls-refs` and
/// `fetch` may come apart; nothing else in the store is served. Kinds come
/// from headers: no want's body is read to refuse it.
fn unadvertised(walk: &mut Walk, wants: &[Oid]) -> io::Result<Option<Oid>> {
    let tips = advertised(walk)?;
    let mut pending: HashSet<Oid> = wants
        .iter()
        .copied()
        .filter(|want| !tips.contains(want))
        .collect();
    if pending.is_empty() {
        return Ok(None);
    }
    // Only a commit can be reachable without being a tip here.
    for want in &pending {
        if walk.kind(*want)? != Some(ObjectType::Commit) {
            return Ok(Some(*want));
        }
    }
    let mut revwalk = walk.repo.revwalk().map_err(git_err)?;
    for tip in &tips {
        if walk.kind(*tip)? == Some(ObjectType::Commit) {
            revwalk.push(*tip).map_err(git_err)?;
        }
    }
    for oid in revwalk {
        walk.step()?;
        pending.remove(&oid.map_err(git_err)?);
        if pending.is_empty() {
            return Ok(None);
        }
    }
    Ok(pending.into_iter().next())
}

/// The objects to send for `wants`, to a client that has `haves`: every
/// commit reachable from a want but not from a have, the annotated tags on
/// the way to a want's target, and the trees and blobs under them, less those
/// the client has.
///
/// The client's objects are those under the trees of the commits it has at
/// the edge of what is sent (the haves that are parents of sent commits), as
/// `git pack-objects` reckons them, and any tree or blob it names as a have.
/// So the walk takes a snapshot of the edge, not the client's whole history.
/// A blob is never read; every body read is checked against the walk's
/// allowance first, and every object visited counts against its budget. The
/// walk is iterative: no tree or tag chain is too deep for it.
fn objects_to_send(walk: &mut Walk, wants: &[Oid], haves: &[Oid]) -> io::Result<Vec<Oid>> {
    // The client's: commits hidden from the revwalk, and other objects it
    // names.
    let mut revwalk = walk.repo.revwalk().map_err(git_err)?;
    let mut theirs: HashSet<Oid> = HashSet::new();
    for have in haves {
        match walk.kind(*have)? {
            Some(ObjectType::Commit) => revwalk.hide(*have).map_err(git_err)?,
            Some(_) => {
                walk.step()?;
                theirs.insert(*have);
            }
            // A `have` we don't actually store — skip it.
            None => {}
        }
    }

    // The wants: a tag is collected, and peeled, down to its target.
    let mut sent: HashSet<Oid> = HashSet::new();
    let mut order: Vec<Oid> = Vec::new();
    let mut roots: Vec<Oid> = Vec::new();
    for want in wants {
        let mut oid = *want;
        loop {
            match walk.kind(oid)? {
                Some(ObjectType::Tag) => {
                    if !sent.insert(oid) {
                        break; // its chain is collected already
                    }
                    walk.step()?;
                    order.push(oid);
                    oid = walk.tag_target(oid)?;
                }
                Some(ObjectType::Commit) => {
                    revwalk.push(oid).map_err(git_err)?;
                    break;
                }
                Some(ObjectType::Tree) => {
                    roots.push(oid);
                    break;
                }
                Some(_) => {
                    if !theirs.contains(&oid) && sent.insert(oid) {
                        walk.step()?;
                        order.push(oid);
                    }
                    break;
                }
                None => {
                    return Err(io::Error::other(format!("no object {oid} to send")));
                }
            }
        }
    }

    // The commits to send, then the edge: their parents the client has.
    let mut commits: Vec<Oid> = Vec::new();
    for oid in revwalk {
        let oid = oid.map_err(git_err)?;
        walk.step()?;
        if sent.insert(oid) {
            order.push(oid);
            commits.push(oid);
        }
    }
    let mut edge: Vec<Oid> = Vec::new();
    for commit in &commits {
        let commit = walk.commit(*commit)?;
        roots.push(commit.tree_id());
        for parent in commit.parent_ids() {
            if !sent.contains(&parent) {
                edge.push(parent);
            }
        }
    }
    // What the client has under the edge's trees.
    for parent in edge {
        if walk.kind(parent)? != Some(ObjectType::Commit) {
            continue;
        }
        let tree = walk.commit(parent)?.tree_id();
        collect_tree(walk, tree, &mut theirs, &HashSet::new(), None)?;
    }
    // What is sent under the commits' trees, and the wanted trees.
    for root in roots {
        collect_tree(walk, root, &mut sent, &theirs, Some(&mut order))?;
    }
    Ok(order)
}

/// Adds the tree `root` and everything under it (subtrees and blobs) to
/// `seen`, and to `order` if given, but for what `skip` holds and `seen` has
/// already.
/// It keeps a stack of its own, rather than recursion; every object counts
/// against the walk's budget, and no blob is read.
fn collect_tree(
    walk: &mut Walk,
    root: Oid,
    seen: &mut HashSet<Oid>,
    skip: &HashSet<Oid>,
    mut order: Option<&mut Vec<Oid>>,
) -> io::Result<()> {
    let mut stack = vec![root];
    while let Some(oid) = stack.pop() {
        if skip.contains(&oid) || !seen.insert(oid) {
            continue; // the client's, or already walked
        }
        walk.step()?;
        if let Some(order) = order.as_mut() {
            order.push(oid);
        }
        let tree = walk.tree(oid)?;
        for entry in tree.iter() {
            match entry.kind() {
                Some(ObjectType::Tree) => stack.push(entry.id()),
                Some(ObjectType::Blob) => {
                    let blob = entry.id();
                    if !skip.contains(&blob) && seen.insert(blob) {
                        walk.step()?;
                        if let Some(order) = order.as_mut() {
                            order.push(blob);
                        }
                    }
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
    use std::cell::Cell;

    use super::*;

    thread_local! {
        /// The bytes of the bodies walks chose to read on this thread.
        pub(super) static READ: Cell<usize> = const { Cell::new(0) };
    }

    /// The objects `objects_to_send` gives, with the usual budget.
    fn to_send(repo: &Repository, wants: &[Oid], haves: &[Oid]) -> HashSet<Oid> {
        let mut walk = Walk::new(repo, MAX_WALK, MAX_METADATA_OBJECT).unwrap();
        objects_to_send(&mut walk, wants, haves)
            .unwrap()
            .into_iter()
            .collect()
    }

    fn unadvertised_of(repo: &Repository, wants: &[Oid]) -> Option<Oid> {
        let mut walk = Walk::new(repo, MAX_WALK, MAX_METADATA_OBJECT).unwrap();
        unadvertised(&mut walk, wants).unwrap()
    }

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

        let objs = to_send(&repo, &[commit], &[]);
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

        let to_send = to_send(&repo, &[c2], &[c1]);
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

        let objs: Vec<Oid> = to_send(&repo, &[commit], &[]).into_iter().collect();
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
        let objs: Vec<Oid> = to_send(&repo, &[commit], &[]).into_iter().collect();
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
        let objs: Vec<Oid> = to_send(&repo, &[commit], &[]).into_iter().collect();
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
        assert_eq!(unadvertised_of(&repo, &[c2, c1, tag, c0]), None);
        assert_eq!(unadvertised_of(&repo, &[c2, loose]), Some(loose));
        assert_eq!(unadvertised_of(&repo, &[blob]), Some(blob));
        assert_eq!(unadvertised_of(&repo, &[tree.id()]), Some(tree.id()));

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
        let objs = to_send(&repo, &[tag], &[]);
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
                to_send(&repo, &[commit], &[]).len()
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

    // Review of heartwood #11, round 1: a walk stops at its budget, before
    // it holds more objects than that.
    #[test]
    fn a_walk_stops_at_its_budget() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let commit = commit_with(&repo, 300, 8);
        let mut walk = Walk::new(&repo, 100, MAX_METADATA_OBJECT).unwrap();
        let err = objects_to_send(&mut walk, &[commit], &[]).unwrap_err();
        assert!(err.to_string().contains("objects walked"), "{err}");
        assert_eq!(walk.left, 0);
        // With room, the same walk completes: the commit, its tree, and the
        // 300 blobs.
        let mut walk = Walk::new(&repo, 1_000, MAX_METADATA_OBJECT).unwrap();
        assert_eq!(
            objects_to_send(&mut walk, &[commit], &[]).unwrap().len(),
            302
        );
    }

    // Review of heartwood #11, round 1: a blob is never read to learn its
    // kind, whether a client names it as a have or wants it unadvertised;
    // and no body past the walk's allowance is read.
    #[test]
    fn a_walk_reads_no_blob_and_no_body_past_its_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let big = repo.blob(&vec![9u8; 4 << 20]).unwrap();
        let small = repo.blob(b"small").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert("big", big, 0o100644).unwrap();
        tb.insert("small", small, 0o100644).unwrap();
        let tree = repo.find_tree(tb.write().unwrap()).unwrap();
        let commit = repo
            .commit(Some("refs/heads/main"), &sig(), &sig(), "m", &tree, &[])
            .unwrap();

        // Wanting the commit, with the big blob as a have.
        READ.with(|read| read.set(0));
        let mut walk = Walk::new(&repo, MAX_WALK, 1024).unwrap();
        let sent = objects_to_send(&mut walk, &[commit], &[big]).unwrap();
        assert!(!sent.contains(&big));
        assert!(sent.contains(&small));
        let read = READ.with(Cell::get);
        assert!(read < 1024, "{read} bytes of bodies read");

        // Wanting the big blob, unadvertised: refused, unread.
        READ.with(|read| read.set(0));
        let mut walk = Walk::new(&repo, MAX_WALK, 1024).unwrap();
        assert_eq!(unadvertised(&mut walk, &[big]).unwrap(), Some(big));
        assert!(READ.with(Cell::get) < 1024);

        // A tree past the allowance isn't read.
        let mut walk = Walk::new(&repo, MAX_WALK, 16).unwrap();
        let err = objects_to_send(&mut walk, &[commit], &[]).unwrap_err();
        assert!(err.to_string().contains("too large to read"), "{err}");
    }

    // Review of heartwood #11, round 1: `ls-refs` writes its advertisement as
    // it makes it, in bounded writes, whatever the number of refs.
    #[test]
    fn ls_refs_writes_its_advertisement_in_bounded_writes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(dir.path()).unwrap();
        let commit = commit_with(&repo, 1, 8);
        for i in 0..5_000 {
            repo.reference(&format!("refs/heads/branch-{i:05}"), commit, true, "test")
                .unwrap();
        }
        let cmd = Command {
            name: "ls-refs".to_owned(),
            lines: vec![b"command=ls-refs".to_vec(), b"peel".to_vec()],
        };
        let mut sink = Sink::default();
        handle_ls_refs(&repo, &cmd, &mut sink).unwrap();
        assert!(sink.writes.len() > 1, "{} writes", sink.writes.len());
        let largest = sink.writes.iter().map(Vec::len).max().unwrap();
        assert!(
            largest <= WRITE_FLUSH_THRESHOLD + 1024,
            "a write of {largest} bytes"
        );
        let wire = sink.writes.concat();
        assert!(wire.ends_with(b"0000"));
        assert_eq!(
            String::from_utf8_lossy(&wire)
                .matches("refs/heads/branch-")
                .count(),
            5_000
        );
    }
}
