//! Client control socket implementation.
use std::io::BufReader;
use std::io::LineWriter;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, net, time};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

use radicle::identity::RepoId;
use radicle::node::Handle;
use radicle::node::NodeId;
use radicle::node::{Command, CommandResult};
use radicle::storage::refs;
use serde_json as json;

use crate::runtime;
use crate::runtime::thread;

/// Maximum timeout for waiting for node events.
const MAX_TIMEOUT: time::Duration = time::Duration::MAX;

/// How long the listener waits, when no connection is pending, before it
/// looks again, and checks whether it is to stop.
const LISTEN_POLL: time::Duration = time::Duration::from_millis(50);

/// How long a command's thread stays, in milliseconds, once its command has
/// returned: for a test in a process of its own, to see that the thread is
/// joined, not merely ended by the time its node lets go of its home.
#[cfg(test)]
pub(crate) static COMMAND_LINGER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Whether a command's thread fails to start, as the operating system can
/// refuse one: for a test in a process of its own.
#[cfg(test)]
pub(crate) static COMMAND_SPAWN_FAILS: AtomicBool = AtomicBool::new(false);

/// Whether the listener panics once it has taken a connection: for a test
/// in a process of its own, of what an unwind leaves running.
#[cfg(test)]
pub(crate) static LISTENER_PANICS: AtomicBool = AtomicBool::new(false);

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to bind control socket listener: {0}")]
    Bind(io::Error),
    #[error("invalid socket path specified: {0}")]
    InvalidPath(PathBuf),
    #[error("node: {0}")]
    Node(#[from] runtime::handle::Error),
}

/// Listen for commands on the control socket, and process them, each on a
/// thread of its own, until `stop` is set.
///
/// The listener doesn't block on its socket: it looks for a connection
/// every [`LISTEN_POLL`], and checks `stop` in between. Once it is set, it
/// shuts down the connections of the commands still running, so that a read
/// or a write they wait on ends, joins their threads, and returns. A
/// command waiting on the node itself ends once the node has stopped: its
/// handle fails, and an event stream ends as the node closes it.
///
/// It does the same if it unwinds ([`Commands`]). A connection whose thread
/// the operating system won't start is closed, and the listener goes on.
pub fn listen<E, H>(listener: UnixListener, handle: H, stop: Arc<AtomicBool>) -> Result<(), Error>
where
    H: Handle<Error = runtime::handle::Error> + 'static,
    H::Sessions: serde::Serialize,
    CommandResult<E>: From<H::Event>,
    E: serde::Serialize,
{
    log::debug!(target: "control", "Control thread listening on socket..");
    let nid = handle.nid()?;
    listener.set_nonblocking(true).map_err(Error::Bind)?;

    let mut commands = Commands::default();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = stream.set_nonblocking(false) {
                    log::warn!(target: "control", "Failed to set up an incoming connection: {e}");
                    continue;
                }
                let control = match stream.try_clone() {
                    Ok(control) => control,
                    Err(e) => {
                        log::warn!(target: "control", "Failed to set up an incoming connection: {e}");
                        continue;
                    }
                };
                #[cfg(test)]
                if LISTENER_PANICS.load(Ordering::SeqCst) {
                    panic!("the listener panics, as a test asks");
                }
                let handle = handle.clone();
                let spawned = spawn_command(&nid, move || {
                    let mut stream = stream;
                    if let Err(e) = command(&stream, handle) {
                        log::debug!(target: "control", "Command returned error: {e}");

                        CommandResult::error(e).to_writer(&mut stream).ok();

                        stream.flush().ok();
                        stream.shutdown(net::Shutdown::Both).ok();
                    }
                    #[cfg(test)]
                    std::thread::sleep(time::Duration::from_millis(
                        COMMAND_LINGER.load(Ordering::SeqCst),
                    ));
                });
                match spawned {
                    Ok(thread) => commands.0.push((control, thread)),
                    // The command's closure, and its end of the connection,
                    // are dropped with the error: the connection closes.
                    Err(e) => {
                        log::warn!(
                            target: "control",
                            "Unable to start a thread for a control connection, closing it: {e}"
                        );
                        control.shutdown(net::Shutdown::Both).ok();
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(LISTEN_POLL),
            Err(e) => {
                log::warn!(target: "control", "Failed to accept incoming connection: {e}");
                std::thread::sleep(LISTEN_POLL);
            }
        }
        // The commands that have ended are joined, so that their handles
        // don't pile up.
        commands.join_ended();
    }
    log::debug!(target: "control", "Exiting control loop..");
    // `commands` shuts the rest down, and joins them, as it is dropped.
    Ok(())
}

/// Starts a command's thread, unless the operating system refuses it.
fn spawn_command<F>(nid: &NodeId, f: F) -> io::Result<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    #[cfg(test)]
    if COMMAND_SPAWN_FAILS.load(Ordering::SeqCst) {
        drop(f);
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "a thread refused, as a test asks",
        ));
    }
    thread::try_spawn(nid, "control", f)
}

/// The commands a listener serves: each one's connection, and its thread.
/// Dropped, as the listener returns or unwinds, it shuts their connections
/// down, so that a read or a write they wait on ends, and joins them.
#[derive(Default)]
struct Commands(Vec<(UnixStream, std::thread::JoinHandle<()>)>);

impl Commands {
    /// Joins the commands that have ended.
    fn join_ended(&mut self) {
        let (ended, running): (Vec<_>, Vec<_>) = std::mem::take(&mut self.0)
            .into_iter()
            .partition(|(_, thread)| thread.is_finished());
        for (_, thread) in ended {
            if thread.join().is_err() {
                log::error!(target: "control", "A control command's thread panicked");
            }
        }
        self.0 = running;
    }
}

impl Drop for Commands {
    fn drop(&mut self) {
        for (stream, _) in &self.0 {
            stream.shutdown(net::Shutdown::Both).ok();
        }
        for (_, thread) in self.0.drain(..) {
            if thread.join().is_err() {
                log::error!(target: "control", "A control command's thread panicked");
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum CommandError {
    #[error("(de)serialization failed: {0}")]
    Serialization(#[from] json::Error),
    #[error("runtime error: {0}")]
    Runtime(#[from] runtime::handle::Error),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

fn command<E, H>(stream: &UnixStream, mut handle: H) -> Result<(), CommandError>
where
    H: Handle<Error = runtime::handle::Error> + 'static,
    H::Sessions: serde::Serialize,
    CommandResult<E>: From<H::Event>,
    E: serde::Serialize,
{
    let mut reader = BufReader::new(stream);
    let mut writer = LineWriter::new(stream);

    let mut line = String::new();

    reader.read_line(&mut line)?;
    let input = line.trim_end();

    log::debug!(target: "control", "Received `{input}` on control socket");
    let cmd: Command = json::from_str(input)?;

    match cmd {
        Command::Connect { addr, opts } => {
            let (nid, addr) = addr.into();
            match handle.connect(nid, addr, opts) {
                Err(e) => return Err(CommandError::Runtime(e)),
                Ok(result) => {
                    json::to_writer(&mut writer, &result)?;
                    writer.write_all(b"\n")?;
                }
            }
        }
        Command::Disconnect { nid } => match handle.disconnect(nid) {
            Err(e) => return Err(CommandError::Runtime(e)),
            Ok(()) => {
                CommandResult::ok().to_writer(writer).ok();
            }
        },
        Command::Fetch {
            rid,
            nid,
            timeout,
            signed_references_minimum_feature_level,
        } => {
            fetch(
                rid,
                nid,
                timeout,
                signed_references_minimum_feature_level,
                writer,
                &mut handle,
            )?;
        }
        Command::Config => {
            let config = handle.config()?;

            CommandResult::Okay(config).to_writer(writer)?;
        }
        Command::ListenAddrs => {
            let addrs = handle.listen_addrs()?;

            CommandResult::Okay(addrs).to_writer(writer)?;
        }
        #[allow(deprecated)]
        Command::Seeds { rid } => {
            let seeds = handle.seeds(rid)?;

            CommandResult::Okay(seeds).to_writer(writer)?;
        }
        Command::SeedsFor { rid, namespaces } => {
            let seeds = handle.seeds_for(rid, namespaces)?;

            CommandResult::Okay(seeds).to_writer(writer)?;
        }
        Command::Sessions => {
            let sessions = handle.sessions()?;

            CommandResult::Okay(sessions).to_writer(writer)?;
        }
        Command::Session { nid } => {
            let session = handle.session(nid)?;

            CommandResult::Okay(session).to_writer(writer)?;
        }
        Command::Seed { rid, scope } => match handle.seed(rid, scope) {
            Ok(result) => {
                CommandResult::updated(result).to_writer(writer)?;
            }
            Err(e) => {
                return Err(CommandError::Runtime(e));
            }
        },
        Command::Unseed { rid } => match handle.unseed(rid) {
            Ok(result) => {
                CommandResult::updated(result).to_writer(writer)?;
            }
            Err(e) => {
                return Err(CommandError::Runtime(e));
            }
        },
        Command::Follow { nid, alias } => match handle.follow(nid, alias) {
            Ok(result) => {
                CommandResult::updated(result).to_writer(writer)?;
            }
            Err(e) => {
                return Err(CommandError::Runtime(e));
            }
        },
        Command::Block { nid } => match handle.block(nid) {
            Ok(result) => {
                CommandResult::updated(result).to_writer(writer)?;
            }
            Err(e) => {
                return Err(CommandError::Runtime(e));
            }
        },
        Command::Unfollow { nid } => match handle.unfollow(nid) {
            Ok(result) => {
                CommandResult::updated(result).to_writer(writer)?;
            }
            Err(e) => {
                return Err(CommandError::Runtime(e));
            }
        },
        #[allow(deprecated)]
        Command::AnnounceRefs { rid } => {
            let refs = handle.announce_refs(rid)?;

            CommandResult::Okay(refs).to_writer(writer)?;
        }
        Command::AnnounceRefsFor { rid, namespaces } => {
            let refs = handle.announce_refs_for(rid, namespaces)?;

            CommandResult::Okay(refs).to_writer(writer)?;
        }
        Command::AnnounceInventory => {
            if let Err(e) = handle.announce_inventory() {
                return Err(CommandError::Runtime(e));
            }
            CommandResult::ok().to_writer(writer).ok();
        }
        Command::AddInventory { rid } => match handle.add_inventory(rid) {
            Ok(result) => {
                CommandResult::updated(result).to_writer(writer)?;
            }
            Err(e) => {
                return Err(CommandError::Runtime(e));
            }
        },
        Command::Subscribe => match handle.subscribe(MAX_TIMEOUT) {
            Ok(events) => {
                for e in events {
                    CommandResult::from(e).to_writer(&mut writer)?;
                }
            }
            Err(e) => return Err(CommandError::Runtime(e)),
        },
        Command::Status => {
            CommandResult::ok().to_writer(writer).ok();
        }
        Command::NodeId => match handle.nid() {
            Ok(nid) => {
                CommandResult::Okay(nid).to_writer(writer)?;
            }
            Err(e) => return Err(CommandError::Runtime(e)),
        },
        Command::Debug => {
            let debug = handle.debug()?;

            CommandResult::Okay(debug).to_writer(writer)?;
        }
        Command::Shutdown => {
            log::debug!(target: "control", "Shutdown requested..");
            // Channel might already be disconnected if shutdown
            // came from somewhere else. Ignore errors.
            handle.shutdown().ok();
            CommandResult::ok().to_writer(writer).ok();
        }
    }
    Ok(())
}

fn fetch<W: Write, H: Handle<Error = runtime::handle::Error>>(
    id: RepoId,
    node: NodeId,
    timeout: time::Duration,
    signed_references_minimum_feature_level: Option<refs::FeatureLevel>,
    mut writer: W,
    handle: &mut H,
) -> Result<(), CommandError> {
    match handle.fetch(id, node, timeout, signed_references_minimum_feature_level) {
        Ok(result) => {
            json::to_writer(&mut writer, &result)?;
        }
        Err(e) => {
            return Err(CommandError::Runtime(e));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread;

    use radicle::identity::RepoId;
    use radicle::node::Handle;
    use radicle::node::policy::Scope;
    use radicle::node::{Alias, Node, NodeId};
    use radicle::test::arbitrary;

    use crate::test;

    #[test]
    fn test_control_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let handle = test::handle::Handle::default();
        let socket = tmp.path().join("alice.sock");
        let rids = arbitrary::set::<RepoId>(1..3);
        let listener = UnixListener::bind(&socket).unwrap();
        let nid = handle.nid().unwrap();

        thread::spawn({
            let handle = handle.clone();

            move || listen(listener, handle, Default::default())
        });

        for rid in &rids {
            let mut stream = loop {
                if let Ok(stream) = UnixStream::connect(&socket) {
                    break stream;
                }
            };
            writeln!(
                &mut stream,
                "{}",
                json::to_string(&Command::AnnounceRefsFor {
                    rid: rid.to_owned(),
                    namespaces: [nid].into(),
                })
                .unwrap()
            )
            .unwrap();

            let stream = BufReader::new(stream);
            let line = stream.lines().next().unwrap().unwrap();

            assert_eq!(
                line,
                json::json!({
                    "remote": handle.nid().unwrap(),
                    "at": "0000000000000000000000000000000000000000"
                })
                .to_string()
            );
        }

        for rid in &rids {
            assert!(handle.updates.lock().unwrap().contains(&(*rid, nid)));
        }
    }

    #[test]
    fn test_seed_unseed() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("node.sock");
        let proj = arbitrary::r#gen::<RepoId>(1);
        let peer = arbitrary::r#gen::<NodeId>(1);
        let listener = UnixListener::bind(&socket).unwrap();
        let mut handle = Node::new(&socket);

        thread::spawn({
            let handle = crate::test::handle::Handle::default();

            move || crate::control::listen(listener, handle, Default::default())
        });

        // Wait for node to be online.
        while !handle.is_running() {}

        assert!(handle.seed(proj, Scope::default()).unwrap());
        assert!(!handle.seed(proj, Scope::default()).unwrap());
        assert!(handle.unseed(proj).unwrap());
        assert!(!handle.unseed(proj).unwrap());

        assert!(handle.follow(peer, Some(Alias::new("alice"))).unwrap());
        assert!(!handle.follow(peer, Some(Alias::new("alice"))).unwrap());
        assert!(handle.unfollow(peer).unwrap());
        assert!(!handle.unfollow(peer).unwrap());
    }
}
