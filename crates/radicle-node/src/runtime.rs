pub mod handle;
pub mod thread;

use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, mpsc};
use std::{fs, io, net, time};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

use handle::Handle;
use localtime::LocalTime;
use protocol::service;
use protocol::service::gossip;
use radicle::cob::migrate;
use radicle::crypto::{Signer as _, SigningKey};
use radicle::node;
use radicle::node::Event;
use radicle::node::UserAgent;
use radicle::node::address;
use radicle::node::address::Store as _;
use radicle::node::dial::Gate;
use radicle::node::events::Emitter;
use radicle::node::gate::RepoGate;
use radicle::node::notifications;
use radicle::node::policy::config as policy;
use radicle::node::{NodeId, routing};
use radicle::profile::{Home, NodeLock};
use radicle::{Storage, cob, git, storage};
use radicle_signals::Signal;
use thiserror::Error;

use crate::control;
use crate::reactor;
use crate::reactor::Reactor;
use crate::resolver;
use crate::wire;
use crate::wire::{Stopped, Wire};
use crate::worker;

/// Maximum pending worker tasks allowed.
pub const MAX_PENDING_TASKS: usize = 1024;

/// The most resolver threads a node runs: fewer when its outbound connection
/// limit is lower, so that names never resolve faster than they can be
/// dialled.
pub const MAX_RESOLVER_THREADS: usize = 4;

/// How long a node's shutdown waits for a resolver thread still in a call.
pub const RESOLVER_JOIN_LIMIT: time::Duration = time::Duration::from_secs(1);

/// How long the signal watcher waits for a signal before it checks whether
/// the node has stopped. A host may keep its signal sender after the node
/// stops, so the watcher can't rely on the channel closing to end.
const SIGNAL_WATCH_INTERVAL: time::Duration = time::Duration::from_millis(250);

/// A client error.
#[derive(Error, Debug)]
pub enum Error {
    /// A routing database error.
    #[error("routing database error: {0}")]
    Routing(#[from] routing::Error),
    /// A cobs cache database error.
    #[error("cobs cache database error: {0}")]
    CobsCache(#[from] cob::cache::Error),
    /// A node database error.
    #[error("node database error: {0}")]
    Database(#[from] node::db::Error),
    /// A storage error.
    #[error("storage error: {0}")]
    Storage(#[from] storage::Error),
    /// A policies database error.
    #[error("policies database error: {0}")]
    Policy(#[from] policy::Error),
    /// A notifications database error.
    #[error("notifications database error: {0}")]
    Notifications(#[from] notifications::Error),
    /// A gossip database error.
    #[error("gossip database error: {0}")]
    Gossip(#[from] gossip::Error),
    /// An address database error.
    #[error("address database error: {0}")]
    Address(#[from] address::Error),
    /// A service error.
    #[error("service error: {0}")]
    Service(Box<service::Error>),
    /// An I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// A control socket error.
    #[error("control socket error: {0}")]
    Control(#[from] control::Error),
    /// Another node is already running.
    #[error(
        "another node appears to be running; \
        if this isn't the case, delete the socket file at '{0}' \
        and restart the node"
    )]
    AlreadyRunning(PathBuf),
    /// Another node runs on the home: it holds its node lock.
    #[error("another node runs on the home at '{0}'")]
    HomeLocked(PathBuf),
    /// The control socket's path names something the node won't replace.
    #[error(
        "the control socket path '{0}' names {1}, which the node neither connects to nor removes"
    )]
    ControlPath(PathBuf, &'static str),
    /// One of the node's threads panicked. The node has stopped, and every
    /// thread of it has been joined.
    #[error("the node's {0} thread panicked")]
    Panicked(&'static str),
    /// A git version error.
    #[error("git version error: {0}")]
    GitVersion(#[from] git::VersionError),
    /// The configuration asks for no fetches at all.
    #[error("invalid configuration: fetch concurrency must be at least 1")]
    ZeroFetchConcurrency,
    /// The configuration has more external addresses than an announcement carries.
    #[error("invalid configuration: {0}")]
    TooManyAddresses(#[from] gossip::TooManyAddresses),
    /// No nonce solves the node announcement's proof of work.
    #[error("unable to solve the node announcement's proof of work")]
    ProofOfWork,
}

impl From<service::Error> for Error {
    fn from(e: service::Error) -> Self {
        Self::Service(Box::new(e))
    }
}

/// Wraps a [`UnixListener`] but tracks its origin.
pub enum ControlSocket {
    /// The listener was created by binding to it.
    Bound(UnixListener, PathBuf),
    /// The listener was received via socket activation.
    Received(UnixListener),
}

/// Holds join handles to the client threads, as well as a client handle.
pub struct Runtime {
    pub id: NodeId,
    pub home: Home,
    /// The control socket, unless the host runs the node without one.
    pub control: Option<ControlSocket>,
    pub handle: Handle,
    pub storage: Storage,
    pub local_addrs: Vec<net::SocketAddr>,
    pub signals: mpsc::Receiver<Signal>,
    /// The error the service stopped the node with, once it has.
    stopped: Stopped,
    /// The node's threads and the home's lock. A runtime dropped without a
    /// run stops and joins its threads before it lets go of the lock.
    life: Lifecycle,
}

/// A node's threads, its control socket's file and its home's lock.
///
/// Its end stops the threads and joins them, removes the file, and only then
/// lets go of the lock. It ends whether the node stops, its start fails, its
/// run unwinds, or its runtime is dropped without a run, so no other node
/// takes the home while anything of this one runs.
struct Lifecycle {
    reactor: Option<Reactor>,
    pool: Option<worker::Pool>,
    resolvers: Option<resolver::Workers>,
    watcher: Option<Watcher>,
    handle: Option<Handle>,
    socket: Option<SocketFile>,
    lock: Option<NodeLock>,
}

/// The signal watcher's thread, and the word that stops it.
struct Watcher {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Lifecycle {
    /// The life of a node that holds `lock`, before anything of it runs.
    fn new(lock: NodeLock) -> Self {
        Self {
            reactor: None,
            pool: None,
            resolvers: None,
            watcher: None,
            handle: None,
            socket: None,
            lock: Some(lock),
        }
    }

    /// Stops what of the node runs, and joins it.
    ///
    /// The reactor goes first: its end closes the workers' and the
    /// resolvers' queues. The workers, the resolvers and the signal watcher
    /// follow. Then the control socket's file is removed, if its path still
    /// names the socket bound, and the lock is released.
    ///
    /// It returns the first thread found to have panicked, if one did.
    fn end(&mut self) -> Option<&'static str> {
        let mut panicked = None;
        if let Some(reactor) = self.reactor.take() {
            // An error: the reactor has ended already.
            reactor.controller().shutdown().ok();
            if reactor.join().is_err() {
                log::error!(target: "node", "The reactor thread panicked");
                panicked = panicked.or(Some("reactor"));
            }
        }
        if let Some(mut pool) = self.pool.take()
            && pool.join().is_err()
        {
            panicked = panicked.or(Some("worker"));
        }
        // A resolver still in a name lookup after this is left to end on its
        // own. It touches nothing of the home.
        if let Some(resolvers) = self.resolvers.take() {
            resolvers.join_within(RESOLVER_JOIN_LIMIT);
        }
        // The watcher ends at its next check, whether or not the host still
        // holds its signal sender.
        if let Some(watcher) = self.watcher.take() {
            watcher.stop.store(true, Ordering::Release);
            if watcher.thread.join().is_err() {
                log::error!(target: "node", "The signal watcher thread panicked");
                panicked = panicked.or(Some("signal watcher"));
            }
        }
        if let Some(handle) = self.handle.take() {
            handle.ended();
        }
        if let Some(socket) = self.socket.take() {
            socket.remove();
        }
        self.lock = None;
        panicked
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        self.end();
    }
}

/// A control socket's file, as the runtime bound it, or found it at its path.
struct SocketFile {
    path: PathBuf,
    /// Its device and inode.
    #[cfg(unix)]
    id: (u64, u64),
}

impl SocketFile {
    /// The socket file at `path`, if the runtime may connect to it and remove
    /// it: only a socket of the user `uid`'s, and never a symbolic link or a
    /// file of another kind.
    #[cfg(unix)]
    fn at(path: &Path, uid: u32) -> Result<Self, Error> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        let meta = fs::symlink_metadata(path)?;
        let kind = meta.file_type();
        let refused = if kind.is_symlink() {
            "a symbolic link"
        } else if !kind.is_socket() {
            "a file that isn't a socket"
        } else if meta.uid() != uid {
            "a socket of another user's"
        } else {
            return Ok(Self {
                path: path.to_owned(),
                id: (meta.dev(), meta.ino()),
            });
        };
        Err(Error::ControlPath(path.to_owned(), refused))
    }

    /// The socket file at `path`, if the runtime may connect to it and remove
    /// it: one of the current user's.
    #[cfg(unix)]
    fn found(path: &Path) -> Result<Self, Error> {
        Self::at(path, rustix::process::geteuid().as_raw())
    }

    /// The socket file at `path`, if the runtime may connect to it and remove
    /// it: never a symbolic link or a directory. Windows has no file identity
    /// in `std`, nor a socket owner the runtime checks.
    #[cfg(windows)]
    fn found(path: &Path) -> Result<Self, Error> {
        let refused = match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => "a symbolic link",
            Ok(meta) if meta.is_dir() => "a file that isn't a socket",
            _ => {
                return Ok(Self {
                    path: path.to_owned(),
                });
            }
        };
        Err(Error::ControlPath(path.to_owned(), refused))
    }

    /// Whether its path still names it.
    fn is_named(&self) -> bool {
        match fs::symlink_metadata(&self.path) {
            #[cfg(unix)]
            Ok(meta) => {
                use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
                meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.id
            }
            #[cfg(windows)]
            Ok(meta) => !meta.file_type().is_symlink() && !meta.is_dir(),
            #[cfg(windows)]
            Err(e) => e.kind() != io::ErrorKind::NotFound,
            #[cfg(unix)]
            Err(_) => false,
        }
    }

    /// Removes it, if its path still names it: a file put in its place, a
    /// symbolic link among them, is left as it is.
    fn remove(self) {
        if self.is_named() {
            fs::remove_file(&self.path).ok();
        } else if self.path.symlink_metadata().is_ok() {
            log::warn!(
                target: "node",
                "The control socket {} was replaced; leaving what is there now",
                self.path.display()
            );
        }
    }
}

impl Runtime {
    /// Initialize the runtime.
    ///
    /// With `socket`, the node listens for control commands there (the `rad`
    /// CLI's connection); without it, the node has no control socket at all,
    /// and only its [`Handle`] controls it: an embedding host that drives the
    /// node in-process needs no socket on disk.
    ///
    /// `gate` decides which addresses the node may dial, and resolves names
    /// for it ([`radicle::node::dial::Open`] keeps the node's own behaviour).
    ///
    /// It takes the home's node lock first, so that no other node can run on
    /// the home while this one does: [`Error::HomeLocked`] if one does. It
    /// binds the control socket next, before any thread starts. A start that
    /// fails after the node's threads have started stops and joins them, so
    /// nothing of the node runs on, before it lets go of the lock.
    ///
    /// On Unix, the home's `node` directory is made its user's alone, and a
    /// control socket the node binds is `0600` before it listens, whatever
    /// the umask. One a service manager passes is left as it is.
    ///
    /// This function spawns threads.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        home: Home,
        config: radicle::node::Config,
        socket: Option<PathBuf>,
        listen: Vec<net::SocketAddr>,
        signals: mpsc::Receiver<Signal>,
        secret_key: SigningKey,
        gate: Arc<dyn Gate>,
        repositories: RepoGate,
    ) -> Result<Runtime, Error> {
        let lock = home.lock_node().map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                Error::HomeLocked(home.path().to_path_buf())
            } else {
                Error::Io(e)
            }
        })?;
        // Whatever stops the start from here, what of the node has started by
        // then is stopped and joined, and the lock released after it.
        let mut life = Lifecycle::new(lock);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            // The node's databases, and its control socket by default.
            if let Err(e) = fs::set_permissions(home.node(), fs::Permissions::from_mode(0o700)) {
                log::warn!(target: "node", "Unable to make {} its user's alone: {e}", home.node().display());
            }
        }
        let id = NodeId::from(*secret_key.public_key());
        let alias = config.alias.clone();
        let network = config.network;
        let rng = fastrand::Rng::new();
        let clock = LocalTime::now();
        let timestamp = clock.into();
        let storage = Storage::open(home.storage(), git::UserInfo { alias, key: id })?;
        let policy = config.seeding_policy.into();

        for (key, _) in &config.extra {
            log::warn!(target: "node", "Unused or deprecated configuration attribute {key:?}");
        }

        log::info!(target: "node", "Opening policy database..");
        let policies = home.policies_mut()?;
        let policies = policy::Config::new(policy, policies);
        let notifications = home.notifications_mut()?;
        let mut cobs_cache = cob::cache::Store::open(home.cobs().join(cob::cache::COBS_DB_FILE))?;

        match cobs_cache.check_version() {
            Ok(()) => {}
            Err(cob::cache::Error::OutOfDate) => {
                log::info!(target: "node", "Migrating COBs cache..");
                let version = cobs_cache.migrate(migrate::log)?;
                log::info!(target: "node", "Migration of COBs cache complete (version={version})..");
            }
            Err(e) => return Err(e.into()),
        }

        log::info!(target: "node", "Default seeding policy set to '{}'", policy);
        log::info!(target: "node", "Initializing service ({network:?})..");

        if usize::from(config.limits.fetch_concurrency) == 0 {
            return Err(Error::ZeroFetchConcurrency);
        }
        let announcement = service::gossip::node(&config, timestamp)?
            .solve(Default::default())
            .ok_or(Error::ProofOfWork)?;

        log::info!(target: "node", "Opening node database..");
        let db = home.database_mut(config.database)?.init(
            &id,
            announcement.features,
            &announcement.alias,
            &announcement.agent,
            announcement.timestamp,
            announcement.addresses.iter(),
        )?;
        let mut stores: service::Stores<_> = db.clone().into();

        if config.connect.is_empty() && stores.addresses().is_empty()? {
            log::info!(target: "node", "Address book is empty. Adding bootstrap nodes..");

            for (alias, version, addrs) in config.network.bootstrap() {
                for addr in addrs {
                    let (id, addr) = addr.into();

                    stores.addresses_mut().insert(
                        &id,
                        version,
                        radicle::node::Features::SEED,
                        &alias,
                        0,
                        &UserAgent::from_str("/radicle/runtime/bootstrap/")
                            .expect("valid user agent"),
                        clock.into(),
                        [node::KnownAddress::new(addr, address::Source::Bootstrap)],
                    )?;
                }
            }
            log::info!(target: "node", "{} nodes added to address book", stores.addresses().len()?);
        }

        let emitter: Emitter<Event> = Default::default();
        let mut service = service::Service::new(
            config.clone(),
            stores,
            storage.clone(),
            policies,
            secret_key.clone(),
            rng,
            announcement,
            emitter.clone(),
            gate.clone(),
        )
        .with_repositories(repositories.clone());

        // The control socket is bound before any of the node's threads start,
        // and removed again if the start fails.
        let control = match socket.clone() {
            Some(path) => {
                let (control, file) = Self::bind(path)?;
                life.socket = file;
                Some(control)
            }
            None => None,
        };

        let (worker_send, worker_recv) =
            crossbeam_channel::bounded::<worker::Task>(MAX_PENDING_TASKS);
        let stopped = Stopped::default();
        let mut local_addrs = Vec::new();
        let mut listeners = Vec::new();

        for addr in listen {
            let listener = reactor::Listener::bind(addr)?;
            local_addrs.push(listener.local_addr());
            listeners.push(listener);
        }
        // The resolver pool hands its answers back through the reactor's
        // controller, which it has before the reactor's first event: a name
        // dialled at start resolves like any other.
        let outbound = usize::from(config.limits.connection.outbound).max(1);
        let mut resolvers = None;
        let mut initialized = Ok(());
        let reactor = Reactor::with(
            |controller| {
                // The gate tells the service of every change of a
                // repository's state, through the reactor: from before the
                // service initializes, which reads the states as they are
                // then, so that no change is missed.
                let gated = controller.clone();
                repositories.listen(move |rid, state| {
                    gated
                        .cmd(wire::Control::User(service::Command::Gate(rid, state)))
                        .ok();
                });
                if let Err(e) = service.initialize(clock) {
                    let reason = e.to_string();
                    initialized = Err(e);
                    return Err(io::Error::other(reason));
                }
                let (queue, workers) = resolver::spawn(
                    gate.clone(),
                    controller,
                    outbound.min(MAX_RESOLVER_THREADS),
                    outbound,
                    thread::name(&id, "resolver"),
                )?;
                resolvers = Some(workers);
                let mut wire = Wire::new(
                    service,
                    worker_send,
                    secret_key.clone(),
                    gate,
                    queue,
                    stopped.clone(),
                );
                for listener in listeners {
                    wire.listen(listener);
                }
                Ok(wire)
            },
            thread::name(&id, "service"),
        );
        life.resolvers = resolvers;
        initialized?;
        let reactor = reactor?;
        let controller = reactor.controller();
        life.reactor = Some(reactor);
        if life.resolvers.is_none() {
            return Err(io::Error::other("no resolver pool").into());
        }
        let handle = Handle::new(home.clone(), socket, controller, emitter);
        life.handle = Some(handle.clone());

        let nid = NodeId::from(*secret_key.public_key());
        let fetch = worker::FetchConfig {
            local: nid,
            expiry: worker::garbage::Expiry::default(),
        };
        life.pool = Some(worker::Pool::with(
            worker_recv,
            nid,
            handle.clone(),
            notifications,
            cobs_cache,
            db,
            worker::Config {
                capacity: config.workers.into(),
                storage: storage.clone(),
                fetch,
                policy,
                policies_db: home.node().join(node::POLICIES_DB_FILE),
                repositories,
            },
        )?);

        Ok(Runtime {
            id,
            home,
            control,
            storage,
            handle,
            signals,
            local_addrs,
            stopped,
            life,
        })
    }

    /// The reactor's controller. Its shutdown stops the node, as the node
    /// handle's does.
    pub fn controller(&self) -> reactor::Controller {
        self.handle.controller.clone()
    }

    /// Runs the node until it stops, then stops and joins its threads before
    /// it lets go of the home's lock: [`Error::Panicked`] if one of them
    /// panicked, without an unwind.
    pub fn run(self) -> Result<(), Error> {
        let Runtime {
            id,
            home,
            control,
            handle,
            signals,
            stopped,
            mut life,
            ..
        } = self;
        let listener = match control {
            Some(ControlSocket::Bound(listener, _) | ControlSocket::Received(listener)) => {
                Some(listener)
            }
            None => None,
        };

        log::info!(target: "node", "Running node {} in {}..", id, home.path().display());

        if let Some(listener) = listener {
            thread::spawn(&id, "control", {
                let handle = handle.clone();
                || control::listen(listener, handle)
            });
        }

        let watcher_stop = Arc::new(AtomicBool::new(false));
        let watcher = thread::spawn(&id, "signals", {
            let stopped = watcher_stop.clone();
            move || {
                loop {
                    use radicle::node::Handle as _;

                    // Checked on every turn, so that a stream of ignored signals can't keep
                    // the watcher from seeing that the node has stopped.
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    match signals.recv_timeout(SIGNAL_WATCH_INTERVAL) {
                        Ok(Signal::Terminate | Signal::Interrupt) => {
                            log::info!(target: "node", "Termination signal received; shutting down..");
                            handle.shutdown().ok();
                            break;
                        }
                        Ok(Signal::Hangup) => {
                            log::debug!(target: "node", "Hangup signal (SIGHUP) received; ignoring..");
                        }
                        Ok(Signal::WindowChanged) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(e @ mpsc::RecvTimeoutError::Disconnected) => {
                            log::warn!(target: "node", "Signal notifications channel error: {e}");
                            break;
                        }
                    }
                }
            }
        });

        life.watcher = Some(Watcher {
            stop: watcher_stop,
            thread: watcher,
        });

        // The node runs until its workers have exited: they do once the
        // reactor's end has closed their queue, or each as it panics. Then
        // what is left of the node is stopped, and joined.
        let workers = life.pool.as_mut().map_or(Ok(()), worker::Pool::join);
        let ended = life.end();

        // Nb. We don't join the control thread here, as we have no way of notifying it that the
        // node is shutting down. With a control socket, its listener thread, and any thread
        // serving a command, outlive `run`, as they always have; the binary exits once `run`
        // returns. Without one, every thread `run` starts has been joined by now. A command
        // still served reaches the node through its handle alone, which reaches nothing once
        // the reactor has ended.

        log::debug!(target: "node", "Node shutdown completed for {id}");

        if let Some(thread) = workers.err().map(|_| "worker").or(ended) {
            return Err(Error::Panicked(thread));
        }
        // A node the service stopped returns the error it stopped with.
        match stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    #[cfg(all(feature = "socket2", feature = "systemd", target_os = "linux"))]
    fn receive_listener() -> Option<UnixListener> {
        // SAFETY: When `fd` is called, no other threads are spawned (yet).
        let fd = match unsafe { radicle_systemd::listen::fd("control") } {
            Ok(Some(fd)) => fd,
            Ok(None) => return None,
            Err(err) => {
                log::error!(target: "node", "Error receiving listener from systemd: {err}");
                return None;
            }
        };

        let socket: socket2::Socket = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };

        let domain = match socket.domain() {
            Ok(domain) => domain,
            Err(err) => {
                log::error!(target: "node", "Error receiving listener from systemd when inspecting domain of socket: {err}");
                return None;
            }
        };

        if domain != socket2::Domain::UNIX {
            log::error!(target: "node", "Dropping listener received from systemd: Domain is not AF_UNIX.");
            return None;
        }

        Some(UnixListener::from(socket))
    }

    /// Binds the control socket at `path`, unless a service manager passes
    /// one. It returns the socket's file, which the runtime removes at its
    /// end, if it bound it.
    fn bind(path: PathBuf) -> Result<(ControlSocket, Option<SocketFile>), Error> {
        #[cfg(all(feature = "socket2", feature = "systemd", target_os = "linux"))]
        {
            if let Some(listener) = Self::receive_listener() {
                log::info!(target: "node", "Received control socket.");
                return Ok((ControlSocket::Received(listener), None));
            }
        }

        log::info!(target: "node", "Binding control socket {}..", path.display());
        match Self::listen(&path) {
            Ok((sock, file)) => Ok((ControlSocket::Bound(sock, path), Some(file))),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                // With the home's lock held, a socket nothing listens on is one
                // a node that ended uncleanly left: it is removed, and bound
                // again. One that answers belongs to a node that runs. Only a
                // socket of the current user's is either: a symbolic link, or
                // a file of another kind, is neither followed nor removed.
                let found = SocketFile::found(&path)?;
                match UnixStream::connect(&path) {
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                        ) =>
                    {
                        log::info!(target: "node", "Removing the stale control socket {}..", path.display());
                        // Unless something else has taken its place meanwhile.
                        found.remove();
                        match Self::listen(&path) {
                            Ok((sock, file)) => Ok((ControlSocket::Bound(sock, path), Some(file))),
                            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                                Err(Error::AlreadyRunning(path))
                            }
                            Err(err) => Err(err.into()),
                        }
                    }
                    _ => Err(Error::AlreadyRunning(path)),
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Binds a socket at `path`, and listens on it once its file is `0600`:
    /// no other user connects to it, whatever the umask, the directory's
    /// mode, or how soon one tries.
    #[cfg(unix)]
    fn listen(path: &Path) -> io::Result<(UnixListener, SocketFile)> {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};

        #[cfg(not(target_vendor = "apple"))]
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )?;
        #[cfg(target_vendor = "apple")]
        let fd = {
            let fd = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
            rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
            fd
        };
        rustix::net::bind(&fd, &SocketAddrUnix::new(path)?)?;
        // What takes the path's place between the bind and the listen is
        // neither listened on nor removed.
        let file = SocketFile::found(path).map_err(|e| io::Error::other(e.to_string()))?;
        let listening = (|| {
            rustix::fs::chmod(path, rustix::fs::Mode::from_raw_mode(0o600))?;
            if !file.is_named() {
                return Err(io::Error::other(
                    "the control socket's path changed as it was bound",
                ));
            }
            rustix::net::listen(&fd, 128)?;
            Ok::<_, io::Error>(())
        })();
        match listening {
            Ok(()) => Ok((UnixListener::from(fd), file)),
            Err(e) => {
                file.remove();
                Err(e)
            }
        }
    }

    /// Binds a socket at `path`, and listens on it.
    #[cfg(windows)]
    fn listen(path: &Path) -> io::Result<(UnixListener, SocketFile)> {
        let listener = UnixListener::bind(path)?;
        Ok((
            listener,
            SocketFile {
                path: path.to_owned(),
            },
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    // Review of heartwood #16, round 1: a stale socket is the runtime's to
    // connect to and remove only if it is the current user's.
    fn a_socket_of_another_user_s_is_left_as_it_is() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("control.sock");
        drop(UnixListener::bind(&path).unwrap());
        let uid = rustix::process::geteuid().as_raw();

        assert!(SocketFile::at(&path, uid).unwrap().is_named());
        assert!(matches!(
            SocketFile::at(&path, uid.wrapping_add(1)),
            Err(Error::ControlPath(_, "a socket of another user's"))
        ));
    }

    #[test]
    // Review of heartwood #16, round 1: a socket file is removed only while
    // its path still names it.
    fn a_socket_file_is_removed_only_while_its_path_names_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("control.sock");
        let uid = rustix::process::geteuid().as_raw();
        drop(UnixListener::bind(&path).unwrap());
        let first = SocketFile::at(&path, uid).unwrap();
        // Another socket takes its place.
        let other = tmp.path().join("other.sock");
        drop(UnixListener::bind(&other).unwrap());
        fs::rename(&other, &path).unwrap();

        assert!(!first.is_named());
        first.remove();
        assert!(
            path.symlink_metadata().is_ok(),
            "another socket was removed"
        );
        SocketFile::at(&path, uid).unwrap().remove();
        assert!(path.symlink_metadata().is_err());
    }
}
