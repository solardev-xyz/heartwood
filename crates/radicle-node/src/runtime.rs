pub mod handle;
pub mod thread;

use std::fmt::Debug;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::{fs, io, net, time};

#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(windows)]
use uds_windows::UnixListener;

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
use radicle::node::notifications;
use radicle::node::policy::config as policy;
use radicle::node::{NodeId, routing};
use radicle::profile::Home;
use radicle::{Storage, cob, git, storage};
use radicle_signals::Signal;
use thiserror::Error;

use crate::control;
use crate::reactor;
use crate::reactor::Reactor;
use crate::resolver;
use crate::wire::Wire;
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
    /// A git version error.
    #[error("git version error: {0}")]
    GitVersion(#[from] git::VersionError),
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
    pub reactor: Reactor,
    pub pool: worker::Pool,
    pub local_addrs: Vec<net::SocketAddr>,
    pub signals: mpsc::Receiver<Signal>,
    /// The resolver threads, joined once the reactor has ended.
    resolvers: resolver::Workers,
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
    /// This function spawns threads.
    pub fn init(
        home: Home,
        config: radicle::node::Config,
        socket: Option<PathBuf>,
        listen: Vec<net::SocketAddr>,
        signals: mpsc::Receiver<Signal>,
        secret_key: SigningKey,
        gate: Arc<dyn Gate>,
    ) -> Result<Runtime, Error> {
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

        let announcement = service::gossip::node(&config, timestamp)
            .solve(Default::default())
            .expect("Runtime::init: unable to solve proof-of-work puzzle");

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
        );
        service.initialize(clock)?;

        let (worker_send, worker_recv) =
            crossbeam_channel::bounded::<worker::Task>(MAX_PENDING_TASKS);
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
        let reactor = Reactor::with(
            |controller| {
                let (queue, workers) = resolver::spawn(
                    gate.clone(),
                    controller,
                    outbound.min(MAX_RESOLVER_THREADS),
                    outbound,
                )?;
                resolvers = Some(workers);
                let mut wire = Wire::new(service, worker_send, secret_key.clone(), gate, queue);
                for listener in listeners {
                    wire.listen(listener);
                }
                Ok(wire)
            },
            thread::name(&id, "service"),
        )?;
        let resolvers = resolvers.ok_or_else(|| io::Error::other("no resolver pool"))?;
        let handle = Handle::new(home.clone(), socket.clone(), reactor.controller(), emitter);

        let nid = NodeId::from(*secret_key.public_key());
        let fetch = worker::FetchConfig {
            local: nid,
            expiry: worker::garbage::Expiry::default(),
        };
        let pool = worker::Pool::with(
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
            },
        )?;
        let control = socket.map(Self::bind).transpose()?;

        Ok(Runtime {
            id,
            home,
            control,
            storage,
            reactor,
            handle,
            pool,
            signals,
            local_addrs,
            resolvers,
        })
    }

    pub fn run(self) -> Result<(), Error> {
        let home = self.home;
        let (listener, remove) = match self.control {
            Some(ControlSocket::Bound(listener, path)) => (Some(listener), Some(path)),
            Some(ControlSocket::Received(listener)) => (Some(listener), None),
            None => (None, None),
        };

        log::info!(target: "node", "Running node {} in {}..", self.id, home.path().display());

        if let Some(listener) = listener {
            thread::spawn(&self.id, "control", {
                let handle = self.handle.clone();
                || control::listen(listener, handle)
            });
        }

        let stopped = Arc::new(AtomicBool::new(false));
        let signals = thread::spawn(&self.id, "signals", {
            let stopped = stopped.clone();
            move || {
                loop {
                    use radicle::node::Handle as _;

                    // Checked on every turn, so that a stream of ignored signals can't keep
                    // the watcher from seeing that the node has stopped.
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    match self.signals.recv_timeout(SIGNAL_WATCH_INTERVAL) {
                        Ok(Signal::Terminate | Signal::Interrupt) => {
                            log::info!(target: "node", "Termination signal received; shutting down..");
                            self.handle.shutdown().ok();
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

        self.pool.run().unwrap();
        self.reactor.join().unwrap();
        // The reactor is gone, and the wire with it, so the resolvers' queue
        // has closed: each ends once its current call returns.
        self.resolvers.join_within(RESOLVER_JOIN_LIMIT);

        // The node has stopped: the signal watcher ends at its next check,
        // whether or not the host still holds its signal sender.
        stopped.store(true, Ordering::Release);
        if signals.join().is_err() {
            log::error!(target: "node", "The signal watcher thread panicked");
        }

        // Nb. We don't join the control thread here, as we have no way of notifying it that the
        // node is shutting down. With a control socket, its listener thread, and any thread
        // serving a command, outlive `run`, as they always have; the binary exits once `run`
        // returns. Without one, every thread `run` starts has been joined by now.

        // Remove control socket file, but don't freak out if it's not there anymore.
        remove.map(|path| fs::remove_file(path).ok());

        log::debug!(target: "node", "Node shutdown completed for {}", self.id);

        Ok(())
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

    fn bind(path: PathBuf) -> Result<ControlSocket, Error> {
        #[cfg(all(feature = "socket2", feature = "systemd", target_os = "linux"))]
        {
            if let Some(listener) = Self::receive_listener() {
                log::info!(target: "node", "Received control socket.");
                return Ok(ControlSocket::Received(listener));
            }
        }

        log::info!(target: "node", "Binding control socket {}..", path.display());
        match UnixListener::bind(&path) {
            Ok(sock) => Ok(ControlSocket::Bound(sock, path)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => Err(Error::AlreadyRunning(path)),
            Err(err) => Err(err.into()),
        }
    }
}
