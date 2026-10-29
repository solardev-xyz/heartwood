#![allow(clippy::too_many_arguments)]
pub(crate) mod channels;
mod upload_pack;
#[cfg(feature = "serve-in-process")]
mod upload_pack_inproc;

pub mod fetch;
pub mod garbage;

use std::path::PathBuf;

use channels::Channels;
use crossbeam_channel as chan;
use protocol::wire::StreamId;
use protocol::worker::{AuthorizationError, FetchError, FetchRequest, FetchResult, UploadError};
use radicle::identity::RepoId;
use radicle::node::gate::{Purpose, RepoGate};
use radicle::node::notifications;
use radicle::node::policy::config as policy;
use radicle::node::policy::config::SeedingPolicy;
use radicle::prelude::NodeId;
use radicle::storage::refs::RefsAt;
use radicle::storage::{ReadRepository, ReadStorage};
use radicle::{Storage, cob, crypto};

use crate::runtime::{handle::Handle, thread};

/// Worker pool configuration.
pub struct Config {
    /// Number of worker threads.
    pub capacity: usize,
    /// Git storage.
    pub storage: Storage,
    /// Configuration for performing fetched.
    pub fetch: FetchConfig,
    /// Default policy, if a policy for a specific node or repository was not found.
    pub policy: SeedingPolicy,
    /// Path to the policies database.
    pub policies_db: PathBuf,
    /// The repository gate: which repositories may be fetched and served.
    pub repositories: RepoGate,
}

/// Task to be accomplished on a worker thread.
/// This is either going to be an outgoing or incoming fetch.
pub struct Task {
    pub fetch: FetchRequest,
    pub stream: StreamId,
    pub channels: Channels,
}

/// Worker response.
#[derive(Debug)]
pub struct TaskResult {
    pub remote: NodeId,
    pub result: FetchResult,
    pub stream: StreamId,
}

#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Public key of the local peer.
    pub local: crypto::PublicKey,
    /// Configuration for `git gc` garbage collection.
    pub expiry: garbage::Expiry,
}

/// A worker that replicates git objects.
struct Worker {
    nid: NodeId,
    storage: Storage,
    fetch_config: FetchConfig,
    tasks: chan::Receiver<Task>,
    handle: Handle,
    policies: policy::Config<policy::store::Read>,
    notifications: notifications::StoreWriter,
    cache: cob::cache::StoreWriter,
    db: radicle::node::Database,
    repositories: RepoGate,
}

impl Worker {
    /// Waits for tasks and runs them. Blocks indefinitely unless there is an error receiving
    /// the next task.
    fn run(mut self) -> Result<(), chan::RecvError> {
        #[cfg(test)]
        if PANIC_ON_START.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("a worker's panic, for a test");
        }
        loop {
            let task = self.tasks.recv()?;
            self.process(task);
        }
    }

    fn process(
        &mut self,
        Task {
            fetch,
            channels,
            stream,
        }: Task,
    ) {
        let remote = fetch.remote();
        let channels = channels::ChannelsFlush::new(self.handle.clone(), channels, remote, stream);
        let result = self._process(fetch, stream, channels, self.notifications.clone());

        log::trace!(target: "worker", "Sending response back to service..");

        if self
            .handle
            .worker_result(TaskResult {
                remote,
                stream,
                result,
            })
            .is_err()
        {
            log::error!(target: "worker", "Unable to report fetch result: worker channel disconnected");
        }
    }

    fn _process(
        &mut self,
        fetch: FetchRequest,
        stream: StreamId,
        mut channels: channels::ChannelsFlush,
        notifs: notifications::StoreWriter,
    ) -> FetchResult {
        match fetch {
            FetchRequest::Initiator {
                rid,
                remote,
                refs_at,
                config,
            } => {
                log::debug!(target: "worker", "Worker processing outgoing fetch for {rid}");
                let result = self.fetch(rid, remote, refs_at, config, channels, notifs);
                FetchResult::Initiator { rid, result }
            }
            FetchRequest::Responder { remote, emitter } => {
                // Embedded hosts that cannot spawn child processes (e.g. iOS)
                // decline to serve instead of spawning `git upload-pack`.
                if cfg!(feature = "no-serve") {
                    log::debug!(target: "worker", "Declining incoming fetch for {remote} on stream {stream} (no-serve build)");
                    drop(emitter);
                    return FetchResult::Responder {
                        rid: None,
                        result: Err(UploadError::PacketLine(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "this node does not serve fetches (no-serve build)",
                        ))),
                    };
                }
                log::debug!(target: "worker", "Worker processing incoming fetch for {remote} on stream {stream}..");

                let timeout = channels.timeout();
                let (mut stream_r, stream_w) = channels.split();

                let mut iter = gix_packetline::blocking_io::StreamingPeekableIter::new(
                    &mut stream_r,
                    &[gix_packetline::PacketLineRef::Flush],
                    false, /* packet tracing */
                );

                let header = match iter.read_line() {
                    None => {
                        return FetchResult::Responder {
                            rid: None,
                            result: Err(UploadError::PacketLine(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "unexpected end of stream while reading upload-pack header",
                            ))),
                        };
                    }
                    Some(Err(e)) => {
                        return FetchResult::Responder {
                            rid: None,
                            result: Err(UploadError::PacketLine(e)),
                        };
                    }
                    Some(Ok(Err(e))) => {
                        return FetchResult::Responder {
                            rid: None,
                            result: Err(UploadError::PacketLine(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("invalid upload-pack header: {e}"),
                            ))),
                        };
                    }
                    Some(Ok(Ok(header))) => header,
                };

                let Some(header) = upload_pack::GitRequest::from_packetline(header) else {
                    return FetchResult::Responder {
                        rid: None,
                        result: Err(UploadError::PacketLine(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "failed to parse upload-pack header",
                        ))),
                    };
                };

                log::debug!(target: "worker", "Spawning upload-pack process for {} on stream {stream}..", header.repo);

                // The repository gate's pass, held until the upload is done: a
                // close to a state that doesn't serve waits for it.
                let Some(_pass) = self.repositories.admit(header.repo, Purpose::Serve) else {
                    let state = self.repositories.state(&header.repo);
                    return FetchResult::Responder {
                        rid: Some(header.repo),
                        result: Err(AuthorizationError::Gated(header.repo, state).into()),
                    };
                };
                if let Err(e) = self.is_authorized(remote, header.repo) {
                    return FetchResult::Responder {
                        rid: Some(header.repo),
                        result: Err(e.into()),
                    };
                }
                #[cfg(test)]
                seams::at(seams::Point::Serve, header.repo);

                // Serve the fetch in-process when built for no-spawn hosts,
                // otherwise spawn `git upload-pack` as before.
                #[cfg(feature = "serve-in-process")]
                let result = {
                    let _ = (&self.nid, timeout); // used only by the spawned path
                    upload_pack_inproc::upload_pack(
                        remote,
                        &self.storage,
                        &emitter,
                        &header,
                        stream_r,
                        stream_w,
                    )
                    .map_err(UploadError::UploadPack)
                };
                #[cfg(not(feature = "serve-in-process"))]
                let result = upload_pack::upload_pack(
                    &self.nid,
                    remote,
                    &self.storage,
                    &emitter,
                    &header,
                    stream_r,
                    stream_w,
                    timeout,
                )
                .map(drop)
                .map_err(UploadError::UploadPack);
                log::debug!(target: "worker", "Upload process on stream {stream} exited with result {result:?}");

                FetchResult::Responder {
                    rid: Some(header.repo),
                    result,
                }
            }
        }
    }

    fn is_authorized(&self, remote: NodeId, rid: RepoId) -> Result<(), AuthorizationError> {
        let policy = self.policies.seed_policy(&rid)?.policy;
        // Check policy first, since if we're blocking then we likely don't have
        // the repository.
        if policy.is_block() {
            return Err(AuthorizationError::Unauthorized(remote, rid));
        }
        let repo = self.storage.repository(rid)?;
        let doc = repo.identity_doc()?;

        if !doc.is_visible_to(&remote.into()) {
            Err(AuthorizationError::Unauthorized(remote, rid))
        } else {
            Ok(())
        }
    }

    fn fetch(
        &mut self,
        rid: RepoId,
        remote: NodeId,
        refs_at: Option<Vec<RefsAt>>,
        fetch_config: ::fetch::Config,
        channels: channels::ChannelsFlush,
        notifs: notifications::StoreWriter,
    ) -> Result<protocol::worker::fetch::FetchResult, FetchError> {
        // The repository gate's pass, held until the fetch and its cache
        // update are done: closing the repository waits for it.
        let Some(_pass) = self.repositories.enter(rid) else {
            return Err(FetchError::Closed {
                rid,
                state: self.repositories.state(&rid),
            });
        };
        #[cfg(test)]
        seams::at(seams::Point::Fetch, rid);
        let FetchConfig { local, expiry } = &self.fetch_config;
        // N.b. if the `rid` is blocked this will return an error, so
        // we won't continue with any further set up of the fetch.
        let allowed = ::fetch::Allowed::from_config(rid, &self.policies)?;
        let blocked = ::fetch::BlockList::from_config(&self.policies)?;

        let mut cache = self.cache.clone();
        let handle = fetch::Handle::new(
            rid,
            *local,
            &self.storage,
            allowed,
            blocked,
            channels,
            notifs,
        )?;
        let result = handle.fetch(
            rid,
            &self.storage,
            &mut cache,
            &mut self.db,
            fetch_config,
            remote,
            refs_at,
        )?;

        if let Err(e) = garbage::collect(&self.storage, &rid, expiry) {
            // N.b. ensure that `git gc` works in debug mode.
            debug_assert!(false, "`git gc` failed: {e}");

            log::debug!(target: "worker", "Failed to run `git gc`: {e}");
        }
        Ok(result)
    }
}

/// A pool of workers. One thread is allocated for each worker.
pub struct Pool {
    pool: Vec<std::thread::JoinHandle<Result<(), chan::RecvError>>>,
}

impl Pool {
    /// Create a new worker pool with the given parameters.
    pub fn with(
        tasks: chan::Receiver<Task>,
        nid: NodeId,
        handle: Handle,
        notifications: notifications::StoreWriter,
        cache: cob::cache::StoreWriter,
        db: radicle::node::Database,
        config: Config,
    ) -> Result<Self, policy::Error> {
        // Every worker's store is opened before any worker starts: a pool
        // that can't be made has no thread left behind.
        let policies = (0..config.capacity)
            .map(|_| {
                policy::Store::reader(&config.policies_db)
                    .map(|store| policy::Config::new(config.policy, store))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut pool = Vec::with_capacity(config.capacity);
        for (i, policies) in policies.into_iter().enumerate() {
            let worker = Worker {
                nid,
                tasks: tasks.clone(),
                handle: handle.clone(),
                storage: config.storage.clone(),
                fetch_config: config.fetch.clone(),
                policies,
                notifications: notifications.clone(),
                cache: cache.clone(),
                db: db.clone(),
                repositories: config.repositories.clone(),
            };
            let thread = thread::spawn(&nid, format!("worker#{i}"), || worker.run());

            pool.push(thread);
        }
        Ok(Self { pool })
    }

    /// Joins every worker, one that panicked or not: blocks until all have
    /// exited, and then returns the first panic, if one did. A worker exits
    /// once its queue closes, which the reactor's end does, or once it
    /// panics. The pool keeps the workers not yet joined.
    pub fn join(&mut self) -> std::thread::Result<()> {
        let mut joined = Ok(());
        let mut i = 0;
        while !self.pool.is_empty() {
            let worker = self.pool.remove(0);
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => log::trace!(target: "pool", "Worker {i} exited: {err}"),
                Err(panic) => {
                    log::error!(target: "pool", "Worker {i} panicked: {}", panic_message(&*panic));
                    if joined.is_ok() {
                        joined = Err(panic);
                    }
                }
            }
            i += 1;
        }
        log::debug!(target: "pool", "Worker pool shutting down..");

        joined
    }
}

/// A panic's message, if it has one.
pub(crate) fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(no message)")
}

/// Makes every worker panic as it starts, for a test that runs in a process
/// of its own.
#[cfg(test)]
pub(crate) static PANIC_ON_START: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Test-only seams: work held, with its gate pass, until a test releases it,
/// per point and repository.
#[cfg(test)]
pub(crate) mod seams {
    use std::collections::HashMap;
    use std::sync::{Condvar, LazyLock, Mutex};

    use radicle::identity::RepoId;

    /// Where work is held.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Point {
        /// A fetch, with its pass, before it begins.
        Fetch,
        /// An upload, with its pass, once it is authorized and before it
        /// opens the repository.
        Serve,
    }

    #[derive(Default)]
    struct Seams {
        /// Work that waits, holding its pass.
        held: HashMap<(Point, RepoId), bool>,
        /// Work waiting now.
        waiting: HashMap<(Point, RepoId), bool>,
    }

    static SEAMS: LazyLock<(Mutex<Seams>, Condvar)> = LazyLock::new(Default::default);

    /// Work at `point` on `rid` waits with its pass, until [`release`].
    pub fn hold(point: Point, rid: RepoId) {
        SEAMS.0.lock().unwrap().held.insert((point, rid), true);
    }

    pub fn release(point: Point, rid: RepoId) {
        SEAMS.0.lock().unwrap().held.insert((point, rid), false);
        SEAMS.1.notify_all();
    }

    /// Whether work at `point` on `rid` waits now, with its pass.
    pub fn waiting(point: Point, rid: RepoId) -> bool {
        SEAMS
            .0
            .lock()
            .unwrap()
            .waiting
            .get(&(point, rid))
            .copied()
            .unwrap_or(false)
    }

    pub(super) fn at(point: Point, rid: RepoId) {
        let mut seams = SEAMS.0.lock().unwrap();
        while seams.held.get(&(point, rid)).copied().unwrap_or(false) {
            seams.waiting.insert((point, rid), true);
            seams = SEAMS.1.wait(seams).unwrap();
        }
        seams.waiting.insert((point, rid), false);
    }
}
