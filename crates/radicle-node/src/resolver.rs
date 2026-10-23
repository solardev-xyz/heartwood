//! The node's name resolvers: a fixed pool of threads, with a bounded queue in
//! front of it, so that resolving names can neither block the reactor nor
//! grow without bound.
//!
//! A worker holds its place until its resolver call really returns, whether or
//! not the dial waiting for it has given up. A job whose dial has given up
//! before a worker takes it isn't resolved at all.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use std::{io, net, thread};

use crossbeam_channel as chan;
use radicle::node::dial::Gate;

use crate::reactor::Controller;
use crate::wire::Control;

/// A name to resolve, for the dial waiting on resolution `id`.
#[derive(Debug)]
pub(crate) struct Job {
    pub id: u64,
    pub host: String,
    pub port: u16,
    /// When the dial gives up: `None` for a timeout too large to add to the
    /// current time.
    pub deadline: Option<Instant>,
    /// Who has it: no one yet, a worker, or the reactor, which expired it.
    pub claim: Arc<Claim>,
}

/// Where a job stands. A worker taking it and the reactor expiring it are
/// mutually exclusive: each is a compare-and-exchange from queued, and the
/// one that loses backs off.
#[derive(Debug, Default)]
pub(crate) struct Claim {
    state: AtomicU8,
    finished: OnceLock<Instant>,
}

impl Claim {
    const QUEUED: u8 = 0;
    const TAKEN: u8 = 1;
    const FINISHED: u8 = 2;
    const EXPIRED: u8 = 3;

    /// A worker's claim, after it checked the deadline: whether it may
    /// resolve the name. Once the reactor has expired the job, it may not.
    pub fn take(&self) -> bool {
        self.state
            .compare_exchange(
                Self::QUEUED,
                Self::TAKEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// The worker's lookup finished `at`.
    pub fn finish(&self, at: Instant) {
        self.finished.set(at).ok();
        self.state.store(Self::FINISHED, Ordering::Release);
    }

    /// The reactor's expiry of a job no worker has taken: whether it expired
    /// it. Once it has, no worker takes it.
    pub fn expire(&self) -> bool {
        self.state
            .compare_exchange(
                Self::QUEUED,
                Self::EXPIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// When its lookup finished, if it has.
    pub fn finished(&self) -> Option<Instant> {
        (self.state.load(Ordering::Acquire) == Self::FINISHED)
            .then(|| self.finished.get().copied())
            .flatten()
    }
}

/// Where the wire queues names to resolve.
#[derive(Clone, Debug)]
pub(crate) struct Resolvers {
    jobs: chan::Sender<Job>,
}

impl Resolvers {
    /// Queues `job`, or hands it back if the queue is full.
    pub fn submit(&self, job: Job) -> Result<(), Job> {
        self.jobs.try_send(job).map_err(|e| e.into_inner())
    }

    /// A queue no worker reads, for tests that don't resolve.
    #[cfg(test)]
    pub fn closed() -> Self {
        let (jobs, _) = chan::bounded(0);
        Self { jobs }
    }
}

/// The resolver threads, for the runtime to join once the reactor has ended.
#[derive(Debug)]
pub(crate) struct Workers(Vec<thread::JoinHandle<()>>);

impl Workers {
    /// Waits up to `limit` for the workers to end. They end once the wire is
    /// gone (the queue closes) and their current call returns. A worker still
    /// in a resolver call past `limit` is left to end on its own, and logged.
    pub fn join_within(self, limit: Duration) {
        let deadline = Instant::now() + limit;
        let mut left = self.0;
        while !left.is_empty() && Instant::now() < deadline {
            let (done, running): (Vec<_>, Vec<_>) =
                left.into_iter().partition(|worker| worker.is_finished());
            for worker in done {
                if worker.join().is_err() {
                    log::error!(target: "wire", "A resolver thread panicked");
                }
            }
            left = running;
            if !left.is_empty() {
                thread::sleep(Duration::from_millis(10));
            }
        }
        if !left.is_empty() {
            log::warn!(
                target: "wire",
                "{} resolver thread(s) still in a resolver call; leaving them to end on their own",
                left.len()
            );
        }
    }
}

/// Starts `threads` workers, resolving through `gate` the jobs of a queue
/// that holds at most `queue`, and handing their answers back to the
/// reactor through `controller`.
pub(crate) fn spawn(
    gate: Arc<dyn Gate>,
    controller: Controller,
    threads: usize,
    queue: usize,
) -> io::Result<(Resolvers, Workers)> {
    let (jobs, queued) = chan::bounded::<Job>(queue);
    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads.max(1) {
        let (queued, gate, controller) = (queued.clone(), gate.clone(), controller.clone());
        let worker = thread::Builder::new()
            .name("resolver".to_owned())
            .spawn(move || work(queued, gate.as_ref(), controller))?;
        workers.push(worker);
    }
    Ok((Resolvers { jobs }, Workers(workers)))
}

/// A worker's loop: until the queue closes.
fn work(queued: chan::Receiver<Job>, gate: &dyn Gate, controller: Controller) {
    for job in queued.iter() {
        // Its dial gave up while it waited: nothing to resolve it for.
        if job
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            continue;
        }
        #[cfg(test)]
        seams::at(seams::Point::Claim, &job.host);
        // The reactor expired it while we checked: it isn't ours to resolve.
        let taken = job.claim.take();
        #[cfg(test)]
        seams::claimed(&job.host, taken);
        if !taken {
            continue;
        }
        let answers: io::Result<Vec<net::SocketAddr>> = gate.resolve(&job.host, job.port);
        let finished = Instant::now();
        job.claim.finish(finished);
        #[cfg(test)]
        seams::at(seams::Point::Answer, &job.host);
        // The reactor may have stopped: nothing to tell then.
        controller
            .cmd(Control::Resolved {
                id: job.id,
                answers,
                finished,
            })
            .ok();
    }
}

/// Test-only seams in a worker's loop, per host: a pause at a point of the
/// loop, and a record of each claim's outcome.
#[cfg(test)]
pub(crate) mod seams {
    use std::collections::HashMap;
    use std::sync::{Condvar, LazyLock, Mutex};

    /// Where a worker may be held.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Point {
        /// Between its deadline check and its claim.
        Claim,
        /// Between its lookup's finish and its answer to the reactor.
        Answer,
    }

    #[derive(Default)]
    struct Seams {
        /// Points at which workers given a host wait, until released.
        paused: HashMap<(Point, String), bool>,
        /// Points at which a worker waits now.
        waiting: HashMap<(Point, String), bool>,
        /// Hosts' claims: whether the worker took the job.
        claims: HashMap<String, bool>,
    }

    static SEAMS: LazyLock<(Mutex<Seams>, Condvar)> = LazyLock::new(Default::default);

    /// Workers given `host` wait at `point`, until [`release`].
    pub fn pause(point: Point, host: &str) {
        SEAMS
            .0
            .lock()
            .unwrap()
            .paused
            .insert((point, host.to_owned()), true);
    }

    pub fn release(point: Point, host: &str) {
        SEAMS
            .0
            .lock()
            .unwrap()
            .paused
            .insert((point, host.to_owned()), false);
        SEAMS.1.notify_all();
    }

    /// Whether a worker waits at `point` with `host`.
    pub fn waiting(point: Point, host: &str) -> bool {
        SEAMS
            .0
            .lock()
            .unwrap()
            .waiting
            .get(&(point, host.to_owned()))
            .copied()
            .unwrap_or(false)
    }

    /// Whether a worker has claimed `host`, once one has tried.
    pub fn claim(host: &str) -> Option<bool> {
        SEAMS.0.lock().unwrap().claims.get(host).copied()
    }

    pub(super) fn at(point: Point, host: &str) {
        let key = (point, host.to_owned());
        let mut seams = SEAMS.0.lock().unwrap();
        while seams.paused.get(&key).copied().unwrap_or(false) {
            seams.waiting.insert(key.clone(), true);
            seams = SEAMS.1.wait(seams).unwrap();
        }
        seams.waiting.insert(key, false);
    }

    pub(super) fn claimed(host: &str, taken: bool) {
        SEAMS
            .0
            .lock()
            .unwrap()
            .claims
            .insert(host.to_owned(), taken);
    }
}
