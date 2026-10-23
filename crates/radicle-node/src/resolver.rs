//! The node's name resolvers: a fixed pool of threads, with a bounded queue in
//! front of it, so that resolving names can neither block the reactor nor
//! grow without bound.
//!
//! A worker holds its place until its resolver call really returns, whether or
//! not the dial waiting for it has given up. A job whose dial has given up
//! before a worker takes it isn't resolved at all.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Set once a worker has taken it to resolve: a dial that gives up before
    /// then failed for want of a free worker, not for its name.
    pub taken: Arc<AtomicBool>,
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
        job.taken.store(true, Ordering::Release);
        let answers: io::Result<Vec<net::SocketAddr>> = gate.resolve(&job.host, job.port);
        // The reactor may have stopped: nothing to tell then.
        controller
            .cmd(Control::Resolved {
                id: job.id,
                answers,
            })
            .ok();
    }
}
