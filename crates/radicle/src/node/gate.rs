//! The repository gate: per repository, whether the node may fetch it,
//! update its COB cache, announce it and serve it.
//!
//! The host sets each repository's state, and the node consults it. A
//! repository the host hasn't named is open. While a repository is being
//! repaired, or once it is quarantined, the node leaves it alone as its
//! [`RepoState`] says; the host repairs it with nothing of the node's
//! mutating it underneath, since closing waits for the node's mutations of
//! it already under way ([`Pass`]).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::prelude::RepoId;

/// Why a quarantined repository is quarantined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Quarantine {
    /// A COB, or the cache, can't be rebuilt. Its git data and the node's
    /// namespace are intact, so it is still announced and served.
    Cache,
    /// A namespace in it doesn't verify. It is neither announced nor served.
    Namespace,
}

/// A repository's state at the gate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RepoState {
    /// The node fetches it, updates its cache, announces and serves it.
    #[default]
    Open,
    /// The host is repairing it. Its fetches and refs announcements wait
    /// until it opens again; it is served.
    Repairing,
    /// The host couldn't repair it. Its fetches are refused. Quarantined for
    /// its cache, it is still announced and served; for a namespace, it is
    /// neither.
    Quarantined(Quarantine),
}

/// What a [`Pass`] admits: closing a repository waits for the passes its new
/// state no longer lets through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// One of the node's mutations of it: a fetch with its cache update, or
    /// a migration of its signed refs. Only while it is open.
    Mutate,
    /// Serving it to a peer, while its state serves.
    Serve,
    /// Announcing its refs, while its state announces.
    Announce,
}

impl RepoState {
    /// Whether it lets a pass for `purpose` through.
    pub fn permits(&self, purpose: Purpose) -> bool {
        match purpose {
            Purpose::Mutate => self.fetches(),
            Purpose::Serve => self.serves(),
            Purpose::Announce => self.announces(),
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Whether the node may fetch it, and update its cache.
    pub fn fetches(&self) -> bool {
        self.is_open()
    }

    /// Whether the node announces its refs now.
    pub fn announces(&self) -> bool {
        matches!(self, Self::Open | Self::Quarantined(Quarantine::Cache))
    }

    /// Whether it is in the node's inventory.
    pub fn inventoried(&self) -> bool {
        !matches!(self, Self::Quarantined(Quarantine::Namespace))
    }

    /// Whether the node serves it to peers.
    pub fn serves(&self) -> bool {
        !matches!(self, Self::Quarantined(Quarantine::Namespace))
    }
}

impl fmt::Display for RepoState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => f.write_str("open"),
            Self::Repairing => f.write_str("being repaired"),
            Self::Quarantined(Quarantine::Cache) => f.write_str("quarantined (cache)"),
            Self::Quarantined(Quarantine::Namespace) => f.write_str("quarantined (namespace)"),
        }
    }
}

/// The node's work on a repository still under way, that its new state
/// doesn't let through, when the gate was asked to close it: the host can't
/// count on the new state yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{rid} still has {passes} operation(s) under way")]
pub struct Busy {
    pub rid: RepoId,
    pub passes: usize,
}

type Listener = Box<dyn Fn(RepoId, RepoState) + Send + Sync>;

#[derive(Default)]
struct Repositories {
    states: HashMap<RepoId, RepoState>,
    /// The passes held, per repository and purpose.
    passes: HashMap<(RepoId, Purpose), usize>,
}

#[derive(Default)]
struct Inner {
    repositories: Mutex<Repositories>,
    /// Notified when a pass is dropped.
    released: Condvar,
    /// Told of every change of state, after it is made.
    listener: Mutex<Option<Listener>>,
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Repositories> {
        self.repositories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// The repository gate, shared by the host and the node. Clones share it.
#[derive(Clone, Default)]
pub struct RepoGate {
    inner: Arc<Inner>,
}

impl fmt::Debug for RepoGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepoGate").finish()
    }
}

impl RepoGate {
    /// A gate with every repository open.
    pub fn new() -> Self {
        Self::default()
    }

    /// The state of `rid`.
    pub fn state(&self, rid: &RepoId) -> RepoState {
        self.inner
            .lock()
            .states
            .get(rid)
            .copied()
            .unwrap_or_default()
    }

    /// A pass for one of the node's mutations of `rid`: a fetch, with its
    /// cache update. `None` unless `rid` is open.
    pub fn enter(&self, rid: RepoId) -> Option<Pass> {
        self.admit(rid, Purpose::Mutate)
    }

    /// A pass for `purpose` on `rid`, held for as long as the work it admits
    /// runs: `None` unless `rid`'s state lets it through. The check and the
    /// work it admits are one, as far as [`RepoGate::close`] can tell: a
    /// close waits for the passes its state doesn't let through.
    pub fn admit(&self, rid: RepoId, purpose: Purpose) -> Option<Pass> {
        let mut repositories = self.inner.lock();
        if !repositories
            .states
            .get(&rid)
            .copied()
            .unwrap_or_default()
            .permits(purpose)
        {
            return None;
        }
        *repositories.passes.entry((rid, purpose)).or_default() += 1;
        Some(Pass {
            inner: self.inner.clone(),
            rid,
            purpose,
        })
    }

    /// Closes `rid` with `state`, being repaired or quarantined: from now on,
    /// it lets through only the passes `state` permits. Then waits, up to
    /// `timeout`, for the passes already held that `state` doesn't permit to
    /// drop: `Busy` if some are still held. Either way, `rid` stays closed.
    pub fn close(&self, rid: RepoId, state: RepoState, timeout: Duration) -> Result<(), Busy> {
        let deadline = Instant::now() + timeout;
        {
            let mut repositories = self.inner.lock();
            repositories.states.insert(rid, state);
            loop {
                let passes = repositories
                    .passes
                    .iter()
                    .filter(|((r, purpose), _)| *r == rid && !state.permits(*purpose))
                    .map(|(_, passes)| passes)
                    .sum::<usize>();
                if passes == 0 {
                    break;
                }
                let now = Instant::now();
                if now >= deadline {
                    drop(repositories);
                    self.changed(rid, state);
                    return Err(Busy { rid, passes });
                }
                repositories = self
                    .inner
                    .released
                    .wait_timeout(repositories, deadline - now)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        }
        self.changed(rid, state);
        Ok(())
    }

    /// Opens `rid`: the node runs the fetches and refs announcements of it
    /// that waited.
    pub fn open(&self, rid: RepoId) {
        self.inner.lock().states.remove(&rid);
        self.changed(rid, RepoState::Open);
    }

    /// Tells `listener` of every change of state from now on, after it is
    /// made: the node's, which it hands to its reactor. It replaces any
    /// listener before it.
    pub fn listen(&self, listener: impl Fn(RepoId, RepoState) + Send + Sync + 'static) {
        *self
            .inner
            .listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(listener));
    }

    fn changed(&self, rid: RepoId, state: RepoState) {
        if let Some(listener) = self
            .inner
            .listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            listener(rid, state);
        }
    }
}

/// Work on a repository under way, admitted for its purpose: closing the
/// repository to a state that doesn't permit it waits for it to drop.
pub struct Pass {
    inner: Arc<Inner>,
    rid: RepoId,
    purpose: Purpose,
}

impl fmt::Debug for Pass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pass")
            .field("rid", &self.rid)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        let mut repositories = self.inner.lock();
        let key = (self.rid, self.purpose);
        if let Some(passes) = repositories.passes.get_mut(&key) {
            *passes = passes.saturating_sub(1);
            if *passes == 0 {
                repositories.passes.remove(&key);
            }
        }
        drop(repositories);
        self.inner.released.notify_all();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::sync::mpsc;
    use std::thread;

    use super::*;
    use crate::test::arbitrary;

    #[test]
    fn a_repository_is_open_until_the_host_closes_it() {
        let gate = RepoGate::new();
        let (rid, other) = (arbitrary::r#gen::<RepoId>(1), arbitrary::r#gen::<RepoId>(1));
        assert_eq!(gate.state(&rid), RepoState::Open);
        assert!(gate.enter(rid).is_some());

        gate.close(rid, RepoState::Repairing, Duration::ZERO)
            .unwrap();
        assert_eq!(gate.state(&rid), RepoState::Repairing);
        assert!(gate.enter(rid).is_none());
        // Other repositories stay open.
        assert!(gate.enter(other).is_some());

        gate.close(
            rid,
            RepoState::Quarantined(Quarantine::Namespace),
            Duration::ZERO,
        )
        .unwrap();
        assert!(gate.enter(rid).is_none());
        gate.open(rid);
        assert_eq!(gate.state(&rid), RepoState::Open);
        assert!(gate.enter(rid).is_some());
    }

    #[test]
    fn what_each_state_lets_through() {
        let cases = [
            (RepoState::Open, [true, true, true, true]),
            (RepoState::Repairing, [false, false, true, true]),
            (
                RepoState::Quarantined(Quarantine::Cache),
                [false, true, true, true],
            ),
            (
                RepoState::Quarantined(Quarantine::Namespace),
                [false, false, false, false],
            ),
        ];
        for (state, [fetches, announces, inventoried, serves]) in cases {
            assert_eq!(state.fetches(), fetches, "{state}");
            assert_eq!(state.announces(), announces, "{state}");
            assert_eq!(state.inventoried(), inventoried, "{state}");
            assert_eq!(state.serves(), serves, "{state}");
        }
    }

    #[test]
    fn closing_waits_for_the_mutations_under_way() {
        let gate = RepoGate::new();
        let rid = arbitrary::r#gen::<RepoId>(1);
        let pass = gate.enter(rid).unwrap();
        let second = gate.enter(rid).unwrap();

        // Not within its timeout: busy, and closed all the same.
        assert_eq!(
            gate.close(rid, RepoState::Repairing, Duration::from_millis(50)),
            Err(Busy { rid, passes: 2 })
        );
        assert!(gate.enter(rid).is_none());
        drop(second);

        // Once the last pass drops, a close waiting for it returns.
        let (done, closed) = mpsc::channel();
        let closing = {
            let gate = gate.clone();
            thread::spawn(move || {
                let result = gate.close(rid, RepoState::Repairing, Duration::from_secs(10));
                done.send(()).unwrap();
                result
            })
        };
        assert!(closed.recv_timeout(Duration::from_millis(100)).is_err());
        drop(pass);
        closed.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(closing.join().unwrap(), Ok(()));
    }

    #[test]
    fn the_listener_hears_every_change() {
        let gate = RepoGate::new();
        let rid = arbitrary::r#gen::<RepoId>(1);
        let (tx, rx) = mpsc::channel();
        gate.listen(move |rid, state| tx.send((rid, state)).unwrap());
        gate.close(rid, RepoState::Repairing, Duration::ZERO)
            .unwrap();
        gate.open(rid);
        let quarantined = RepoState::Quarantined(Quarantine::Cache);
        gate.close(rid, quarantined, Duration::ZERO).unwrap();
        assert_eq!(
            rx.try_iter().collect::<Vec<_>>(),
            [
                (rid, RepoState::Repairing),
                (rid, RepoState::Open),
                (rid, quarantined)
            ]
        );
    }

    // Review of heartwood #7, round 1: serving and announcing are fenced like
    // mutations, each by the states that don't let them through. A close
    // waits for exactly those passes.
    #[test]
    fn closing_waits_for_the_passes_its_state_doesn_t_let_through() {
        let gate = RepoGate::new();
        let rid = arbitrary::r#gen::<RepoId>(1);
        let serve = gate.admit(rid, Purpose::Serve).unwrap();
        let announce = gate.admit(rid, Purpose::Announce).unwrap();
        let zero = Duration::ZERO;

        // Quarantined for its cache, it is still served and announced.
        let cache = RepoState::Quarantined(Quarantine::Cache);
        assert_eq!(gate.close(rid, cache, zero), Ok(()));
        assert!(gate.admit(rid, Purpose::Serve).is_some());
        assert!(gate.admit(rid, Purpose::Announce).is_some());
        assert!(gate.admit(rid, Purpose::Mutate).is_none());
        // Being repaired, it is served, but not announced.
        assert_eq!(
            gate.close(rid, RepoState::Repairing, zero),
            Err(Busy { rid, passes: 1 })
        );
        assert!(gate.admit(rid, Purpose::Serve).is_some());
        assert!(gate.admit(rid, Purpose::Announce).is_none());
        drop(announce);
        assert_eq!(gate.close(rid, RepoState::Repairing, zero), Ok(()));
        // Quarantined for a namespace, it is neither.
        let namespace = RepoState::Quarantined(Quarantine::Namespace);
        assert_eq!(
            gate.close(rid, namespace, zero),
            Err(Busy { rid, passes: 1 })
        );
        assert!(gate.admit(rid, Purpose::Serve).is_none());
        drop(serve);
        assert_eq!(gate.close(rid, namespace, zero), Ok(()));
    }
}
