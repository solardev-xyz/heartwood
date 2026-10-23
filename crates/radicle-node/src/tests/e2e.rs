use std::{collections::HashSet, thread, time};

use radicle::cob;
use radicle::cob::Title;
use radicle::cob::store::access::{ReadOnly, WriteAs};
use radicle::crypto::{Signer as _, SigningKey};
use radicle::git::fmt::Component;
use test_log::test;

use radicle::git::raw::ErrorExt as _;
use radicle::node::Event;
use radicle::node::policy::Scope;
use radicle::node::{Alias, ConnectResult, DEFAULT_TIMEOUT, FetchResult, Handle as _};
use radicle::storage::{
    ReadRepository, ReadStorage, RefUpdate, RemoteRepository, SignRepository, ValidateRepository,
    WriteRepository, WriteStorage,
};
use radicle::test::fixtures;
use radicle::{assert_matches, rad};
use radicle::{git, issue};

use crate::test::node::{Node, NodeHandle, converge};
use protocol::service;
use radicle::node::config::Limits;
use radicle::node::{Config, ConnectOptions};
use radicle::storage::git::transport;

mod config {
    use super::*;
    use radicle::node::config::{Config, Relay};

    /// Relay node config.
    pub fn relay(alias: &'static str) -> Config {
        Config {
            relay: Relay::Always,
            ..Config::test(Alias::new(alias))
        }
    }

    /// Get the scale or "test size". This is used to scale tests with more
    /// data. Defaults to `1`.
    pub fn scale() -> usize {
        std::env::var("RAD_TEST_SCALE")
            .map(|s| {
                s.parse()
                    .expect("repository: invalid value for `RAD_TEST_SCALE`")
            })
            .unwrap_or(1)
    }
}

#[test]
//
//     alice -- bob
//
fn test_inventory_sync_basic() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);

    alice.project("alice", "");
    bob.project("bob", "");

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);

    let routes = converge([&alice, &bob]);
    assert_eq!(routes.len(), 2);
}

#[test]
//
//     alice -- bob, bob with no control socket
//
fn test_node_without_control_socket() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);

    alice.project("alice", "");
    bob.project("bob", "");

    let socket = bob.home.socket_default();
    let mut alice = alice.spawn();
    let bob = bob.spawn_without_control_socket();

    // Nothing listens for control commands on bob's home.
    assert!(!socket.exists());

    // Its handle controls it, and it syncs as any node does.
    alice.connect(&bob);
    let routes = converge([&alice, &bob]);
    assert_eq!(routes.len(), 2);

    // And it shuts down through its handle alone: dropping the handle shuts
    // the node down and joins its thread.
    bob.shutdown();
    assert!(!socket.exists());
}

/// A node with no control socket, run by a host that keeps its signal
/// sender, as an embedding host does.
fn run_with_signals(
    path: &std::path::Path,
) -> (
    std::sync::mpsc::Sender<radicle_signals::Signal>,
    std::net::SocketAddr,
    crate::runtime::handle::Handle,
    thread::JoinHandle<Result<(), crate::runtime::Error>>,
) {
    let node = Node::init(path, config::relay("alice"), 139);
    let (signals, receiver) = std::sync::mpsc::channel();
    let runtime = crate::runtime::Runtime::init(
        node.home.clone(),
        node.config,
        None,
        vec![([127, 0, 0, 1], 0).into()],
        receiver,
        node.secret_key,
        std::sync::Arc::new(radicle::node::dial::Open),
    )
    .unwrap();
    assert!(runtime.control.is_none());
    let address = runtime.local_addrs[0];
    let handle = runtime.handle.clone();
    (
        signals,
        address,
        handle,
        thread::spawn(move || runtime.run()),
    )
}

#[test]
// Review of heartwood #1, round 1: the node's shutdown joins its signal
// watcher even while the host still holds the signal sender.
fn test_node_without_control_socket_joins_its_signal_watcher() {
    let tmp = tempfile::tempdir().unwrap();
    let (signals, address, handle, running) = run_with_signals(tmp.path());

    handle.shutdown().unwrap();
    running.join().unwrap().unwrap();

    // The watcher has ended, and dropped its receiver.
    assert!(
        signals.send(radicle_signals::Signal::Hangup).is_err(),
        "shutdown returned with its signal watcher still alive"
    );
    assert!(
        std::net::TcpStream::connect_timeout(&address, time::Duration::from_millis(200)).is_err()
    );
}

#[test]
// Review of heartwood #1, round 2: a stream of ignored signals doesn't keep
// the watcher from ending once the node has stopped.
fn test_node_without_control_socket_stops_while_signals_keep_coming() {
    let tmp = tempfile::tempdir().unwrap();
    let (signals, _, handle, running) = run_with_signals(tmp.path());
    let producing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let producer = thread::spawn({
        let producing = producing.clone();
        move || {
            while producing.load(std::sync::atomic::Ordering::SeqCst) {
                signals.send(radicle_signals::Signal::WindowChanged).ok();
                thread::sleep(time::Duration::from_millis(1));
            }
        }
    });

    handle.shutdown().unwrap();
    let deadline = time::Instant::now() + time::Duration::from_secs(5);
    while !running.is_finished() && time::Instant::now() < deadline {
        thread::sleep(time::Duration::from_millis(20));
    }
    let finished = running.is_finished();
    producing.store(false, std::sync::atomic::Ordering::SeqCst);
    producer.join().unwrap();
    assert!(
        finished,
        "ignored signals kept the node's run from returning"
    );
    running.join().unwrap().unwrap();
}

#[test]
// While the node runs, its signals act as before: a hangup is ignored, and a
// termination stops it.
fn test_node_without_control_socket_stops_on_a_termination_signal() {
    let tmp = tempfile::tempdir().unwrap();
    let (signals, _, _handle, running) = run_with_signals(tmp.path());

    signals.send(radicle_signals::Signal::Hangup).unwrap();
    thread::sleep(time::Duration::from_millis(600));
    assert!(!running.is_finished(), "a hangup stopped the node");

    signals.send(radicle_signals::Signal::Terminate).unwrap();
    let deadline = time::Instant::now() + time::Duration::from_secs(10);
    while !running.is_finished() {
        assert!(
            time::Instant::now() < deadline,
            "the node didn't stop on its signal"
        );
        thread::sleep(time::Duration::from_millis(20));
    }
    running.join().unwrap().unwrap();
}

#[test]
//
//     alice -- bob -- eve
//
fn test_inventory_sync_bridge() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let mut eve = Node::init(tmp.path(), config::relay("eve"), 42);

    alice.project("alice", "");
    bob.project("bob", "");
    eve.project("eve", "");

    let mut alice = alice.spawn();
    let mut eve = eve.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);
    eve.connect(&bob);

    let routes = converge([&alice, &bob, &eve]);
    assert_eq!(routes.len(), 3);
}

#[test]
//
//     alice -- bob
//       |       |
//     carol -- eve
//
fn test_inventory_sync_ring() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let mut eve = Node::init(tmp.path(), config::relay("eve"), 42);
    let mut carol = Node::init(tmp.path(), Config::test(Alias::new("carol")), 73);

    alice.project("alice", "");
    bob.project("bob", "");
    eve.project("eve", "");
    carol.project("carol", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut eve = eve.spawn();
    let mut carol = carol.spawn();

    alice.connect(&bob);
    bob.connect(&eve);
    eve.connect(&carol);
    carol.connect(&alice);

    let routes = converge([&alice, &bob, &eve, &carol]);
    assert_eq!(routes.len(), 4);
}

#[test]
//
//             dave
//              |
//     eve -- alice -- bob
//              |
//            carol
//
fn test_inventory_sync_star() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let mut eve = Node::init(tmp.path(), config::relay("eve"), 42);
    let mut carol = Node::init(tmp.path(), Config::test(Alias::new("carol")), 73);
    let mut dave = Node::init(tmp.path(), Config::test(Alias::new("dave")), 91);

    alice.project("alice", "");
    bob.project("bob", "");
    eve.project("eve", "");
    carol.project("carol", "");
    dave.project("dave", "");

    let alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut eve = eve.spawn();
    let mut carol = carol.spawn();
    let mut dave = dave.spawn();

    bob.connect(&alice);
    eve.connect(&alice);
    carol.connect(&alice);
    dave.connect(&alice);

    let routes = converge([&alice, &bob, &eve, &carol, &dave]);
    assert_eq!(routes.len(), 5);
}

#[test]
fn test_replication() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = bob.project("acme", "");

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    let inventory = alice.storage.repositories().unwrap();
    assert!(inventory.is_empty());

    let updated = alice.handle.seed(acme, Scope::All).unwrap();
    assert!(updated);

    let seeds = alice.handle.seeds_for(acme, None).unwrap();
    assert!(seeds.is_connected(&bob.id));

    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    let updated = match result {
        FetchResult::Success { updated, .. } => updated,
        FetchResult::Failed { reason } => {
            panic!("Fetch failed from {}: {reason}", bob.id);
        }
    };
    assert!(!updated.is_empty());

    log::debug!(target: "test", "Fetch complete with {}", bob.id);

    let inventory = alice.storage.repositories().unwrap();
    let alice_repo = alice.storage.repository(acme).unwrap();
    let bob_repo = bob.storage.repository(acme).unwrap();

    let alice_refs = alice_repo
        .references()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let bob_refs = bob_repo
        .references()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(inventory.first().map(|r| r.rid), Some(acme));
    assert_eq!(alice_refs, bob_refs);
    assert_matches!(
        alice.storage.repository(acme).unwrap().validate(),
        Ok(validations) if validations.is_empty()
    );

    // Ensure that .keep files are deleted upon replication
    {
        let repo = alice.storage.repository(acme).unwrap();
        let pack_dir = repo.path().join("objects").join("pack");
        for entry in std::fs::read_dir(pack_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            assert_ne!(
                path.extension(),
                Some("keep".as_ref()),
                "found .keep file after fetch: {path:?}"
            );
        }
    }
}

/// A node built to serve fetches entirely in-process (the no-spawn / iOS
/// build) can still *publish*: it creates a repository and an issue COB, and
/// a peer fetches both — including the issue — over the network, with the
/// serving side never spawning `git upload-pack`. This is the missing half
/// of publishing from an embedded node.
#[cfg(feature = "serve-in-process")]
#[test]
fn test_in_process_serve_publishes_cob() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = bob.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let issue_id = bob.issue(
        acme,
        Title::new("Ship it").unwrap(),
        "filed from an embedded, no-spawn node",
    );

    alice.connect(&bob);
    converge([&alice, &bob]);

    alice.handle.seed(acme, Scope::All).unwrap();
    // Bob serves this fetch in-process (serve-in-process build).
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success(), "in-process fetch failed: {result:?}");

    let repo = alice.storage.repository(acme).unwrap();
    let issues = issue::Issues::open(&repo, WriteAs::new(&alice.signer)).unwrap();
    assert!(
        issues.get(&issue_id).unwrap().is_some(),
        "issue {issue_id} did not replicate from the in-process-serving node"
    );
}

#[test]
fn test_replication_ref_in_sigrefs() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let acme = bob.project("acme", "");
    // Delete one of the signed refs.
    bob.storage
        .repository_mut(acme)
        .unwrap()
        .reference(&bob.id, &git::fmt::qualified!("refs/heads/master"))
        .unwrap()
        .delete()
        .unwrap();

    let mut alice = alice.spawn();

    // At this point, bob will migrate sigrefs, because there only is a
    // root commit in his `refs/heads/sigrefs`.
    let bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    alice.handle.seed(acme, Scope::All).unwrap();
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();

    assert_matches!(result, FetchResult::Success { .. });

    // Before automatic migration of sigrefs was introduced,
    // alice would still see bob's master branch at this point and we
    // would assert `.is_ok()`.
    // With automatic migration, refs are signed as bob's node starts
    // up, which is after he removes his ref locally, thus we now
    // assert `.is_err()`.
    assert!(
        alice
            .storage
            .repository(acme)
            .unwrap()
            .reference(&bob.id, &git::fmt::qualified!("refs/heads/master"))
            .is_err(),
        "refs/namespaces/{}/refs/heads/master does not exist",
        bob.id
    );
}

#[test]
fn test_replication_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let carol = SigningKey::mock(8);
    let acme = bob.project("acme", "");
    let repo = bob.storage.repository_mut(acme).unwrap();
    let (_, head) = repo.head().unwrap();
    let id = repo.identity_head().unwrap();

    // Create some unsigned refs for Carol in Bob's storage.
    repo.raw()
        .reference(
            &git::fmt::qualified!("refs/heads/carol")
                .with_namespace(Component::from(carol.public_key())),
            head.into(),
            true,
            &String::default(),
        )
        .unwrap();
    repo.raw()
        .reference(
            &git::refs::storage::id(carol.public_key()),
            id.into(),
            true,
            &String::default(),
        )
        .unwrap();

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    alice.handle.follow(*carol.public_key(), None).unwrap();
    alice.handle.seed(acme, Scope::Followed).unwrap();
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();

    // Fetch is successful despite not fetching Carol's refs, since she isn't a delegate.
    assert!(result.is_success());

    let repo = alice.storage.repository(acme).unwrap();
    let mut remotes = repo.remote_ids().unwrap();

    assert_eq!(remotes.next().unwrap().unwrap(), bob.id);
    assert!(remotes.next().is_none());

    assert!(repo.validate().unwrap().is_empty());
}

#[test]
fn test_migrated_clone() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    let updated = bob.handle.seed(acme, Scope::All).unwrap();
    assert!(updated);

    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    log::debug!(target: "test", "Fetch complete with {}", alice.id);

    // Simulate alice deleting the project and cloning it again
    {
        let path = alice.storage.path().join(acme.canonical());
        std::fs::remove_dir_all(path).unwrap();
    }
    assert!(!alice.storage.contains(&acme).unwrap());
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    let alice_repo = alice.storage.repository(acme).unwrap();
    let bob_repo = bob.storage.repository(acme).unwrap();

    let alice_refs = alice_repo
        .references()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let bob_refs = bob_repo
        .references()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(alice_refs, bob_refs);
    assert_matches!(
        alice.storage.repository(acme).unwrap().validate(),
        Ok(validations) if validations.is_empty()
    );
}

#[test]
fn test_dont_fetch_owned_refs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    assert!(bob.handle.seed(acme, Scope::Followed).unwrap());

    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    log::debug!(target: "test", "Fetch complete with {}", bob.id);

    alice.issue(acme, Title::new("Don't fetch self").unwrap(), "Use ^");
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success())
}

#[test]
fn test_fetch_followed_remotes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = alice.project("acme", "");
    let mut signers = Vec::with_capacity(5);
    {
        for i in 0..5 {
            let signer = SigningKey::mock(i);
            rad::fork_remote(acme, &alice.id, &signer, &alice.storage).unwrap();
            signers.push(signer);
        }
    }

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    let followed = signers
        .iter()
        .map(|s| *s.public_key())
        .take(2)
        .collect::<HashSet<_>>();

    assert!(
        followed.len() < signers.len(),
        "Bob is only trusting a subset of peers"
    );
    assert!(bob.handle.seed(acme, Scope::Followed).unwrap());
    for nid in &followed {
        assert!(bob.handle.follow(*nid, None).unwrap());
    }

    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    log::debug!(target: "test", "Fetch complete with {}", bob.id);

    let bob_repo = bob.storage.repository(acme).unwrap();
    let bob_remotes = bob_repo
        .remote_ids()
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    assert_eq!(bob_remotes.len(), followed.len() + 1);
    assert!(bob_remotes.is_superset(&followed));
    assert!(bob_remotes.contains(&alice.id));
}

#[test]
fn test_missing_remote() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let carol = SigningKey::mock(98);

    alice.connect(&bob);
    converge([&alice, &bob]);

    assert!(bob.handle.seed(acme, Scope::Followed).unwrap());
    assert!(bob.handle.follow(*carol.public_key(), None).unwrap());
    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());
    log::debug!(target: "test", "Fetch complete with {}", bob.id);

    rad::fork_remote(acme, &alice.id, &carol, &bob.storage).unwrap();

    alice.issue(
        acme,
        Title::new("Missing Remote").unwrap(),
        "Fixing the missing remote issue",
    );
    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());
    log::debug!(target: "test", "Fetch complete with {}", bob.id);
}

#[test]
fn test_fetch_preserve_owned_refs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = alice.project("acme", "");
    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    assert!(bob.handle.seed(acme, Scope::Followed).unwrap());
    assert!(bob.handle.follow(alice.id, None).unwrap());

    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    log::debug!(target: "test", "Fetch complete with {}", bob.id);

    alice.issue(acme, Title::new("Bug").unwrap(), "Bugs, bugs, bugs");

    let before = alice
        .storage
        .repository(acme)
        .unwrap()
        .references_of(&alice.id)
        .unwrap();

    // Fetch shouldn't prune any of our own refs.
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    let (updated, _) = result.success().unwrap();
    assert_eq!(updated, vec![]);

    let after = alice
        .storage
        .repository(acme)
        .unwrap()
        .references_of(&alice.id)
        .unwrap();

    assert_eq!(before, after);
}

#[test]
fn test_clone() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = bob.project("acme", "");

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    transport::local::register(alice.storage.clone());

    let _ = alice.handle.seed(acme, Scope::All).unwrap();
    let seeds = alice.handle.seeds_for(acme, None).unwrap();
    assert!(seeds.is_connected(&bob.id));

    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    rad::fork(acme, &alice.signer, &alice.storage).unwrap();

    let working = rad::checkout(
        acme,
        alice.signer.public_key(),
        tmp.path().join("clone"),
        &alice.storage,
        false,
    )
    .unwrap();

    // Makes test finish faster.
    drop(alice);

    let head = working.head().unwrap();
    let oid = head.target().unwrap();

    let (_, canonical) = bob
        .storage
        .repository(acme)
        .unwrap()
        .canonical_head()
        .unwrap();

    assert_eq!(canonical, oid);

    // Make sure that bob has refs/rad/id set
    assert!(
        bob.storage
            .repository(acme)
            .unwrap()
            .identity_head()
            .is_ok()
    );
}

#[test]
fn test_fetch_up_to_date() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = bob.project("acme", "");

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    transport::local::register(alice.storage.clone());

    let _ = alice.handle.seed(acme, Scope::All).unwrap();
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    // Fetch again! This time, everything's up to date.
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert_matches!(
        result.success(),
        Some((updates, _fetched)) if updates.iter().all(|update| matches!(update, RefUpdate::Skipped { .. }))
    );
}

#[test]
fn test_fetch_unseeded() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let acme = bob.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    transport::local::register(alice.storage.clone());

    let _ = alice.handle.seed(acme, Scope::All).unwrap();
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    // Bob stops seeding the repository
    assert!(bob.handle.unseed(acme).unwrap());

    // Alice attempts to fetch but is unauthorized
    let result = alice
        .handle
        .fetch(acme, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert_matches!(result, FetchResult::Failed { .. });
}

#[test]
fn test_large_fetch() {
    let tmp = tempfile::tempdir().unwrap();
    let scale = config::scale();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let (repo, _) = fixtures::repository(tmp.path());
    fixtures::populate(&repo, scale.max(3));

    let rid = alice.project_from("acme", "", &repo);

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let bob_events = bob.handle.events();

    bob.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);

    bob_events
        .wait(
            |e| {
                matches!(e, Event::RefsFetched { updated, .. } if !updated.is_empty()).then_some(())
            },
            time::Duration::from_secs(9 * scale as u64),
        )
        .unwrap();

    let doc = bob.storage.repository(rid).unwrap().identity_doc().unwrap();
    let proj = doc.project().unwrap();

    assert_eq!(proj.name(), "acme");
}

#[test]
fn test_concurrent_fetches() {
    let tmp = tempfile::tempdir().unwrap();
    let scale = config::scale();
    let repos = scale.max(4);
    let limits = Limits {
        // By setting fetch concurrency to one less than the total number of repos,
        // we guarantee that at least one fetch will be queued while the others
        // are in progress.
        fetch_concurrency: (repos - 1).into(),
        ..Limits::default()
    };
    let mut bob_repos = HashSet::new();
    let mut alice_repos = HashSet::new();
    let mut alice = Node::init(
        tmp.path(),
        radicle::node::config::Config {
            limits: limits.clone(),
            relay: radicle::node::config::Relay::Always,
            ..config::relay("alice")
        },
        13,
    );
    let mut bob = Node::init(
        tmp.path(),
        radicle::node::config::Config {
            limits,
            relay: radicle::node::config::Relay::Always,
            ..config::relay("bob")
        },
        37,
    );

    for i in 0..repos {
        // Create a repo for Alice.
        let tmp = tempfile::tempdir().unwrap();
        let (repo, _) = fixtures::repository(tmp.path());
        fixtures::populate(&repo, scale);

        let rid = alice.project_from(&format!("alice-{i}"), "", &repo);
        alice_repos.insert(rid);

        // Create a repo for Bob.
        let tmp = tempfile::tempdir().unwrap();
        let (repo, _) = fixtures::repository(tmp.path());
        fixtures::populate(&repo, scale);

        let rid = bob.project_from(&format!("bob-{i}"), "", &repo);
        bob_repos.insert(rid);
    }

    // Clone repositories list for assertions so we don't assert over an empty set.
    let all_alice_repos = alice_repos.clone();
    let all_bob_repos = bob_repos.clone();

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    let alice_events = alice.handle.events();
    let bob_events = bob.handle.events();

    for rid in &bob_repos {
        alice.handle.seed(*rid, Scope::All).unwrap();
    }
    for rid in &alice_repos {
        bob.handle.seed(*rid, Scope::All).unwrap();
    }
    alice.connect(&bob);

    while !bob_repos.is_empty() {
        match alice_events.recv().unwrap() {
            // We're looking for a `RefsFetched` event, which signals a completed fetch.
            // We also ensure that `updated` is not empty, meaning data was actually received.
            Event::RefsFetched { rid, updated, .. } if !updated.is_empty() => {
                // Once a repo is fetched, remove it from our tracking set.
                bob_repos.remove(&rid);
                log::debug!(target: "test", "{} fetched {rid} ({} left)",alice.id, bob_repos.len());
            }
            _ => {}
        }
    }

    while !alice_repos.is_empty() {
        match bob_events.recv().unwrap() {
            Event::RefsFetched { rid, updated, .. } if !updated.is_empty() => {
                // Once a repo is fetched, remove it from our tracking set.
                alice_repos.remove(&rid);
                log::debug!(target: "test", "{} fetched {rid} ({} left)", bob.id, alice_repos.len());
            }
            _ => {}
        }
    }

    // Positively assert empty sets, not necessary but proves test was previously broken.
    assert!(bob_repos.is_empty());
    assert!(alice_repos.is_empty());

    for rid in &all_bob_repos {
        let doc = alice
            .storage
            .repository(*rid)
            .unwrap()
            .identity_doc()
            .unwrap();
        let proj = doc.project().unwrap();

        assert!(proj.name().starts_with("bob"));
    }
    for rid in &all_alice_repos {
        let doc = bob
            .storage
            .repository(*rid)
            .unwrap()
            .identity_doc()
            .unwrap();
        let proj = doc.project().unwrap();

        assert!(proj.name().starts_with("alice"));
    }
}

#[test]
fn test_connection_crossing() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let alice = alice.spawn();
    let bob = bob.spawn();
    let preferred = alice.id.max(bob.id);

    log::debug!(target: "test", "Preferred peer is {preferred}");

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b1 = barrier.clone();
    let b2 = barrier.clone();
    let t1 = thread::spawn({
        let mut alice = alice.handle.clone();

        move || {
            b1.wait();
            alice
                .connect(bob.id, bob.addr.into(), ConnectOptions::default())
                .unwrap()
        }
    });
    let t2 = thread::spawn({
        let mut bob = bob.handle.clone();
        move || {
            b2.wait();
            bob.connect(alice.id, alice.addr.into(), ConnectOptions::default())
                .unwrap()
        }
    });

    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();

    // Note that the non-preferred peer will have their outbound connection fail, and this
    // could already show up as the result of the call here (but not always).
    if preferred == alice.id {
        assert_matches!(r1, ConnectResult::Connected);
    } else {
        assert_matches!(r2, ConnectResult::Connected);
    }

    let mut iterations = 0;
    let (alice_s, bob_s, s1, s2) = loop {
        let alice_s = alice.handle.sessions().unwrap();
        let bob_s = bob.handle.sessions().unwrap();

        let s1 = alice_s.iter().find(|s| s.nid == bob.id).cloned();
        let s2 = bob_s.iter().find(|s| s.nid == alice.id).cloned();

        if let (Some(s1), Some(s2)) = (s1, s2) {
            // Wait until both sessions are fully connected
            if s1.state.is_connected() && s2.state.is_connected() {
                break (alice_s, bob_s, s1, s2);
            }
        }
        iterations += 1;
        if iterations >= 100 {
            panic!("Timeout waiting for sessions to connect");
        }
        thread::sleep(time::Duration::from_millis(50));
    };

    // We assert that they have opposite link directions.
    // In a true simultaneous crossing, the preferred peer wins the Outbound link.
    // However, due to OS thread scheduling and reactor event ordering, one peer
    // might fully establish the connection before the other even processes the dial command.
    // In all valid cases (crossing or sequential), exactly one is Outbound and one is Inbound.
    assert_ne!(
        s1.link, s2.link,
        "One must be Inbound and the other Outbound"
    );
    assert_eq!(alice_s.len(), 1);
    assert_eq!(bob_s.len(), 1);
}

#[test]
/// Alice is going to try to fetch outdated refs of Bob, from Eve. This is a non-fast-forward fetch
/// on the sigrefs branch.
fn test_non_fast_forward_sigrefs() {
    let tmp = tempfile::tempdir().unwrap();

    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let eve = Node::init(tmp.path(), config::relay("eve"), 42);

    let rid = bob.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut eve = eve.spawn();

    alice.handle.seed(rid, Scope::All).unwrap();
    eve.handle.seed(rid, Scope::All).unwrap();

    alice.connect(&bob);
    alice.connect(&eve);
    eve.connect(&bob);

    converge([&alice, &bob, &eve]);

    // Eve fetches the initial project from Bob.
    eve.handle
        .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    // Alice fetches it too.
    let old_bob = alice
        .handle
        .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    let bob_sigrefs = bob
        .storage
        .repository(rid)
        .unwrap()
        .reference_oid(&bob.id, &radicle::storage::refs::SIGREFS_BRANCH)
        .unwrap();
    let up = old_bob
        .find_updated(
            &(*radicle::storage::refs::Special::SignedRefs.namespaced(&bob.id)).to_ref_string(),
        )
        .unwrap();
    let old_bob = match up {
        RefUpdate::Created { oid, .. } => oid,
        RefUpdate::Skipped { oid, .. } => oid,
        _ => panic!("rad/sigrefs should have been created or skipped: {up:?}"),
    };
    assert_eq!(bob_sigrefs, old_bob);

    // Log the before Oid value of bob's 'rad/sigrefs', for debugging purposes.
    {
        let before = alice
            .storage
            .repository(rid)
            .unwrap()
            .reference_oid(&bob.id, &radicle::storage::refs::SIGREFS_BRANCH)
            .unwrap();
        log::debug!(target: "test", "bob's old 'rad/sigrefs': {before}");
    }

    // Now Eve disconnects from Bob so she doesn't fetch his update.
    eve.handle
        .command(service::Command::Disconnect(bob.id))
        .unwrap();

    // Bob updates his refs.
    bob.issue(
        rid,
        Title::new("Updated Sigrefs").unwrap(),
        "Updated sigrefs are harshing my vibes",
    );
    // Alice fetches from Bob.
    let new_bob = alice
        .handle
        .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    let bob_sigrefs = bob
        .storage
        .repository(rid)
        .unwrap()
        .reference_oid(&bob.id, &radicle::storage::refs::SIGREFS_BRANCH)
        .unwrap();
    let up = new_bob
        .find_updated(
            &(*radicle::storage::refs::Special::SignedRefs.namespaced(&bob.id)).to_ref_string(),
        )
        .unwrap();
    let new_bob = match up {
        RefUpdate::Updated { new, .. } => new,
        // FIXME: Really it shouldn't be skipped but let's see what happens
        RefUpdate::Skipped { oid, .. } => oid,
        _ => panic!("rad/sigrefs should have been updated {up:?}"),
    };
    assert_eq!(bob_sigrefs, new_bob);

    // Log the after Oid value of bob's 'rad/sigrefs', for debugging purposes.
    {
        let after = alice
            .storage
            .repository(rid)
            .unwrap()
            .reference_oid(&bob.id, &radicle::storage::refs::SIGREFS_BRANCH)
            .unwrap();
        log::debug!(target: "test", "bob's new 'rad/sigrefs': {after}");
    }

    assert_matches!(
        alice.handle.fetch(rid, eve.id, DEFAULT_TIMEOUT, None).unwrap(),
        FetchResult::Success { updated, .. }
        if updated.iter().all(|u| u.is_skipped())
    );
}

#[test]
fn test_outdated_sigrefs() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let eve = Node::init(tmp.path(), config::relay("eve"), 42);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut eve = eve.spawn();

    bob.handle.seed(rid, Scope::All).unwrap();
    eve.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);
    bob.connect(&eve);
    eve.connect(&alice);
    converge([&alice, &bob, &eve]);

    bob.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(bob.storage.contains(&rid).unwrap());
    rad::fork(rid, &bob.signer, &bob.storage).unwrap();

    eve.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(eve.storage.contains(&rid).unwrap());
    rad::fork(rid, &eve.signer, &eve.storage).unwrap();

    alice
        .handle
        .follow(eve.id, Some(Alias::new("eve")))
        .unwrap();
    alice
        .handle
        .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    let repo = alice.storage.repository(rid).unwrap();
    assert!(repo.remote(&eve.id).is_ok());

    log::debug!(target: "test", "Bob fetches from Eve..");
    assert_matches!(
        bob.handle
            .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = bob.storage.repository(rid).unwrap();
    let eve_remote = repo.remote(&eve.id).unwrap();
    let old_refs = eve_remote.refs;

    // At this stage, Alice and Bob have Eve's fork and Eve does not
    // have Bob's fork

    let issue_id = eve.issue(
        rid,
        Title::new("Outdated Sigrefs").unwrap(),
        "Outdated sigrefs are harshing my vibes",
    );
    let repo = eve.storage.repository(rid).unwrap();
    let eves_refs = repo.remote(&eve.id).unwrap().refs;

    // Get the current state of eve's refs in alice's storage
    log::debug!(target: "test", "Alice fetches from Eve..");
    assert_matches!(
        alice
            .handle
            .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = alice.storage.repository(rid).unwrap();
    let issues = issue::Issues::open(&repo, WriteAs::new(&alice.signer)).unwrap();
    assert!(
        issues.get(&issue_id).unwrap().is_some(),
        "Alice did not fetch issue {issue_id}"
    );
    let eve_remote = repo.remote(&eve.id).unwrap();
    let eves_refs_expected = eve_remote.refs;
    assert_ne!(eves_refs_expected, old_refs);
    assert_eq!(eves_refs_expected, eves_refs);

    log::debug!(target: "test", "Alice fetches from Bob..");

    alice
        .handle
        .follow(bob.id, Some(Alias::new("bob")))
        .unwrap();
    assert_matches!(
        alice
            .handle
            .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );

    // Ensure that Eve's refs have not changed after fetching the old refs from Bob.
    let repo = alice.storage.repository(rid).unwrap();
    let eve_remote = repo.remote(&eve.id).unwrap();
    let eves_refs = eve_remote.refs;

    assert_ne!(eves_refs, old_refs);
    assert_eq!(eves_refs_expected, eves_refs);
}

#[test]
fn test_outdated_delegate_sigrefs() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let eve = Node::init(tmp.path(), config::relay("eve"), 42);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut eve = eve.spawn();

    bob.handle.seed(rid, Scope::All).unwrap();
    eve.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);
    bob.connect(&eve);
    eve.connect(&alice);
    converge([&alice, &bob, &eve]);

    bob.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(bob.storage.contains(&rid).unwrap());
    rad::fork(rid, &bob.signer, &bob.storage).unwrap();

    eve.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(eve.storage.contains(&rid).unwrap());
    rad::fork(rid, &eve.signer, &eve.storage).unwrap();

    alice
        .handle
        .follow(eve.id, Some(Alias::new("eve")))
        .unwrap();
    alice
        .handle
        .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    let repo = alice.storage.repository(rid).unwrap();
    assert!(repo.remote(&eve.id).is_ok());

    log::debug!(target: "test", "Bob fetches from Eve..");
    assert_matches!(
        bob.handle
            .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = bob.storage.repository(rid).unwrap();
    let alice_remote = repo.remote(&alice.id).unwrap();
    let old_refs = alice_remote.refs;

    // At this stage, Alice and Bob have Eve's fork and Eve does not
    // have Bob's fork

    alice.issue(
        rid,
        Title::new("Outdated Sigrefs").unwrap(),
        "Outdated sigrefs are harshing my vibes",
    );
    let repo = alice.storage.repository(rid).unwrap();
    let alice_refs = repo.remote(&alice.id).unwrap().refs;

    // Get the current state of eve's refs in alice's storage
    log::debug!(target: "test", "Alice fetches from Eve..");
    assert_matches!(
        eve.handle
            .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = eve.storage.repository(rid).unwrap();
    let alice_remote = repo.remote(&alice.id).unwrap();
    let alice_refs_expected = alice_remote.refs;
    assert_ne!(alice_refs_expected, old_refs);
    assert_eq!(alice_refs_expected, alice_refs);

    log::debug!(target: "test", "Alice fetches from Bob..");

    eve.handle.follow(bob.id, Some(Alias::new("bob"))).unwrap();
    assert_matches!(
        eve.handle
            .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );

    // Ensure that Eve's refs have not changed after fetching the old refs from Bob.
    let repo = eve.storage.repository(rid).unwrap();
    let alice_remote = repo.remote(&alice.id).unwrap();
    let alice_refs = alice_remote.refs;

    assert_ne!(alice_refs, old_refs);
    assert_eq!(alice_refs_expected, alice_refs);
}

#[test]
fn missing_default_branch() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.handle.seed(rid, Scope::All).unwrap();
    bob.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);
    converge([&alice, &bob]);

    bob.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(bob.storage.contains(&rid).unwrap());

    // Fetching from still works despite not having
    // `refs/heads/master`, but has `rad/sigrefs`.
    bob.issue(
        rid,
        Title::new("Hello, Acme").unwrap(),
        "Popping in to say hello",
    );
    alice
        .handle
        .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
        .unwrap();

    {
        let repo = bob.storage.repository(rid).unwrap();
        assert!(repo.canonical_head().is_ok());
        assert!(repo.canonical_identity_doc().is_ok());
        assert!(repo.head().is_ok());
    }

    // If for some reason Alice managed to delete her master reference
    {
        let repo = alice.storage.repository_mut(rid).unwrap();
        let mut r = repo
            .backend
            .find_reference(&format!("refs/namespaces/{}/refs/heads/master", alice.id))
            .unwrap();
        r.delete().unwrap();
        repo.sign_refs(&alice.signer).unwrap();
    }

    // Fetching from her will still succeed.
    assert_matches!(
        bob.handle
            .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = bob.storage.repository(rid).unwrap();
    // The canonical head cannot be computed, though.
    assert!(repo.canonical_head().is_err());
}

#[test]
fn missing_delegate_default_branch() {
    use radicle::identity::Identity;
    use radicle::storage::git::Repository;
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let seed = Node::init(tmp.path(), config::relay("seed"), 7);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut seed = seed.spawn();

    let bob_events = bob.handle.events();

    alice.handle.seed(rid, Scope::All).unwrap();
    bob.handle.seed(rid, Scope::All).unwrap();
    seed.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&seed);
    converge([&seed]);
    bob.connect(&seed);

    bob.handle
        .fetch(rid, seed.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    bob_events
        .wait(
            |e| {
                matches!(e, Event::RefsFetched { updated, .. } if !updated.is_empty()).then_some(())
            },
            DEFAULT_TIMEOUT,
        )
        .unwrap();
    assert!(bob.storage.contains(&rid).unwrap());

    let bob_key = *bob.signer.public_key();

    // Helper to assert that Bob's default branch is not in storage
    let assert_bobs_default_is_missing = |repo: &Repository| {
        let doc = repo.identity_doc().unwrap();
        let project = doc.project().unwrap();
        let default_branch = repo.reference(
            &bob_key,
            &radicle::git::refs::branch(project.default_branch()),
        );
        assert!(matches!(
            default_branch,
            Err(e) if e.is_not_found()
        ));
    };

    // Add Bob as a delegate to the identity document
    {
        let repo = alice.storage.repository(rid).unwrap();
        let mut identity = Identity::load_mut(&repo, &alice.signer).unwrap();
        let doc = repo
            .identity_doc()
            .unwrap()
            .doc
            .with_edits(|doc| {
                doc.delegate(bob.signer.public_key().into());
            })
            .unwrap();
        let rev = identity
            .update(Title::new("Add Bob").unwrap(), "", &doc)
            .unwrap();
        repo.set_identity_head_to(rev).unwrap();

        let new = repo.identity_doc().unwrap().doc;
        assert!(
            new.is_delegate(&bob_key.into()),
            "Bob must be a delegate after the update"
        );
    }

    // We ensure that Bob does not have the default branch
    let repo = bob.storage.repository(rid).unwrap();
    assert_bobs_default_is_missing(&repo);

    // Create an issue to ensure there are new refs to fetch
    let issue = bob.issue(
        rid,
        Title::new("Delegate Issue").unwrap(),
        "Further investigation into delegates",
    );
    let assert_bobs_issue_exists = |repo: &Repository| {
        let issue_ref = radicle::git::refs::storage::cob(
            bob.signer.public_key(),
            &radicle::cob::issue::TYPENAME,
            &issue,
        );
        assert!(repo.backend.find_reference(issue_ref.as_str()).is_ok(),);
    };

    // The seed fetches from Bob and checks that:
    // a) Bob's default branch is still missing
    // b) Bob's issue is there
    assert_matches!(
        seed.handle
            .fetch(rid, bob.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    {
        let repo = seed.storage.repository(rid).unwrap();
        assert_bobs_default_is_missing(&repo);
        assert_bobs_issue_exists(&repo);
    }

    // Do the same for Alice
    assert_matches!(
        alice
            .handle
            .fetch(rid, seed.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    {
        let repo = alice.storage.repository(rid).unwrap();
        assert_bobs_default_is_missing(&repo);
        assert_bobs_issue_exists(&repo);
    }

    // Check that Bob can still fetch from the seed
    assert_matches!(
        bob.handle
            .fetch(rid, seed.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
}

#[test]
fn test_background_foreground_fetch() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let eve = Node::init(tmp.path(), config::relay("eve"), 42);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let alice_events = alice.handle.events();
    let mut bob = bob.spawn();
    let mut eve = eve.spawn();

    bob.handle.seed(rid, Scope::Followed).unwrap();
    eve.handle.seed(rid, Scope::Followed).unwrap();
    alice.connect(&bob);
    alice.connect(&eve);
    converge([&alice, &bob, &eve]);

    bob.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(bob.storage.contains(&rid).unwrap());
    rad::fork(rid, &bob.signer, &bob.storage).unwrap();

    eve.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(eve.storage.contains(&rid).unwrap());
    rad::fork(rid, &eve.signer, &eve.storage).unwrap();

    // Alice fetches Eve's fork and we make note of the sigrefs
    alice
        .handle
        .follow(eve.id, Some(Alias::new("eve")))
        .unwrap();
    alice
        .handle
        .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    let repo = alice.storage.repository(rid).unwrap();
    assert!(repo.remote(&eve.id).is_ok());
    let repo = alice.storage.repository(rid).unwrap();
    let eve_remote = repo.remote(&eve.id).unwrap();
    let old_refs = eve_remote.refs;

    // Eve creates an issue, updating their refs, and we make note of
    // the new refs
    eve.issue(
        rid,
        Title::new("Outdated Sigrefs").unwrap(),
        "Outdated sigrefs are harshing my vibes",
    );
    let repo = eve.storage.repository(rid).unwrap();
    let eves_refs = repo.remote(&eve.id).unwrap().refs;

    // Alice follows Bob and they make a new change and announce it,
    // this initiates a background fetch for Alice from Bob
    alice
        .handle
        .follow(bob.id, Some(Alias::new("bob")))
        .unwrap();
    bob.issue(
        rid,
        Title::new("Concurrent fetches").unwrap(),
        "Concurrent fetches are harshing my vibes",
    );
    bob.handle.announce_refs_for(rid, [bob.id]).unwrap();
    alice_events
        .wait(
            |e| matches!(e, Event::RefsAnnounced { .. }).then_some(()),
            DEFAULT_TIMEOUT,
        )
        .unwrap();

    // Alice initiates a fetch from Eve and we ensure that we get the
    // updated refs from Eve, and the fetch from Bob should not
    // interfere
    log::debug!(target: "test", "Alice fetches from Eve..");
    assert_matches!(
        alice
            .handle
            .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = alice.storage.repository(rid).unwrap();
    let eve_remote = repo.remote(&eve.id).unwrap();
    let eves_refs_expected = eve_remote.refs;
    assert_ne!(eves_refs_expected, old_refs);
    assert_eq!(eves_refs_expected, eves_refs);
}

#[test]
/// Alice is offline while Bob pushes some changes to the repo. When Alice reconnects,
/// she is made aware of the changes via the `subscribe` message, and fetches from the seed.
fn test_catchup_on_refs_announcements() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let bob_id = bob.id;
    let seed = Node::init(tmp.path(), config::relay("seed"), 7);
    let acme = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let mut seed = seed.spawn();

    bob.handle.seed(acme, Scope::All).unwrap();
    seed.handle.seed(acme, Scope::All).unwrap();

    alice.connect(&seed);
    seed.has_repository(&acme);
    alice.disconnect(&seed);
    bob.connect(&seed);
    bob.has_repository(&acme);

    log::debug!(target: "test", "Bob creating his issue..");
    bob.issue(acme, Title::new("Bob's issue").unwrap(), "[..]");
    bob.handle.announce_refs_for(acme, [bob.id]).unwrap();

    log::debug!(target: "test", "Waiting for seed to fetch Bob's refs from Bob..");
    seed.has_remote_of(&acme, &bob.id); // Seed fetches Bob's refs.
    bob.disconnect(&seed);
    bob.shutdown();

    log::debug!(target: "test", "Alice re-connects to the seed..");
    alice.connect(&seed);
    alice.has_remote_of(&acme, &bob_id);
}

#[test]
fn test_multiple_offline_inits() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let acme = alice.project("acme", "");
    let radcliffe = alice.project("radcliffe", "");
    let cobs = alice.project("cobs", "");
    let projects = [acme, radcliffe, cobs];

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    for rid in &projects {
        bob.handle.seed(*rid, Scope::All).unwrap();
    }

    alice.connect(&bob).converge([&bob]);

    for repo in bob.storage.repositories().unwrap() {
        assert!(projects.contains(&repo.rid), "Bob is missing {}", repo.rid);
    }
}

#[test]
fn test_channel_reader_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let limits = radicle::node::config::Limits {
        fetch_pack_receive: radicle::node::config::FetchPackSizeLimit::bytes(1000),
        ..radicle::node::config::Limits::default()
    };
    let bob = Node::init(
        tmp.path(),
        Config {
            limits,
            ..config::relay("bob")
        },
        37,
    );
    let acme = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    let updated = bob.handle.seed(acme, Scope::All).unwrap();
    assert!(updated);

    let result = bob
        .handle
        .fetch(acme, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(!result.is_success());

    let FetchResult::Failed { reason } = result else {
        panic!("fetch result must be failed")
    };
    // Either gitoxide will error by being unable to consume the packet, or the
    // byte limit error will be returned
    assert!(
        reason.contains("Failed to consume the pack sent by the remote")
            || reason.contains("exceeded number of allowed bytes"),
        "actual: {reason}"
    );
}

#[test]
fn test_fetch_emits_canonical_ref_update() {
    let tmp = tempfile::tempdir().unwrap();
    let scale = config::scale();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let (repo, _) = fixtures::repository(tmp.path());
    fixtures::populate(&repo, scale.max(3));

    let rid = alice.project_from("acme", "", &repo);

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let bob_events = bob.handle.events();

    bob.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);

    let result = bob
        .handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    // Drain all the events including initial `CanonicalRefUpdated`
    // from fetch
    while bob_events.try_recv().is_ok() {}

    let default_branch: git::fmt::Qualified = {
        let repo = alice.storage.repository(rid).unwrap();
        let proj = repo.project().unwrap();
        git::fmt::lit::refs_heads(proj.default_branch()).into()
    };

    alice.commit_to(rid, &default_branch);

    alice.handle.announce_refs_for(rid, [alice.id]).unwrap();

    bob_events
        .wait(
            |e| {
                matches!(e, Event::CanonicalRefUpdated { refname, .. } if *refname == default_branch)
                    .then_some(())
            },
            time::Duration::from_secs(9 * scale as u64),
        )
        .unwrap();
}

#[test]
fn test_non_fast_forward_identity_doc() {
    use radicle::identity::Identity;

    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), Config::test(Alias::new("alice")), 13);
    let bob = Node::init(tmp.path(), Config::test(Alias::new("bob")), 37);
    let eve = Node::init(tmp.path(), Config::test(Alias::new("eve")), 42);
    let alice_laptop = Node::init(tmp.path(), Config::test(Alias::new("alice-laptop")), 113);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut alice_laptop = alice_laptop.spawn();
    let mut bob = bob.spawn();
    let bob_events = bob.handle.events();
    let mut eve = eve.spawn();

    let has_issue = |node: &NodeHandle, issue: &cob::ObjectId| -> bool {
        let repo = node.storage.repository(rid).unwrap();
        repo.contains(**issue).unwrap()
    };

    alice.connect(&alice_laptop);
    alice.connect(&bob);
    alice.connect(&eve);
    eve.connect(&bob);
    eve.connect(&alice_laptop);

    // Due to permissive relaying, we need to lock down the scope for the RID.
    //
    // See: [`radicle-protocol::service::Service::relay()`] and
    //      [`radicle-protocol::service::Service::relay_announcement()`]
    alice.handle.seed(rid, Scope::Followed).unwrap();

    // Bob and Eve have the same state for the repository
    bob.handle.seed(rid, Scope::Followed).unwrap();
    bob.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();

    alice_laptop.handle.seed(rid, Scope::All).unwrap();
    alice_laptop
        .handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();

    // Alice pushes new references to her laptop
    let issue = alice_laptop.issue(
        rid,
        "Feature #1".parse().unwrap(),
        "Implementing new feature",
    );

    // Eve will fetch these references since her scope is "all"
    eve.handle.seed(rid, Scope::All).unwrap();
    eve.handle
        .fetch(rid, alice_laptop.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(has_issue(&eve, &issue));

    bob_events
        .wait(
            |e| matches!(e, Event::RefsAnnounced { nid, .. } if *nid == eve.id).then_some(()),
            DEFAULT_TIMEOUT,
        )
        .unwrap();

    // Alice updates the identity of the document to include her laptop
    let (prev, next) = {
        let repo = alice.storage.repository(rid).unwrap();
        let mut identity = Identity::load_mut(&repo, &alice.signer).unwrap();
        let prev = identity.current;
        let doc = repo
            .identity_doc()
            .unwrap()
            .doc
            .with_edits(|raw| raw.delegate(alice_laptop.id.into()))
            .unwrap();
        let rev = identity
            .update(Title::new("Add Laptop").unwrap(), "", &doc)
            .unwrap();
        repo.set_identity_head_to(rev).unwrap();
        (prev, rev)
    };

    assert!(!has_issue(&alice, &issue));

    // Bob fetches from Alice and we see the identity document was updated.
    //
    // Bob does not have the issue because Alice does not have the updates from
    // Alice's Laptop.
    let result = bob
        .handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(matches!(result, FetchResult::Success { .. }));
    assert!(!has_issue(&bob, &issue));
    let repo = bob.storage.repository(rid).unwrap();
    let identity = Identity::load_mut(&repo, &bob.signer).unwrap();
    assert_eq!(identity.current, next);
    assert_eq!(identity.parent, Some(prev));

    // Bob fetches from Eve, the identity document should remain the same, but
    // since Bob now knows that Alice's Laptop is a delegate, the issue should
    // be fetched.
    bob.handle
        .fetch(rid, eve.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(matches!(result, FetchResult::Success { .. }));
    assert!(has_issue(&bob, &issue));
    let repo = bob.storage.repository(rid).unwrap();
    let identity = Identity::load_mut(&repo, &bob.signer).unwrap();
    assert_eq!(identity.current, next);
    assert_eq!(identity.parent, Some(prev));
}

#[test]
fn test_block_active_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    alice.connect(&bob);
    converge([&alice, &bob]);

    let events = alice.handle.events();
    assert!(alice.handle.block(bob.id).unwrap());

    events
        .wait(
            |e| matches!(e, Event::PeerDisconnected { nid, .. } if *nid == bob.id).then_some(()),
            DEFAULT_TIMEOUT,
        )
        .unwrap();

    let sessions = alice.handle.sessions().unwrap();
    assert!(sessions.iter().all(|s| s.nid != bob.id));
}

#[test]
fn test_block_prevents_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    assert!(alice.handle.block(bob.id).unwrap());

    let result = alice
        .handle
        .connect(bob.id, bob.addr.into(), ConnectOptions::default())
        .unwrap();

    assert_matches!(result, ConnectResult::Disconnected { .. });

    let events = alice.handle.events();
    bob.connect(&alice);

    // Alice receives Bob's inbound connection, but disconnects from him.
    events
        .wait(
            |e| matches!(e, Event::PeerDisconnected { nid, .. } if *nid == bob.id).then_some(()),
            time::Duration::from_secs(10),
        )
        .unwrap();

    let sessions = alice.handle.sessions().unwrap();
    assert!(sessions.iter().all(|s| s.nid != bob.id));
}

#[test]
fn test_block_prevents_fetch() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let rid = bob.project("acme", "");

    let mut alice = alice.spawn();
    let bob = bob.spawn();

    assert!(alice.handle.block(bob.id).unwrap());

    let result = alice
        .handle
        .fetch(rid, bob.id, time::Duration::from_secs(5), None)
        .unwrap();

    assert_matches!(result, FetchResult::Failed { .. });
}

#[test]
fn fetch_does_not_contain_rad_sigrefs_parent() {
    use radicle::storage::refs::SIGREFS_PARENT;

    let tmp = tempfile::tempdir().unwrap();

    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let rid = alice.project("acme", "");

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();

    bob.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);
    converge([&alice, &bob]);

    bob.handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(bob.storage.contains(&rid).unwrap());
    rad::fork(rid, &bob.signer, &bob.storage).unwrap();

    let issue_id = alice.issue(
        rid,
        Title::new("No rad/sigrefs-parent").unwrap(),
        "sigrefs are harshing my vibes",
    );
    let repo = alice.storage.repository(rid).unwrap();
    let alice_signed_refs = repo.remote(&alice.id).unwrap().refs;

    log::debug!(target: "test", "Bob fetches from Alice..");
    assert_matches!(
        bob.handle
            .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
            .unwrap(),
        FetchResult::Success { .. }
    );
    let repo = bob.storage.repository(rid).unwrap();
    let issues = issue::Issues::open(&repo, ReadOnly).unwrap();
    assert!(
        issues.get(&issue_id).unwrap().is_some(),
        "Bob did not fetch issue {issue_id}"
    );

    let repo = bob.storage.repository(rid).unwrap();
    let alice_remote = repo.remote(&alice.id).unwrap();

    assert_eq!(alice_signed_refs.refs(), alice_remote.refs());
    assert!(alice_remote.refs().get(&SIGREFS_PARENT).is_none());
}

#[test]
fn test_fetch_emits_canonical_ref_update_partial_glob() {
    let tmp = tempfile::tempdir().unwrap();
    let scale = config::scale();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let bob = Node::init(tmp.path(), config::relay("bob"), 37);

    let (repo, _) = fixtures::repository(tmp.path());
    let rid = alice.project_from("acme", "", &repo);

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    let bob_events = bob.handle.events();

    {
        let repo = alice.storage.repository(rid).unwrap();
        let mut identity = radicle::identity::Identity::load_mut(&repo, &alice.signer).unwrap();
        let doc = repo
            .identity_doc()
            .unwrap()
            .doc
            .with_edits(|raw| {
                let crefs = serde_json::json!({
                    "rules": {
                        "refs/heads/main*": {
                            "threshold": 1,
                            "allow": "delegates"
                        }
                    }
                });

                raw.payload.insert(
                    radicle::identity::doc::PayloadId::canonical_refs(),
                    radicle::identity::doc::Payload::from(crefs),
                );
            })
            .unwrap();

        let rev = identity
            .update(Title::new("Add main* rule").unwrap(), "", &doc)
            .unwrap();
        repo.set_identity_head_to(rev).unwrap();
    }

    bob.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);

    let result = bob
        .handle
        .fetch(rid, alice.id, DEFAULT_TIMEOUT, None)
        .unwrap();
    assert!(result.is_success());

    let target_branch: git::fmt::Qualified = git::fmt::qualified!("refs/heads/main-2026q2");
    alice.commit_to(rid, &target_branch);
    alice.handle.announce_refs_for(rid, [alice.id]).unwrap();

    bob_events
        .wait(
            |e| {
                matches!(e, Event::CanonicalRefUpdated { refname, .. } if *refname == target_branch)
                    .then_some(())
            },
            time::Duration::from_secs(9 * scale as u64),
        )
        .unwrap();
}

/// A gate for the dial tests: it resolves `name` to `answers`, waiting on
/// `hold` first if there is one, and allows only `allowed`.
#[derive(Debug)]
struct TestGate {
    name: String,
    answers: Vec<std::net::SocketAddr>,
    allowed: Vec<std::net::IpAddr>,
    hold: Option<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
    timeout: time::Duration,
}

impl radicle::node::dial::Gate for TestGate {
    fn allows(&self, _target: &radicle::node::Address, addr: &std::net::SocketAddr) -> bool {
        self.allowed.contains(&addr.ip())
    }

    fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        if let Some(hold) = &self.hold {
            hold.lock().unwrap().recv().ok();
        }
        if host == self.name {
            Ok(self.answers.clone())
        } else {
            Err(std::io::ErrorKind::NotFound.into())
        }
    }

    fn resolve_timeout(&self) -> time::Duration {
        self.timeout
    }
}

fn test_gate(bob: &NodeHandle, allowed: bool) -> TestGate {
    TestGate {
        name: "bob.test".to_owned(),
        answers: vec![bob.addr],
        allowed: if allowed { vec![bob.addr.ip()] } else { vec![] },
        hold: None,
        timeout: time::Duration::from_secs(10),
    }
}

fn by_name(bob: &NodeHandle) -> radicle::node::Address {
    format!("bob.test:{}", bob.addr.port()).parse().unwrap()
}

fn connect(
    alice: &mut NodeHandle,
    bob: &NodeHandle,
    addr: radicle::node::Address,
) -> ConnectResult {
    alice
        .handle
        .connect(
            bob.id,
            addr,
            ConnectOptions {
                persistent: false,
                timeout: time::Duration::from_secs(10),
            },
        )
        .unwrap()
}

#[test]
// heartwood#11 (freedom-core design 0008): a name is resolved through the
// node's gate, and the node connects to the address it checked.
fn test_dial_resolves_a_name_through_the_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = Node::init(tmp.path(), config::relay("bob"), 37).spawn();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13)
        .spawn_with_gate(std::sync::Arc::new(test_gate(&bob, true)));

    let result = connect(&mut alice, &bob, by_name(&bob));
    assert!(matches!(result, ConnectResult::Connected), "{result:?}");
}

#[test]
// An address the gate refuses isn't dialled, given directly or resolved from
// a name.
fn test_dial_refused_by_the_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = Node::init(tmp.path(), config::relay("bob"), 37).spawn();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13)
        .spawn_with_gate(std::sync::Arc::new(test_gate(&bob, false)));

    let direct = connect(&mut alice, &bob, bob.addr.into());
    assert!(
        matches!(direct, ConnectResult::Disconnected { .. }),
        "{direct:?}"
    );
    let named = connect(&mut alice, &bob, by_name(&bob));
    assert!(
        matches!(named, ConnectResult::Disconnected { .. }),
        "{named:?}"
    );
}

#[test]
// A resolver that doesn't answer fails its dial at the gate's deadline, and
// holds up nothing else: the node answers its handle meanwhile, and the late
// answer is dropped.
fn test_dial_a_resolver_that_hangs_fails_its_dial_only() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = Node::init(tmp.path(), config::relay("bob"), 37).spawn();
    let (release, hold) = std::sync::mpsc::channel();
    let gate = TestGate {
        hold: Some(std::sync::Mutex::new(hold)),
        timeout: time::Duration::from_millis(300),
        ..test_gate(&bob, true)
    };
    let alice = Node::init(tmp.path(), config::relay("alice"), 13)
        .spawn_with_gate(std::sync::Arc::new(gate));

    // The resolver is let go after 2 s, well past its dial's deadline.
    let releaser = thread::spawn(move || {
        thread::sleep(time::Duration::from_secs(2));
        release.send(()).ok();
    });
    let started = time::Instant::now();
    let mut handle = alice.handle.clone();
    let (bob_id, addr) = (bob.id, by_name(&bob));
    let dialling = thread::spawn(move || {
        handle
            .connect(
                bob_id,
                addr,
                ConnectOptions {
                    persistent: false,
                    timeout: time::Duration::from_secs(10),
                },
            )
            .unwrap()
    });
    // While the resolver hangs, the node answers at once.
    thread::sleep(time::Duration::from_millis(100));
    let asked = time::Instant::now();
    assert!(alice.handle.sessions().is_ok());
    assert!(
        asked.elapsed() < time::Duration::from_millis(500),
        "the node waited on its resolver"
    );
    let result = dialling.join().unwrap();
    assert!(
        matches!(result, ConnectResult::Disconnected { .. }),
        "{result:?}"
    );
    assert!(
        started.elapsed() < time::Duration::from_secs(2),
        "the dial waited for its resolver past the deadline"
    );

    // The answer, once it comes, is too late: nothing is dialled.
    let events = alice.handle.events();
    releaser.join().unwrap();
    let connected = events.wait(
        |e| matches!(e, Event::PeerConnected { nid } if nid == &bob.id).then_some(()),
        time::Duration::from_secs(1),
    );
    assert!(connected.is_err(), "a late answer was dialled");
    let sessions = alice.handle.sessions().unwrap();
    assert!(
        !sessions
            .iter()
            .any(|s| s.nid == bob.id && s.state.is_connected()),
        "a late answer connected"
    );
}

/// A gate whose resolver waits until it is released, counting the calls in
/// it, and then answers `answers`; it allows everything.
#[derive(Debug)]
struct HeldGate {
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    release: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    answers: Vec<std::net::SocketAddr>,
}

impl HeldGate {
    fn new(answers: Vec<std::net::SocketAddr>) -> Self {
        Self {
            active: Default::default(),
            release: Default::default(),
            answers,
        }
    }

    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }

    /// Waits until exactly `count` calls are in the resolver.
    fn wait_for(&self, count: usize) {
        let until = time::Instant::now() + time::Duration::from_secs(5);
        while self.active.load(std::sync::atomic::Ordering::SeqCst) != count {
            assert!(
                time::Instant::now() < until,
                "{} calls in the resolver, not {count}",
                self.active.load(std::sync::atomic::Ordering::SeqCst)
            );
            thread::sleep(time::Duration::from_millis(5));
        }
    }
}

impl radicle::node::dial::Gate for HeldGate {
    fn allows(&self, _: &radicle::node::Address, _: &std::net::SocketAddr) -> bool {
        true
    }

    fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::sync::atomic::Ordering::SeqCst;

        self.active.fetch_add(1, SeqCst);
        let (lock, changed) = &*self.release;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        drop(released);
        self.active.fetch_sub(1, SeqCst);
        Ok(self.answers.clone())
    }

    fn resolve_timeout(&self) -> time::Duration {
        time::Duration::from_millis(200)
    }
}

#[test]
// Review of heartwood #4, round 1: resolutions are bounded by the pool, as
// many at once as the node may dial and at most four, even when their dials
// have given up, and a shutdown doesn't wait on a resolver for long.
fn test_dial_resolutions_are_bounded_by_the_pool() {
    let tmp = tempfile::tempdir().unwrap();
    let gate = std::sync::Arc::new(HeldGate::new(vec![]));
    let mut cfg = config::relay("alice");
    cfg.limits.connection.outbound = 2.into();
    let alice = Node::init(tmp.path(), cfg, 13).spawn_with_gate(gate.clone());
    let events = alice.handle.events();
    for wave in 0..2u8 {
        for i in 0..8u8 {
            let key = SigningKey::from_seed(radicle::crypto::Seed::new([40 + wave * 8 + i; 32]));
            alice
                .handle
                .command(service::Command::Connect(
                    *key.public_key(),
                    format!("node-{wave}-{i}.test:8776").parse().unwrap(),
                    ConnectOptions {
                        persistent: false,
                        timeout: time::Duration::from_secs(2),
                    },
                ))
                .unwrap();
        }
        // Two resolvers, both held; two more queued; the other four refused
        // at once, for want of room.
        gate.wait_for(2);
        let mut refused = 0;
        while refused < 4 {
            let reason = events
                .wait(
                    |e| match e {
                        Event::PeerDisconnected { reason, .. } => Some(reason.clone()),
                        _ => None,
                    },
                    time::Duration::from_secs(2),
                )
                .expect("the dials beyond the queue are refused");
            refused += usize::from(reason.contains("too many names are being resolved"));
        }
        thread::sleep(time::Duration::from_millis(500));
        gate.wait_for(2);
    }

    // A shutdown with both resolvers still held returns all the same, soon.
    let started = time::Instant::now();
    alice.shutdown();
    assert!(
        started.elapsed() < time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    gate.release();
    gate.wait_for(0);
}

#[test]
// Review of heartwood #4, round 1: an answer that comes after its dial's
// deadline isn't dialled, however long the reactor was busy before it got
// to it.
fn test_dial_a_late_answer_fails_however_busy_the_reactor_was() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = Node::init(tmp.path(), config::relay("bob"), 37).spawn();
    let gate = std::sync::Arc::new(HeldGate::new(vec![bob.addr]));
    let alice = Node::init(tmp.path(), config::relay("alice"), 13).spawn_with_gate(gate.clone());

    let mut handle = alice.handle.clone();
    let (nid, addr) = (bob.id, by_name(&bob));
    let connecting = thread::spawn(move || {
        handle
            .connect(
                nid,
                addr,
                ConnectOptions {
                    persistent: false,
                    timeout: time::Duration::from_secs(5),
                },
            )
            .unwrap()
    });
    gate.wait_for(1);
    // The reactor is kept busy for 700 ms; the answer comes 350 ms in, past
    // its 200 ms deadline, while it is.
    let (entered, entering) = std::sync::mpsc::sync_channel(1);
    let busy: std::sync::Arc<service::QueryState> = std::sync::Arc::new(move |_| {
        entered.send(()).ok();
        thread::sleep(time::Duration::from_millis(700));
        Ok(())
    });
    let (answered, _) = std::sync::mpsc::sync_channel(1);
    alice
        .handle
        .command(service::Command::QueryState(busy, answered))
        .unwrap();
    entering.recv_timeout(time::Duration::from_secs(2)).unwrap();
    thread::sleep(time::Duration::from_millis(350));
    gate.release();

    let result = connecting.join().unwrap();
    assert!(
        matches!(result, ConnectResult::Disconnected { .. }),
        "a late answer was dialled: {result:?}"
    );
}

#[test]
// Review of heartwood #4, round 1: a dial's deadline holds when the reactor
// is busy as it starts: a timer that fires early is set again.
fn test_dial_its_deadline_holds_after_a_busy_turn() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = Node::init(tmp.path(), config::relay("bob"), 37).spawn();
    let gate = std::sync::Arc::new(HeldGate::new(vec![]));
    let alice = Node::init(tmp.path(), config::relay("alice"), 13).spawn_with_gate(gate.clone());
    let events = alice.handle.events();

    // A 350 ms command, then the dial, in the same reactor turn.
    let (entered, entering) = std::sync::mpsc::sync_channel(1);
    let busy: std::sync::Arc<service::QueryState> = std::sync::Arc::new(move |_| {
        entered.send(()).ok();
        thread::sleep(time::Duration::from_millis(350));
        Ok(())
    });
    let (answered, _) = std::sync::mpsc::sync_channel(1);
    alice
        .handle
        .command(service::Command::QueryState(busy, answered))
        .unwrap();
    entering.recv_timeout(time::Duration::from_secs(2)).unwrap();
    alice
        .handle
        .command(service::Command::Connect(
            bob.id,
            by_name(&bob),
            ConnectOptions {
                persistent: false,
                timeout: time::Duration::from_secs(2),
            },
        ))
        .unwrap();
    gate.wait_for(1);

    let timed_out = events.wait(
        |e| matches!(e, Event::PeerDisconnected { nid, .. } if *nid == bob.id).then_some(()),
        time::Duration::from_millis(650),
    );
    gate.release();
    gate.wait_for(0);
    assert!(timed_out.is_ok(), "the dial's deadline was lost");
}

#[test]
// Review of heartwood #4, round 1: a peer configured by name is resolved at
// start like any other, not refused because the resolvers weren't ready.
// Round 2: it is the first dial that connects, not a retry after it failed.
fn test_dial_a_configured_peer_by_name_at_start() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = Node::init(tmp.path(), config::relay("bob"), 37).spawn();
    let mut alice = Node::init(tmp.path(), config::relay("alice"), 13);
    alice.config.connect = [radicle::node::config::ConnectAddress::from((
        bob.id,
        by_name(&bob),
    ))]
    .into_iter()
    .collect();
    let start = localtime::LocalTime::now();
    let alice = alice.spawn_with_gate(std::sync::Arc::new(test_gate(&bob, true)));

    let events = alice.handle.events();
    let since = || {
        alice
            .handle
            .sessions()
            .unwrap()
            .into_iter()
            .find_map(|s| match s.state {
                radicle::node::State::Connected { since, .. } if s.nid == bob.id => Some(since),
                _ => None,
            })
    };
    let since = since()
        .or_else(|| {
            events
                .wait(
                    |e| matches!(e, Event::PeerConnected { nid } if *nid == bob.id).then_some(()),
                    time::Duration::from_secs(10),
                )
                .ok()
                .and_then(|()| since())
        })
        .expect("alice never connected to bob by name");
    // A failed first dial is retried no sooner than the least reconnection
    // delay after it: a connection made before then is the first dial's.
    let after = since.duration_since(start);
    assert!(
        after < service::MIN_RECONNECTION_DELTA,
        "alice connected to bob {after} after starting: not on her first dial"
    );
}

/// `node`'s runtime, from its own configuration, or the error that refuses it.
fn init(node: crate::test::node::Node) -> Result<crate::runtime::Runtime, crate::runtime::Error> {
    let (_, signals) = std::sync::mpsc::sync_channel(1);
    crate::runtime::Runtime::init(
        node.home.clone(),
        node.config,
        Some(node.home.socket_default()),
        vec![([127, 0, 0, 1], 0).into()],
        signals,
        node.secret_key,
        std::sync::Arc::new(radicle::node::dial::Open),
    )
}

#[test]
// heartwood#12 (freedom-core design 0008): configuration checks at start are
// errors from `Runtime::init`, not panics.
fn test_init_refuses_a_zero_fetch_concurrency() {
    let tmp = tempfile::tempdir().unwrap();
    let mut node = Node::init(tmp.path(), config::relay("alice"), 13);
    node.config.limits.fetch_concurrency = 0.into();
    assert!(matches!(
        init(node),
        Err(crate::runtime::Error::ZeroFetchConcurrency)
    ));
}

#[test]
fn test_init_refuses_too_many_external_addresses() {
    let tmp = tempfile::tempdir().unwrap();
    let mut node = Node::init(tmp.path(), config::relay("alice"), 13);
    node.config.external_addresses = (0..=service::ADDRESS_LIMIT as u16)
        .map(|port| std::net::SocketAddr::from(([192, 0, 2, 1], 8000 + port)).into())
        .collect();
    match init(node) {
        Err(crate::runtime::Error::TooManyAddresses(e)) => {
            assert_eq!(e.0, service::ADDRESS_LIMIT + 1)
        }
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("a node with too many external addresses started"),
    }
}

#[test]
//
//     alice -- bob
//
// heartwood#12: a policy read that fails while the node handles a message
// stops it, and its runtime returns that error.
fn test_policy_failure_stops_the_node_with_its_error() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = Node::init(tmp.path(), config::relay("alice"), 13);
    let mut bob = Node::init(tmp.path(), config::relay("bob"), 37);
    let rid = bob.project("bob", "");
    let mut alice = alice.spawn();
    let bob = bob.spawn();

    // Alice seeds bob's repository, so that his refs announcements reach her.
    alice.handle.seed(rid, Scope::All).unwrap();
    alice.connect(&bob);

    // Her policy tables are dropped behind her back. The first read after it
    // finds no policy; the ones after it fail.
    let mut db = sqlite::open(alice.home.node().join(radicle::node::POLICIES_DB_FILE)).unwrap();
    // Alice's node may hold the database for a moment: wait for it.
    db.set_busy_timeout(10_000).unwrap();
    db.execute(r#"DROP TABLE "seeding"; DROP TABLE "following";"#)
        .unwrap();

    // Bob announces his refs until alice, reading her policy for them, stops.
    let mut bob_handle = bob.handle.clone();
    let deadline = time::Instant::now() + time::Duration::from_secs(30);
    while !alice.thread.is_finished() {
        assert!(time::Instant::now() < deadline, "alice never stopped");
        bob_handle.announce_refs_for(rid, [bob.id]).ok();
        thread::sleep(time::Duration::from_millis(200));
    }
    match alice.stopped(time::Duration::from_secs(1)) {
        Err(crate::runtime::Error::Service(e)) => {
            assert!(matches!(*e, service::Error::Policy(_)), "{e}")
        }
        other => panic!("expected the policy error, got {other:?}"),
    }
}

/// A gate whose name `online.test` resolves at once, to `online`, and whose
/// other names wait on `held`. Its dials give up after `timeout`.
#[derive(Debug)]
struct PenaltyGate {
    held: HeldGate,
    online: std::net::SocketAddr,
    timeout: time::Duration,
}

impl radicle::node::dial::Gate for PenaltyGate {
    fn allows(&self, _: &radicle::node::Address, _: &std::net::SocketAddr) -> bool {
        true
    }

    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        if host == "online.test" {
            Ok(vec![self.online])
        } else {
            self.held.resolve(host, port)
        }
    }

    fn resolve_timeout(&self) -> time::Duration {
        self.timeout
    }
}

/// Alice, online through dan, with two resolvers (two outbound
/// connections), bob in her address book by name, and a gate that holds
/// every name but dan's. Returns her, bob, the gate, and her address book.
fn penalty_fixture(
    tmp: &std::path::Path,
    timeout: time::Duration,
) -> (
    NodeHandle,
    NodeHandle,
    NodeHandle,
    std::sync::Arc<PenaltyGate>,
    radicle::node::Database,
) {
    use radicle::node::address::{KnownAddress, Source, Store as _};

    let dan = Node::init(tmp, config::relay("dan"), 51).spawn();
    let bob = Node::init(tmp, config::relay("bob"), 37).spawn();
    let mut cfg = config::relay("alice");
    cfg.peers = radicle::node::config::PeerConfig::Static;
    cfg.limits.connection.outbound = 2.into();
    let mut node = Node::init(tmp, cfg, 13);
    node.db
        .addresses_mut()
        .insert(
            &bob.id,
            1,
            radicle::node::Features::SEED,
            &bob.alias,
            0,
            &radicle::node::UserAgent::default(),
            localtime::LocalTime::now().into(),
            [KnownAddress::new(by_name(&bob), Source::Peer)],
        )
        .unwrap();
    let book = node.home.database_mut(node.config.database).unwrap();
    let gate = std::sync::Arc::new(PenaltyGate {
        held: HeldGate::new(vec![bob.addr]),
        online: dan.addr,
        timeout,
    });
    let alice = node.spawn_with_gate(gate.clone());
    // Online: a dial that fails is then held against its peer.
    let online = format!("online.test:{}", dan.addr.port()).parse().unwrap();
    assert!(matches!(
        alice
            .handle
            .clone()
            .connect(dan.id, online, connect_options())
            .unwrap(),
        ConnectResult::Connected
    ));
    (alice, bob, dan, gate, book)
}

fn connect_options() -> ConnectOptions {
    ConnectOptions {
        persistent: false,
        timeout: time::Duration::from_secs(5),
    }
}

/// Bob's penalty in `book`, once alice's reactor has handled what came before.
fn penalty(
    alice: &NodeHandle,
    bob: &NodeHandle,
    book: &radicle::node::Database,
) -> radicle::node::Penalty {
    use radicle::node::address::Store as _;

    alice.handle.sessions().unwrap();
    book.get(&bob.id).unwrap().unwrap().penalty
}

/// Holds both of alice's resolvers with names of their own.
fn hold_resolvers(alice: &NodeHandle, gate: &PenaltyGate) {
    for i in 0..2u8 {
        let key = SigningKey::from_seed(radicle::crypto::Seed::new([90 + i; 32]));
        alice
            .handle
            .command(service::Command::Connect(
                *key.public_key(),
                format!("held-{i}.test:8776").parse().unwrap(),
                connect_options(),
            ))
            .unwrap();
    }
    gate.held.wait_for(2);
}

#[test]
// Review of heartwood #4, round 2: a dial refused because alice's resolver
// queue is full is her own failure, and costs bob nothing: 32 of them would
// have put him past the threshold of automatic connections.
fn test_dial_a_full_resolver_queue_costs_the_peer_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob, _dan, gate, book) = penalty_fixture(tmp.path(), time::Duration::from_secs(30));
    let before = penalty(&alice, &bob, &book);
    hold_resolvers(&alice, &gate);
    // And fill the queue.
    for i in 0..2u8 {
        let key = SigningKey::from_seed(radicle::crypto::Seed::new([100 + i; 32]));
        alice
            .handle
            .command(service::Command::Connect(
                *key.public_key(),
                format!("queued-{i}.test:8776").parse().unwrap(),
                connect_options(),
            ))
            .unwrap();
    }
    for _ in 0..32 {
        let result = alice
            .handle
            .clone()
            .connect(bob.id, by_name(&bob), connect_options())
            .unwrap();
        assert!(
            matches!(&result, ConnectResult::Disconnected { reason } if reason.contains("too many names are being resolved")),
            "{result:?}"
        );
    }
    let after = penalty(&alice, &bob, &book);
    gate.held.release();
    assert_eq!(after, before);
    assert!(!after.is_connect_threshold_reached());
}

#[test]
// Review of heartwood #4, round 2: a name whose dial gives up while it waits
// in alice's queue was never tried, and costs bob nothing.
fn test_dial_a_name_left_in_the_queue_costs_the_peer_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob, _dan, gate, book) =
        penalty_fixture(tmp.path(), time::Duration::from_millis(300));
    let before = penalty(&alice, &bob, &book);
    hold_resolvers(&alice, &gate);
    let result = alice
        .handle
        .clone()
        .connect(bob.id, by_name(&bob), connect_options())
        .unwrap();
    assert!(
        matches!(&result, ConnectResult::Disconnected { reason } if reason.contains("no resolver was free")),
        "{result:?}"
    );
    let after = penalty(&alice, &bob, &book);
    gate.held.release();
    assert_eq!(after, before);
}

#[test]
// Review of heartwood #4, round 2: a name a resolver tried, and that didn't
// resolve in time, is bob's, and costs him as a failed dial always has.
fn test_dial_a_name_too_slow_to_resolve_costs_the_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob, _dan, gate, book) =
        penalty_fixture(tmp.path(), time::Duration::from_millis(300));
    let before = penalty(&alice, &bob, &book);
    let result = alice
        .handle
        .clone()
        .connect(bob.id, by_name(&bob), connect_options())
        .unwrap();
    assert!(
        matches!(&result, ConnectResult::Disconnected { reason } if reason.contains("name resolution timed out")),
        "{result:?}"
    );
    let after = penalty(&alice, &bob, &book);
    gate.held.release();
    assert!(after > before, "{after:?} after {before:?}");
}
