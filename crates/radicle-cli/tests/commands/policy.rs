use crate::test;
use crate::util::environment::Environment;
use radicle::node;
use radicle::node::Alias;
use radicle::node::config::DefaultSeedingPolicy;

#[test]
fn rad_seed_and_follow() {
    Environment::alice(["rad-seed-and-follow"]);
}

#[test]
fn rad_seed_scope() {
    Environment::alice(["rad-seed-scope"]);
}

#[test]
fn rad_seed_many() {
    let mut environment = Environment::new();
    let alice = environment.node("alice");
    let mut bob = environment.node("bob");
    // Bob creates two projects that Alice seeds in the test
    let _ = bob.project("heartwood", "Radicle Heartwood Protocol & Stack");
    let _ = bob.project("nixpkgs", "Home for Nix Packages");
    let alice = alice.spawn();
    let mut bob = bob.spawn();

    bob.connect(&alice).converge([&alice]);

    test(
        "examples/rad-seed-many.md",
        environment.work(&alice),
        Some(&alice.home),
        [],
    )
    .unwrap();
}

#[test]
fn rad_unseed() {
    let mut environment = Environment::new();
    let mut alice = environment.node("alice");
    let working = tempfile::tempdir().unwrap();

    // Set up a test project.
    alice.project("heartwood", "Radicle Heartwood Protocol & Stack");
    let alice = alice.spawn();

    test("examples/rad-unseed.md", working, Some(&alice.home), []).unwrap();
}

#[test]
fn rad_unseed_many() {
    let mut environment = Environment::new();
    let mut alice = environment.node("alice");

    // Set up a test project.
    alice.project("heartwood", "Radicle Heartwood Protocol & Stack");
    alice.project("nixpkgs", "Home for Nix Packages");
    let alice = alice.spawn();

    test(
        "examples/rad-unseed-many.md",
        environment.work(&alice),
        Some(&alice.home),
        [],
    )
    .unwrap();
}

#[test]
fn rad_block() {
    let mut environment = Environment::new();
    let alice = environment.node_with(radicle::node::Config {
        seeding_policy: DefaultSeedingPolicy::permissive(),
        ..radicle::node::Config::test(Alias::new("alice"))
    });
    let working = tempfile::tempdir().unwrap();

    test("examples/rad-block.md", working, Some(&alice.home), []).unwrap();
}

#[test]
// Review of heartwood #26, round 3: beside a running node, `rad unblock <rid>`
// goes through the node, under a permissive default, and the repository is
// cloned after it.
fn rad_unblock_through_the_node() {
    use radicle::node::Handle as _;
    use radicle::node::policy::{Policy, Scope};

    let mut environment = Environment::new();
    let mut alice = environment.node("alice");
    let mut bob = environment.node_with(radicle::node::Config {
        seeding_policy: DefaultSeedingPolicy::permissive(),
        ..radicle::node::Config::test(Alias::new("bob"))
    });
    let working = environment.tempdir().join("working");
    let acme = alice.project("heartwood", "Radicle Heartwood Protocol & Stack");
    // What a removal leaves under a permissive default.
    bob.policies.set_seed_policy(&acme, Policy::Block).unwrap();

    let mut alice = alice.spawn();
    let mut bob = bob.spawn();
    // Prevent Alice from fetching Bob's fork, as we're not testing that.
    alice.handle.seed(acme, Scope::Followed).unwrap();
    bob.connect(&alice).converge([&alice]);

    test(
        "examples/rad-unblock-through-the-node.md",
        working,
        Some(&bob.home),
        [],
    )
    .unwrap();
}

#[test]
fn rad_seed_policy_allow_no_scope() {
    let mut environment = Environment::new();
    let alice = environment.node_with(radicle::node::Config {
        seeding_policy: DefaultSeedingPolicy::Allow {
            scope: node::config::Scope::implicit(),
        },
        ..radicle::node::Config::test(Alias::new("alice"))
    });

    let alice = alice.spawn();

    test(
        "examples/rad-seed-policy-allow-no-scope.md",
        environment.work(&alice),
        Some(&alice.home),
        [],
    )
    .unwrap();
}
