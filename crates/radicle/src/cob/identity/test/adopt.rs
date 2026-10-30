//! Security R-22: a chain of pending revisions is adopted without recursion,
//! in the order the recursion took.

use std::collections::HashMap;

use crate::cob::identity::{Identity, RejectedBy, Revision, RevisionId, State, Verdict};
use crate::cob::{self, Author, Timestamp};
use crate::crypto::{PublicKey, Signature, Signer as _, SigningKey};
use crate::git::Oid;
use crate::identity::Doc;
use crate::storage::ReadRepository as _;
use crate::test::setup::NodeWithRepo;

/// The recursive adoption the iterative one replaces, as the reference.
fn adopt_recursively(identity: &mut Identity, id: RevisionId) {
    if identity.current == id {
        return;
    }
    let candidate = identity.revision(&id).expect("revision exists");
    assert_eq!(candidate.state, State::Active);
    let parent = candidate.parent.expect("revision has parent");
    if parent != identity.current {
        return;
    }
    let votes = candidate.accepted().count();
    if !identity.is_majority(votes) {
        return;
    }
    for sibling in identity.siblings_of(&id).copied().collect::<Vec<_>>() {
        let Some(revision) = identity.revisions.get_mut(&sibling) else {
            continue;
        };
        if revision.state != State::Active {
            continue;
        }
        revision.state = State::Rejected(RejectedBy::Sibling(id));
        identity.cascade(sibling, State::Rejected(RejectedBy::Parent));
    }
    identity.current = id;
    identity
        .revision_mut(&id)
        .expect("current revision exists")
        .state = State::Accepted;
    let children_to_adopt = identity
        .children_of(&id)
        .filter(|child| {
            identity.revisions.get(child).is_some_and(|r| {
                r.state == State::Active
                    && identity
                        .is_majority(r.accepted().filter(|did| identity.is_delegate(did)).count())
            })
        })
        .copied()
        .collect::<Vec<_>>();
    for child in children_to_adopt {
        adopt_recursively(identity, child);
    }
}

/// An identity held in memory, with no store behind it, and the delegates
/// of its every revision.
struct InMemory {
    identity: Identity,
    doc: Doc,
    delegates: Vec<PublicKey>,
}

/// A revision ID for `n`.
fn revision_id(n: u32) -> RevisionId {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    bytes[19] = 0xad;
    Oid::from_sha1(bytes)
}

impl InMemory {
    /// An identity whose root revision, accepted, has `delegates` delegates.
    fn new(delegates: usize) -> Self {
        let NodeWithRepo { node, repo } = NodeWithRepo::default();
        let mut raw = repo.identity_doc().unwrap().doc.edit();
        let mut keys = vec![*node.signer.public_key()];
        for i in 1..delegates {
            let key = *SigningKey::mock(200 + i).public_key();
            raw.delegate(key.into());
            keys.push(key);
        }
        let doc = raw.verified().unwrap();
        let root = revision_id(0);
        let mut this = Self {
            identity: Identity {
                current: root,
                root,
                revisions: HashMap::new(),
                timeline: vec![],
            },
            doc,
            delegates: keys,
        };
        this.insert(root, None, 0, &[], State::Accepted);
        this
    }

    /// Adds the revision `id`, authored by the delegate `author`, with the
    /// accepts of the delegates `voters` too, as a child of `parent`.
    fn insert(
        &mut self,
        id: RevisionId,
        parent: Option<RevisionId>,
        author: usize,
        voters: &[usize],
        state: State,
    ) {
        let signature = |n: usize| Signature::from_bytes(&[n as u8 + 1; 64]);
        let mut revision = Revision::new(
            id,
            cob::Title::new("A revision").unwrap(),
            String::new(),
            Author::new(self.delegates[author]),
            id,
            self.doc.clone(),
            state,
            signature(author),
            parent,
            Timestamp::from_secs(0),
        );
        for voter in voters {
            revision
                .verdicts
                .insert(self.delegates[*voter], Verdict::Accept(signature(*voter)));
        }
        self.identity.revisions.insert(id, revision);
        self.identity.timeline.push(id);
        if let Some(parent) = parent {
            self.identity
                .revisions
                .get_mut(&parent)
                .unwrap()
                .children
                .push(id);
        }
    }

    /// Adds the delegate `voter`'s accept to the revision `id`.
    fn accept(&mut self, id: RevisionId, voter: usize) {
        let signature = Signature::from_bytes(&[voter as u8 + 1; 64]);
        self.identity
            .revisions
            .get_mut(&id)
            .unwrap()
            .verdicts
            .insert(self.delegates[voter], Verdict::Accept(signature));
    }
}

#[test]
// The iterative adoption leaves exactly the identity the recursive one did,
// its current revision and every revision's state, on random trees of
// revisions, adopting one after another. Each delegate accepts at most one
// child of a revision, as `apply` holds them to.
fn adoption_keeps_the_recursive_result() {
    let mut rng = fastrand::Rng::with_seed(0xad09);
    let base = InMemory::new(3);
    let mut cascades = 0;
    for _ in 0..300 {
        let mut tree = InMemory {
            identity: base.identity.clone(),
            doc: base.doc.clone(),
            delegates: base.delegates.clone(),
        };
        let len = rng.u32(2..40);
        // Who accepted a child of each revision already.
        let mut voted: HashMap<RevisionId, Vec<usize>> = HashMap::new();
        let mut inserted = vec![revision_id(0)];
        for n in 1..len {
            let parent = inserted[rng.usize(0..inserted.len())];
            let author = rng.usize(0..3);
            let taken = voted.entry(parent).or_default();
            if taken.contains(&author) {
                continue;
            }
            taken.push(author);
            let voters: Vec<usize> = (0..3)
                .filter(|v| *v != author && !taken.contains(v) && rng.bool())
                .collect();
            taken.extend(&voters);
            tree.insert(revision_id(n), Some(parent), author, &voters, State::Active);
            inserted.push(revision_id(n));
        }
        let mut iterative = tree.identity.clone();
        let mut recursive = tree.identity.clone();
        for _ in 0..rng.usize(1..6) {
            let id = revision_id(rng.u32(1..len));
            let Some(revision) = iterative.revision(&id) else {
                continue;
            };
            if revision.state != State::Active {
                continue;
            }
            iterative.adopt(id);
            adopt_recursively(&mut recursive, id);
            assert_eq!(iterative, recursive);
            if iterative.current != id && iterative.current != tree.identity.current {
                cascades += 1;
            }
        }
    }
    // Adoptions went on past the revision adopted, often enough.
    assert!(cascades > 50, "{cascades} cascades");
}

#[test]
// Security R-22: a chain of pending revisions, each a child of the one
// before, each with the quorum but its first, is adopted whole once its
// first gets the quorum, on a 256 KiB stack, where the recursive adoption
// overflowed it.
fn a_long_chain_of_pending_revisions_is_adopted_without_recursion() {
    const LEN: u32 = 10_000;
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let mut tree = InMemory::new(2);
            tree.insert(revision_id(1), Some(revision_id(0)), 0, &[], State::Active);
            for n in 2..=LEN {
                tree.insert(
                    revision_id(n),
                    Some(revision_id(n - 1)),
                    0,
                    &[1],
                    State::Active,
                );
            }
            tree.identity.adopt(revision_id(1));
            assert_eq!(tree.identity.current, revision_id(0), "no quorum yet");

            tree.accept(revision_id(1), 1);
            tree.identity.adopt(revision_id(1));
            assert_eq!(tree.identity.current, revision_id(LEN));
            for n in 1..=LEN {
                assert_eq!(
                    tree.identity.revision(&revision_id(n)).unwrap().state,
                    State::Accepted
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
// Security R-22, as a peer would make it: with two delegate keys, Alice
// proposes a chain of revisions, each on the one before, none adopted, since
// each needs Bob too. Bob accepts them out of order, the last first, and the
// chain's first last: then the whole chain is adopted, in one cascade, as
// the identity is evaluated from the store.
fn a_chain_of_pending_revisions_accepted_out_of_order_is_adopted_whole() {
    use crate::cob::identity::Transaction;

    const LEN: usize = 24;
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let bob = SigningKey::mock(0xb0b);
    let title = cob::Title::new("A revision").unwrap();
    let mut alice = Identity::load_mut(&*repo, &node.signer).unwrap();
    // Bob becomes a delegate too: from then on, a revision needs both.
    let mut doc = alice.doc().clone().edit();
    doc.delegate(bob.public_key().into());
    let r1 = alice
        .update(title.clone(), "", &doc.clone().verified().unwrap())
        .unwrap();
    assert_eq!(alice.current, r1);

    let mut chain = Vec::new();
    let mut parent = r1;
    for i in 0..LEN {
        // Each document differs from the one before.
        doc.threshold = if i % 2 == 0 { 2 } else { 1 };
        let tx = Transaction::new_revision(
            title.clone(),
            "",
            &doc.clone().verified().unwrap(),
            Some(parent),
            &*repo,
            &node.signer,
        )
        .unwrap();
        let (identity, id) = tx
            .commit("Propose revision", alice.id, &mut alice.store)
            .unwrap();
        alice.identity = identity;
        chain.push(id);
        parent = id;
    }
    assert_eq!(alice.current, r1);
    assert!(
        chain
            .iter()
            .all(|id| alice.revision(id).unwrap().state == State::Active)
    );

    {
        let mut bob = Identity::load_mut(&*repo, &bob).unwrap();
        for id in chain[1..].iter().rev() {
            bob.accept(id).unwrap();
            assert_eq!(bob.current, r1, "adopted before its parent");
        }
    }
    Identity::load_mut(&*repo, &bob)
        .unwrap()
        .accept(&chain[0])
        .unwrap();
    // Evaluated from the store afresh: the whole chain is adopted.
    let loaded = Identity::load_mut(&*repo, &node.signer).unwrap();
    assert_eq!(loaded.current, *chain.last().unwrap());
    assert!(
        chain
            .iter()
            .all(|id| loaded.revision(id).unwrap().state == State::Accepted)
    );
}
