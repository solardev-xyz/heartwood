//! Identity evaluation is bounded: it reads delegates' namespaces only, and
//! within [`IDENTITY_LIMITS`], so another peer's identity changes can't make
//! every identity check cost what that peer chooses.

use nonempty::NonEmpty;

use crate::cob::identity::{self, Action, Identity, State, TYPENAME};
use crate::cob::store::encoding;
use crate::cob::{self, Embed, ObjectId, Title};
use crate::crypto::signature::Signer as _;
use crate::crypto::{PublicKey, Signer as _, SigningKey};
use crate::git::Oid;
use crate::identity::{Doc, Visibility};
use crate::storage::{
    IdentityDocError, ReadRepository as _, ReadStorage as _, RepositoryError, WriteRepository as _,
};
use crate::test::setup::NodeWithRepo;

use super::{IDENTITY_LIMITS, IdentityRead, IdentityTips, Repository};

/// Writes an identity change of `actions` by `signer`, on `parents`, with
/// `embeds`, and points `signer`'s reference of the identity at it.
fn write(
    repo: &Repository,
    signer: &SigningKey,
    root: &ObjectId,
    parents: Vec<Oid>,
    embeds: Vec<Embed<Oid>>,
    action: &Action,
) -> Oid {
    let entry = cob::change::Storage::store(
        repo,
        None,
        vec![],
        signer,
        cob::change::Template {
            type_name: TYPENAME.clone(),
            tips: parents,
            message: "Identity change".to_owned(),
            embeds,
            contents: NonEmpty::new(encoding::encode(action).unwrap()),
        },
    )
    .unwrap();
    cob::object::Storage::update(repo, signer.public_key(), &TYPENAME, root, &entry.id).unwrap();

    entry.id
}

/// A chain of `len` changes by `signer` on `base`, each a verdict on the
/// root revision, which is accepted already: a change anyone may write,
/// which changes nothing and yet is applied, so it is part of the history.
fn stuff(repo: &Repository, signer: &SigningKey, root: &ObjectId, base: Oid, len: usize) -> Oid {
    let signature = signer.sign(b"anything");
    let mut tip = base;
    for _ in 0..len {
        let accept = Action::RevisionAccept {
            revision: **root,
            signature,
        };
        tip = write(repo, signer, root, vec![tip], vec![], &accept);
    }
    tip
}

/// The identity as upstream evaluates it: from every namespace, unbounded.
fn upstream(repo: &Repository, root: &ObjectId) -> cob::CollaborativeObject<Identity> {
    cob::get::<Identity, _>(repo, &TYPENAME, root)
        .unwrap()
        .unwrap()
}

/// The identity as this fork evaluates it, within `limits`.
fn evaluate(
    repo: &Repository,
    root: &ObjectId,
    limits: &cob::Limits,
) -> Result<(Identity, IdentityRead), crate::cob::store::Error> {
    let refs = cob::object::Storage::objects(repo, &TYPENAME, root).unwrap();
    repo.evaluate_identity(root, &IdentityTips::from(&refs), limits)
        .map(|(identity, read, _)| (identity, read))
}

/// Whether `result` failed at a limit of identity evaluation.
fn is_limit<T: std::fmt::Debug>(result: &Result<T, IdentityDocError>) -> bool {
    matches!(
        result,
        Err(IdentityDocError::Repository(err)) if matches!(
            **err,
            RepositoryError::Store(cob::store::Error::Retrieve(cob::error::Retrieve::Limit(_)))
        )
    )
}

/// The keys of the namespaces an evaluation read.
fn read_keys(read: &IdentityRead) -> Vec<PublicKey> {
    match read {
        IdentityRead::Delegates(keys) => keys.keys().copied().collect(),
        IdentityRead::All(_) => panic!("every namespace was read"),
    }
}

/// Each revision of `identity`, with its state and its verdicts' authors.
fn revisions(identity: &Identity) -> Vec<(Oid, State, Vec<PublicKey>)> {
    let mut revisions = identity
        .revisions()
        .map(|r| {
            let mut verdicts = r.verdicts().map(|(key, _)| *key).collect::<Vec<_>>();
            verdicts.sort();
            (r.id, r.state, verdicts)
        })
        .collect::<Vec<_>>();
    revisions.sort_by_key(|(id, _, _)| *id);
    revisions
}

#[test]
fn a_peer_namespace_stuffed_with_identity_changes_is_not_read() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let alice = node.signer.public_key();
    let root = ObjectId::from(repo.identity_root().unwrap());
    let doc = repo.identity_doc().unwrap();
    let eve = SigningKey::mock(31);

    // Eve, no delegate, writes more identity changes than the limits allow.
    stuff(&repo, &eve, &root, *root, IDENTITY_LIMITS.changes + 64);

    // Upstream applies every one of them: anyone can make the history, which
    // every identity check evaluates, as long as they like.
    let upstream = upstream(&repo, &root);
    assert_eq!(upstream.history.len(), IDENTITY_LIMITS.changes + 65);
    assert_eq!(upstream.object.current, *root);

    // Here, Eve's namespace isn't read: the evaluation reads Alice's root,
    // and fits in limits of one change.
    let one = cob::Limits {
        changes: 1,
        ..IDENTITY_LIMITS
    };
    let (identity, read) = evaluate(&repo, &root, &one).unwrap();
    assert_eq!(identity.current, *root);
    assert_eq!(read_keys(&read), vec![*alice]);

    // A fresh handle, as `Worker::is_authorized` opens for each inbound
    // fetch, gets the same document.
    let fresh = node.storage.repository(repo.id).unwrap();
    assert_eq!(fresh.identity_doc().unwrap(), doc);
    assert_eq!(fresh.canonical_identity_head().unwrap(), *root);
}

#[test]
fn a_delegate_history_past_the_limits_is_refused() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let root = ObjectId::from(repo.identity_root().unwrap());
    let eve = SigningKey::mock(31);
    let len = IDENTITY_LIMITS.changes + 64;
    let tip = stuff(&repo, &eve, &root, *root, len);

    // Alice updates the identity, as upstream's client does it, having
    // fetched Eve's changes: they are applied, so the history's tip is
    // Eve's, and Alice's revision builds on it.
    let mut identity = identity::Identity::load_mut(&*repo, &node.signer).unwrap();
    let mut doc = identity.doc().clone().edit();
    doc.delegate(SigningKey::mock(103).public_key().into());
    let revision = identity
        .update(Title::new("Add Bob").unwrap(), "", &doc.verified().unwrap())
        .unwrap();
    let parents = repo.raw().find_commit(revision.into()).unwrap();
    assert!(parents.parent_ids().any(|parent| Oid::from(parent) == tip));
    assert_eq!(upstream(&repo, &root).history.len(), len + 2);

    // Alice's history is now past the limits: the identity doesn't load, and
    // each lookup stops at the limit rather than reading the history.
    let fresh = node.storage.repository(repo.id).unwrap();
    assert!(is_limit(&fresh.identity_doc()));
    assert!(is_limit(&fresh.identity_doc_at(*root)));
    assert!(fresh.canonical_identity_head().is_err());
}

#[test]
fn a_document_past_the_byte_limit_is_refused_before_it_is_read() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let root = ObjectId::from(repo.identity_root().unwrap());

    // Alice proposes a revision whose document is past the byte limit.
    let large = vec![b' '; IDENTITY_LIMITS.bytes as usize + 1];
    let blob = Oid::from(repo.raw().blob(&large).unwrap());
    let revision = Action::Revision {
        title: Title::new("Large").unwrap(),
        description: String::new(),
        blob,
        parent: Some(*root),
        signature: node.signer.sign(&large),
    };
    let embed = Embed {
        name: "radicle.json".to_owned(),
        content: blob,
    };
    write(
        &repo,
        &node.signer,
        &root,
        vec![*root],
        vec![embed],
        &revision,
    );

    let fresh = node.storage.repository(repo.id).unwrap();
    assert!(is_limit(&fresh.identity_doc()));
}

#[test]
fn an_honest_identity_evaluates_as_upstream_evaluates_it() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let alice = &node.signer;
    let bob = SigningKey::mock(103);
    let carol = SigningKey::mock(107);
    let eve = SigningKey::mock(31);
    let root = ObjectId::from(repo.identity_root().unwrap());
    let title = Title::new("Identity update").unwrap();

    // Alice adds Bob: accepted, as she is the only delegate.
    let mut identity = identity::Identity::load_mut(&*repo, alice).unwrap();
    let mut doc = identity.doc().clone().edit();
    doc.delegate(bob.public_key().into());
    let r1 = identity
        .update(title.clone(), "", &doc.clone().verified().unwrap())
        .unwrap();
    // Bob, from his namespace, proposes adding Carol; Alice accepts.
    let mut identity = identity::Identity::load_mut(&*repo, &bob).unwrap();
    doc.delegate(carol.public_key().into());
    let r2 = identity
        .update(title.clone(), "", &doc.clone().verified().unwrap())
        .unwrap();
    identity::Identity::load_mut(&*repo, alice)
        .unwrap()
        .accept(&r2)
        .unwrap();
    // Carol, from hers, proposes a private repository; Bob accepts, which
    // makes a majority of three.
    let mut identity = identity::Identity::load_mut(&*repo, &carol).unwrap();
    doc.visibility = Visibility::private([]);
    let r3 = identity
        .update(title.clone(), "", &doc.clone().verified().unwrap())
        .unwrap();
    identity::Identity::load_mut(&*repo, &bob)
        .unwrap()
        .accept(&r3)
        .unwrap();
    // A pending revision of Carol's, and some of Eve's changes.
    doc.threshold = 2;
    let r4 = identity::Identity::load_mut(&*repo, &carol)
        .unwrap()
        .update(title, "", &doc.verified().unwrap())
        .unwrap();
    stuff(&repo, &eve, &root, r3, 8);

    let expected = upstream(&repo, &root).object;
    assert_eq!(expected.current, r3);
    assert_eq!(expected.revision(&r4).unwrap().state, State::Active);
    let mut delegates = vec![*alice.public_key(), *bob.public_key(), *carol.public_key()];
    delegates.sort();

    let check = |repo: &Repository| {
        let (identity, read) = evaluate(repo, &root, &IDENTITY_LIMITS).unwrap();
        assert_eq!(identity.current, expected.current);
        assert_eq!(revisions(&identity), revisions(&expected));
        assert_eq!(read_keys(&read), delegates);
        for revision in [*root, r1, r2, r3] {
            assert_eq!(
                repo.identity_doc_at(revision).unwrap(),
                Doc::load_at(revision, repo).unwrap()
            );
        }
        assert!(matches!(
            repo.identity_doc_at(r4),
            Err(IdentityDocError::UnacceptedRevision(id)) if id == r4
        ));
        assert_eq!(repo.canonical_identity_head().unwrap(), r3);
    };
    // With `rad/id` behind, at the root: the namespaces of the delegates
    // added since are found from the revisions that add them.
    repo.set_identity_head_to(*root).unwrap();
    check(&node.storage.repository(repo.id).unwrap());
    // With `rad/id` current.
    repo.set_identity_head_to(r3).unwrap();
    check(&node.storage.repository(repo.id).unwrap());

    // Without the founder's namespace: the other delegates' hold the history.
    let alice_ref =
        crate::git::refs::storage::cob_with_namespace(alice.public_key(), &TYPENAME, &root);
    repo.raw()
        .find_reference(alice_ref.as_str())
        .unwrap()
        .delete()
        .unwrap();
    check(&node.storage.repository(repo.id).unwrap());
}

#[test]
fn every_namespace_is_read_when_no_delegate_has_one() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let alice = node.signer.public_key();
    let root = ObjectId::from(repo.identity_root().unwrap());
    let bob = SigningKey::mock(103);

    // Bob holds a copy of Alice's history in his namespace, and Alice's
    // namespace has none.
    cob::object::Storage::update(&*repo, bob.public_key(), &TYPENAME, &root, &*root).unwrap();
    let alice_ref = crate::git::refs::storage::cob_with_namespace(alice, &TYPENAME, &root);
    repo.raw()
        .find_reference(alice_ref.as_str())
        .unwrap()
        .delete()
        .unwrap();

    let (identity, read) = evaluate(&repo, &root, &IDENTITY_LIMITS).unwrap();
    assert_eq!(identity.current, *root);
    assert!(matches!(read, IdentityRead::All(_)));
}

#[test]
fn a_cached_identity_is_evaluated_again_only_once_a_delegate_writes() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let alice = &node.signer;
    let bob = SigningKey::mock(103);
    let eve = SigningKey::mock(31);
    let root = ObjectId::from(repo.identity_root().unwrap());
    let reader = node.storage.repository(repo.id).unwrap();
    assert_eq!(reader.identity().unwrap().current, *root);

    // Eve's changes don't touch a delegate's namespace: the cached
    // evaluation still holds.
    stuff(&repo, &eve, &root, *root, 2);
    let cached = reader.cached_identity.borrow();
    let tips =
        IdentityTips::from(&cob::object::Storage::objects(&*repo, &TYPENAME, &root).unwrap());
    assert!(cached.as_ref().unwrap().read.is_current(&tips));
    drop(cached);

    // Alice's change, through another handle, does.
    let mut identity = identity::Identity::load_mut(&*repo, alice).unwrap();
    let mut doc = identity.doc().clone().edit();
    doc.delegate(bob.public_key().into());
    let r1 = identity
        .update(Title::new("Add Bob").unwrap(), "", &doc.verified().unwrap())
        .unwrap();
    assert_eq!(reader.identity().unwrap().current, r1);
}

#[test]
fn a_fresh_handle_takes_the_identity_another_handle_evaluated() {
    let NodeWithRepo { node, repo } = NodeWithRepo::default();
    let root = ObjectId::from(repo.identity_root().unwrap());
    let expected = repo.identity_from(&root).unwrap().clone();

    // The root change's tree is gone from the objects: evaluating the
    // identity again would fail, while its references still list.
    let tree = repo.raw().find_commit((*root).into()).unwrap().tree_id();
    let hex = tree.to_string();
    let object = repo
        .raw()
        .path()
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..]);
    std::fs::remove_file(object).unwrap();
    let fresh = node.storage.repository(repo.id).unwrap();
    assert!(evaluate(&fresh, &root, &IDENTITY_LIMITS).is_err());

    // A fresh handle, as each inbound fetch opens, takes the evaluation an
    // earlier handle made, its references being as they were.
    assert_eq!(*fresh.identity_from(&root).unwrap(), expected);
}
