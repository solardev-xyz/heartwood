// Copyright © 2021 The Radicle Link Contributors

use std::ops::ControlFlow;
use std::{cmp::Ordering, collections::BTreeSet};

use dag::Dag;
use oid::Oid;

use crate::{
    CollaborativeObject, Entry, EntryId, History, ObjectId, TypeName, change, object,
    object::collaboration::Evaluate,
};

#[derive(Debug, thiserror::Error)]
pub enum EvaluateError {
    #[error("unable to initialize object: {0}")]
    Init(Box<dyn std::error::Error + Sync + Send + 'static>),
    #[error("invalid signature for entry '{0}'")]
    Signature(EntryId),
    #[error("root entry '{0}' missing from graph")]
    MissingRoot(EntryId),
    #[error("root entry '{0}' has parents")]
    RootHasParents(EntryId),
}

/// Bounds on a strict load ([`crate::get_strict`]): a COB past any of them
/// doesn't load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Changes in its history. Evaluating a history costs time on the order
    /// of the square of its length, so this bounds that too.
    pub changes: usize,
    /// Operations, the contents of its changes, in all.
    pub operations: usize,
    /// Bytes its changes' objects take, in all: each change is measured
    /// before it is read, where the store can tell.
    pub bytes: u64,
}

/// What lenient loads within [`Limits`] ([`crate::get_within`]) have read so
/// far. Loads that share one are bounded together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Spent {
    /// Changes read, or tried: one that doesn't load counts too.
    pub changes: usize,
    /// Operations of the changes read.
    pub operations: usize,
    /// Bytes of the changes' objects, each change measured before it is
    /// read, with what evaluating it reads besides.
    pub bytes: u64,
}

/// A lenient load within [`Limits`] ([`crate::get_within`]) stopped at one
/// of them, before reading past it.
#[derive(Debug, thiserror::Error)]
#[error("the COB has more than {limit} {what}")]
pub struct Exceeded {
    pub what: &'static str,
    pub limit: u64,
}

/// Why a COB doesn't load strictly: any change that doesn't load, or that a
/// lenient load would leave out, fails it, rather than leaving a partial
/// object.
#[derive(Debug, thiserror::Error)]
pub enum StrictError {
    #[error("change {id} doesn't load: {reason}")]
    Load { id: Oid, reason: String },
    #[error("the COB has more than {limit} {what}")]
    Limit { what: &'static str, limit: u64 },
    #[error("change {0} isn't of the COB: its history has another root")]
    Foreign(Oid),
    #[error("change {id} is of the type {typename}, not the COB's")]
    Type { id: Oid, typename: TypeName },
    #[error("change {id} is discarded: {reason}")]
    Discarded { id: EntryId, reason: String },
    #[error(transparent)]
    Evaluate(#[from] EvaluateError),
    #[error("the COB's load was stopped")]
    Stopped,
}

/// The graph of changes for a particular collaborative object
pub(super) struct ChangeGraph {
    object_id: ObjectId,
    graph: Dag<Oid, Entry>,
}

impl ChangeGraph {
    /// Load the change graph from the underlying git store by walking
    /// backwards from references to the object
    pub(crate) fn load<'a, S>(
        storage: &S,
        tip_refs: impl Iterator<Item = &'a object::Reference> + 'a,
        typename: &TypeName,
        oid: &ObjectId,
    ) -> Option<ChangeGraph>
    where
        S: change::Storage<
                ObjectId = Oid,
                Parent = Oid,
                PublicKey = crypto::PublicKey,
                Signature = crypto::Signature,
            >,
    {
        let tip_refs = tip_refs.collect::<Vec<_>>();

        if log::log_enabled!(log::Level::Debug) {
            log::debug!(target: "cob", "Loading object of type {typename} at {oid}.");
        } else if log::log_enabled!(log::Level::Trace) {
            log::trace!(target: "cob", "Loading object of type {typename} at {oid} from tips {}.", tip_refs.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", "));
        }

        let mut graph: Dag<Oid, Entry> = Dag::new();

        // Populate the initial set of node ids from the refs we have
        let mut child_ids = Vec::from_iter(tip_refs.into_iter().map(|r| r.target.id));
        let mut edges_to_add = Vec::new();

        while let Some(child_id) = child_ids.pop() {
            // Skip if we already processed this node.
            if graph.contains(&child_id) {
                continue;
            }

            match storage.load(child_id) {
                Ok(change) => {
                    for parent_id in &change.parents {
                        edges_to_add.push((child_id, *parent_id));
                        child_ids.push(*parent_id);
                        debug_assert_ne!(Some(*parent_id), change.resource);
                    }
                    graph.node(child_id, change);
                }
                Err(e) => {
                    log::warn!(
                        target: "cob",
                        "Unable to load change tree from commit {child_id}: {e}",
                    );
                }
            }
        }

        // The Dag::dependency() function implicitly assumes that both nodes already exist in the graph.
        // Therefore, we add the edges only after successfully processing all nodes.
        for (child_id, parent_id) in edges_to_add {
            if graph.contains(&parent_id) {
                graph.dependency(child_id, parent_id);
            }
        }

        graph.roots().next()?;

        Some(ChangeGraph {
            object_id: *oid,
            graph,
        })
    }

    /// Loads the change graph of `oid` strictly, from `tips` alone, within
    /// `limits`: every change must load, be of `typename`, and descend from
    /// the object's root. `None` if there are no tips. `stop` is asked
    /// before each change; once it says so, the load fails.
    pub(crate) fn load_strict<S>(
        storage: &S,
        tips: &[Oid],
        typename: &TypeName,
        oid: &ObjectId,
        limits: &Limits,
        stop: &dyn Fn() -> bool,
    ) -> Result<Option<ChangeGraph>, StrictError>
    where
        S: change::Storage<
                ObjectId = Oid,
                Parent = Oid,
                PublicKey = crypto::PublicKey,
                Signature = crypto::Signature,
            >,
    {
        let failed = |id: Oid, e: &dyn std::fmt::Display| StrictError::Load {
            id,
            reason: e.to_string(),
        };
        let mut graph: Dag<Oid, Entry> = Dag::new();
        let mut child_ids = tips.to_vec();
        let mut edges_to_add = Vec::new();
        let (mut bytes, mut operations) = (0u64, 0usize);

        while let Some(child_id) = child_ids.pop() {
            if graph.contains(&child_id) {
                continue;
            }
            if stop() {
                return Err(StrictError::Stopped);
            }
            if graph.len() >= limits.changes {
                return Err(StrictError::Limit {
                    what: "changes",
                    limit: limits.changes as u64,
                });
            }
            let left = limits.bytes - bytes;
            let measured = storage
                .size_of(&child_id, left)
                .map_err(|e| failed(child_id, &e))?;
            let too_large = || StrictError::Limit {
                what: "bytes",
                limit: limits.bytes,
            };
            if measured.is_some_and(|size| size > left) {
                return Err(too_large());
            }
            let change = storage.load(child_id).map_err(|e| failed(child_id, &e))?;
            // A store that can't measure beforehand is charged its contents.
            let size = measured.unwrap_or_else(|| {
                change
                    .contents
                    .iter()
                    .map(|content| content.len() as u64)
                    .sum()
            });
            bytes = bytes.saturating_add(size);
            if bytes > limits.bytes {
                return Err(too_large());
            }
            operations += change.contents.len();
            if operations > limits.operations {
                return Err(StrictError::Limit {
                    what: "operations",
                    limit: limits.operations as u64,
                });
            }
            if change.manifest.type_name != *typename {
                return Err(StrictError::Type {
                    id: child_id,
                    typename: change.manifest.type_name.clone(),
                });
            }
            for parent_id in &change.parents {
                edges_to_add.push((child_id, *parent_id));
                child_ids.push(*parent_id);
            }
            graph.node(child_id, change);
        }
        for (child_id, parent_id) in edges_to_add {
            graph.dependency(child_id, parent_id);
        }
        if graph.is_empty() {
            return Ok(None);
        }
        // The object's own change is its history's only root.
        if let Some((root, _)) = graph.roots().find(|(root, _)| **root != **oid) {
            return Err(StrictError::Foreign(*root));
        }
        Ok(Some(ChangeGraph {
            object_id: *oid,
            graph,
        }))
    }

    /// Loads the change graph of `oid` from `tips` as [`ChangeGraph::load`]
    /// does, leniently: a change that doesn't load is left out. But each
    /// change is counted against `limits`, on top of what `spent` holds,
    /// before it is read, and past any of them the load stops: a history is
    /// as long as its writers make it. `extra` gives the bytes evaluating a
    /// change reads besides the change itself, measured beforehand up to the
    /// bytes left, which it is given (past them, any number above them);
    /// they are charged with it. `None` if no change loads.
    pub(crate) fn load_within<S>(
        storage: &S,
        tips: &[Oid],
        typename: &TypeName,
        oid: &ObjectId,
        limits: &Limits,
        spent: &mut Spent,
        extra: &dyn Fn(&Oid, u64) -> u64,
    ) -> Result<Option<ChangeGraph>, Exceeded>
    where
        S: change::Storage<
                ObjectId = Oid,
                Parent = Oid,
                PublicKey = crypto::PublicKey,
                Signature = crypto::Signature,
            >,
    {
        log::debug!(target: "cob", "Loading object of type {typename} at {oid} within {limits:?}.");

        let mut graph: Dag<Oid, Entry> = Dag::new();
        let mut child_ids = tips.to_vec();
        let mut edges_to_add = Vec::new();
        // Changes that didn't load, which aren't tried again.
        let mut skipped = BTreeSet::new();

        while let Some(child_id) = child_ids.pop() {
            if graph.contains(&child_id) || skipped.contains(&child_id) {
                continue;
            }
            if spent.changes >= limits.changes {
                return Err(Exceeded {
                    what: "changes",
                    limit: limits.changes as u64,
                });
            }
            spent.changes += 1;

            let too_large = Exceeded {
                what: "bytes",
                limit: limits.bytes,
            };
            let left = limits.bytes.saturating_sub(spent.bytes);
            let measured = match storage.size_of(&child_id, left) {
                Ok(measured) => measured,
                Err(e) => {
                    log::warn!(target: "cob", "Unable to measure change {child_id}: {e}");
                    skipped.insert(child_id);
                    continue;
                }
            };
            if measured.is_some_and(|size| size > left) {
                return Err(too_large);
            }
            let besides = extra(&child_id, left - measured.unwrap_or(0));
            if let Some(size) = measured {
                let size = size.saturating_add(besides);
                if size > left {
                    return Err(too_large);
                }
                spent.bytes += size;
            }
            let change = match storage.load(child_id) {
                Ok(change) => change,
                Err(e) => {
                    log::warn!(
                        target: "cob",
                        "Unable to load change tree from commit {child_id}: {e}",
                    );
                    skipped.insert(child_id);
                    continue;
                }
            };
            // A store that can't measure beforehand is charged its contents.
            if measured.is_none() {
                let size = change
                    .contents
                    .iter()
                    .map(|content| content.len() as u64)
                    .sum::<u64>()
                    .saturating_add(besides);
                spent.bytes = spent.bytes.saturating_add(size);
                if spent.bytes > limits.bytes {
                    return Err(too_large);
                }
            }
            spent.operations += change.contents.len();
            if spent.operations > limits.operations {
                return Err(Exceeded {
                    what: "operations",
                    limit: limits.operations as u64,
                });
            }
            for parent_id in &change.parents {
                edges_to_add.push((child_id, *parent_id));
                child_ids.push(*parent_id);
            }
            graph.node(child_id, change);
        }
        for (child_id, parent_id) in edges_to_add {
            if graph.contains(&parent_id) {
                graph.dependency(child_id, parent_id);
            }
        }
        if graph.roots().next().is_none() {
            return Ok(None);
        }
        Ok(Some(ChangeGraph {
            object_id: *oid,
            graph,
        }))
    }

    /// Evaluates the graph strictly: a change whose signature is invalid, or
    /// whose actions don't apply, fails the evaluation, where
    /// [`ChangeGraph::evaluate`] would leave its branch out. `stop` is asked
    /// before each change.
    pub(crate) fn evaluate_strict<S, T: Evaluate<S>>(
        mut self,
        store: &S,
        stop: &dyn Fn() -> bool,
    ) -> Result<CollaborativeObject<T>, StrictError> {
        let root = *self.object_id;
        let root = self
            .graph
            .get(&root)
            .ok_or(EvaluateError::MissingRoot(root))?;
        if !root.valid_signatures() {
            return Err(EvaluateError::Signature(root.id).into());
        }
        // As in `evaluate`: a root has no COB parents. `load_strict` already
        // fails such a history, its parents being another root.
        if !root.parents.is_empty() {
            return Err(EvaluateError::RootHasParents(root.id).into());
        }
        let mut object =
            T::init(&root.value, store).map_err(|e| EvaluateError::Init(Box::new(e)))?;
        let children = Vec::from_iter(root.dependents.iter().cloned());
        let manifest = root.manifest.clone();
        let root = root.id;

        let mut failure = None;
        self.graph.prune_by(
            &children,
            |_, entry, siblings| {
                // Once one change has failed, nothing more is applied.
                if failure.is_some() {
                    return ControlFlow::Break(());
                }
                if stop() {
                    failure = Some(StrictError::Stopped);
                    return ControlFlow::Break(());
                }
                if !entry.valid_signatures() {
                    failure = Some(StrictError::Discarded {
                        id: entry.id,
                        reason: "its signature is invalid".to_owned(),
                    });
                    return ControlFlow::Break(());
                }
                if let Err(err) = object.apply(entry, siblings.map(|(k, n)| (k, &n.value)), store) {
                    failure = Some(StrictError::Discarded {
                        id: entry.id,
                        reason: err.to_string(),
                    });
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
            Self::chronological,
        );
        if let Some(failure) = failure {
            return Err(failure);
        }
        Ok(CollaborativeObject {
            manifest,
            object,
            history: History::new(root, self.graph),
            id: self.object_id,
        })
    }

    /// Given a graph evaluate it to produce a collaborative object. This will
    /// filter out branches of the graph which do not have valid signatures.
    pub(crate) fn evaluate<S, T: Evaluate<S>>(
        mut self,
        store: &S,
    ) -> Result<CollaborativeObject<T>, EvaluateError> {
        let root = *self.object_id;
        let root = self
            .graph
            .get(&root)
            .ok_or(EvaluateError::MissingRoot(root))?;

        if !root.valid_signatures() {
            return Err(EvaluateError::Signature(root.id));
        }
        if !root.parents.is_empty() {
            return Err(EvaluateError::RootHasParents(root.id));
        }
        // Evaluate the root separately, since we can't have a COB without a valid root.
        // Then, traverse the graph starting from the root's dependents, building the
        // `applied` DAG directly so only applied descendants of `root` form the history.
        let mut object =
            T::init(&root.value, store).map_err(|e| EvaluateError::Init(Box::new(e)))?;
        let children = Vec::from_iter(root.dependents.iter().cloned());
        let manifest = root.manifest.clone();
        let mut applied = Dag::root(root.id, root.value.clone());
        let root = root.id;

        self.graph.prune_by(
            &children,
            |id, entry, siblings| {
                // Every COB parent must have been applied before the entry.
                if !entry.parents.iter().all(|p| applied.contains(p)) {
                    log::debug!("Entry {} has a parent that was not applied.", entry.id);
                    return ControlFlow::Break(());
                }
                // Check the entry signatures are valid.
                if !entry.valid_signatures() {
                    log::debug!("Signature verification failed for entry {}.", entry.id);
                    return ControlFlow::Break(());
                }
                // Apply the entry to the state, and if there is an error, prune that branch.
                if let Err(err) = object.apply(entry, siblings.map(|(k, n)| (k, &n.value)), store) {
                    log::debug!("Application of entry {} returned error: {err}", entry.id);
                    return ControlFlow::Break(());
                }
                applied.node(*id, entry.value.clone());
                for parent in &entry.dependencies {
                    applied.dependency(*id, *parent);
                }
                ControlFlow::Continue(())
            },
            Self::chronological,
        );

        Ok(CollaborativeObject {
            manifest,
            object,
            history: History::new(root, applied),
            id: self.object_id,
        })
    }

    /// Get the tips of the collaborative object
    pub(crate) fn tips(&self) -> BTreeSet<Oid> {
        self.graph.tips().map(|(_, change)| *change.id()).collect()
    }

    pub(crate) fn number_of_nodes(&self) -> usize {
        self.graph.len()
    }

    fn chronological(x: (&Oid, &Entry), y: (&Oid, &Entry)) -> Ordering {
        x.1.timestamp.cmp(&y.1.timestamp).then(x.0.cmp(y.0))
    }
}

#[cfg(all(test, feature = "git2"))]
#[allow(clippy::unwrap_used)]
mod test {
    use nonempty::NonEmpty;

    use super::*;
    use crate::change::{Storage as _, Template};
    use crate::object::{Commit, Objects, Reference, collaboration::get_from_objects};

    fn store(repo: &git2::Repository, parents: Vec<Oid>, message: &str) -> Entry {
        repo.store(
            None,
            vec![],
            &crypto::SigningKey::mock(1),
            Template {
                type_name: "xyz.radicle.issue".parse().unwrap(),
                tips: parents,
                message: message.to_owned(),
                embeds: vec![],
                contents: NonEmpty::new(message.as_bytes().to_vec()),
            },
        )
        .unwrap()
    }

    // Write a parent link without requiring the parent or its tree to be readable.
    // COB signatures cover the tree, so adding a parent preserves the signature.
    fn with_parent(repo: &git2::Repository, entry: &Entry, parent: Oid) -> Oid {
        let odb = repo.odb().unwrap();
        let object = odb.read(entry.id.into()).unwrap();
        let commit = std::str::from_utf8(object.data()).unwrap();
        let (tree, rest) = commit.split_once('\n').unwrap();
        odb.write(
            git2::ObjectType::Commit,
            format!("{tree}\nparent {parent}\n{rest}").as_bytes(),
        )
        .unwrap()
        .into()
    }

    fn unreadable_parents(repo: &git2::Repository, root: &Entry) -> Vec<Oid> {
        let missing = "1111111111111111111111111111111111111111".parse().unwrap();
        let sig = git2::Signature::now("test", "test@example.com").unwrap();
        let tree = repo.find_tree(root.revision.into()).unwrap();
        // A COB tree without the required signature is not a plain code commit.
        let unsigned = repo
            .commit(None, &sig, &sig, "unsigned", &tree, &[])
            .unwrap();
        let odb = repo.odb().unwrap();
        let object = odb.read(unsigned).unwrap();
        let commit = std::str::from_utf8(object.data()).unwrap();
        let (_, rest) = commit.split_once('\n').unwrap();
        let missing_tree = odb
            .write(
                git2::ObjectType::Commit,
                format!("tree {missing}\n{rest}").as_bytes(),
            )
            .unwrap();
        let mut builder = repo.treebuilder(Some(&tree)).unwrap();
        let invalid = repo.blob(b"invalid manifest").unwrap();
        builder.insert("manifest", invalid, 0o100644).unwrap();
        let tree = repo.find_tree(builder.write().unwrap()).unwrap();
        let malformed = repo
            .commit(None, &sig, &sig, "malformed", &tree, &[])
            .unwrap();

        vec![
            missing,
            missing_tree.into(),
            unsigned.into(),
            malformed.into(),
        ]
    }

    fn setup() -> (tempfile::TempDir, git2::Repository) {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "test").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();
        (dir, repo)
    }

    fn objects(tip: Oid) -> Objects {
        Objects::new(Reference {
            name: "refs/cobs/test".to_owned().try_into().unwrap(),
            target: Commit { id: tip },
        })
    }

    #[test]
    fn unreadable_parents_block_entries_and_their_descendants() {
        let (_dir, repo) = setup();
        let root = store(&repo, vec![], "root");
        for parent in unreadable_parents(&repo, &root) {
            let entry = store(&repo, vec![root.id], "child");
            let child = with_parent(&repo, &entry, parent);
            let descendant = store(&repo, vec![child], "descendant");
            let object = get_from_objects::<NonEmpty<Entry>, _>(
                &repo,
                root.type_name(),
                &root.id.into(),
                &objects(descendant.id),
            )
            .unwrap()
            .unwrap();
            assert_eq!(object.history.len(), 1, "parent {parent}");
            assert_eq!(object.history.tips(), BTreeSet::from([root.id]));
        }
    }

    #[test]
    fn unreadable_parents_cannot_turn_an_entry_into_a_root() {
        let (_dir, repo) = setup();
        let entry = store(&repo, vec![], "root");
        for parent in unreadable_parents(&repo, &entry) {
            let root = with_parent(&repo, &entry, parent);
            let result = get_from_objects::<NonEmpty<Entry>, _>(
                &repo,
                entry.type_name(),
                &root.into(),
                &objects(root),
            );
            assert!(result.is_err(), "parent {parent}");
        }
    }

    // Freedom (upstream sync): what the lenient load above leaves out, a
    // strict load (`get_strict`, H4d) refuses whole: an entry built on a
    // parent that isn't a readable, signed change of the object, and a root
    // with such a parent.
    #[test]
    fn unreadable_parents_fail_a_strict_load() {
        use crate::object::collaboration::get_strict;

        let limits = Limits {
            changes: 64,
            operations: 64,
            bytes: 1 << 20,
        };
        let (_dir, repo) = setup();
        let root = store(&repo, vec![], "root");
        for parent in unreadable_parents(&repo, &root) {
            let entry = store(&repo, vec![root.id], "child");
            let child = with_parent(&repo, &entry, parent);
            let descendant = store(&repo, vec![child], "descendant");
            let result = get_strict::<NonEmpty<Entry>, _>(
                &repo,
                root.type_name(),
                &root.id.into(),
                &[descendant.id],
                &limits,
                &|| false,
            );
            assert!(result.is_err(), "child of {parent}");

            let rooted = with_parent(&repo, &root, parent);
            let result = get_strict::<NonEmpty<Entry>, _>(
                &repo,
                root.type_name(),
                &rooted.into(),
                &[rooted],
                &limits,
                &|| false,
            );
            assert!(result.is_err(), "root with {parent}");
        }
        // The history without them loads.
        let result = get_strict::<NonEmpty<Entry>, _>(
            &repo,
            root.type_name(),
            &root.id.into(),
            &[root.id],
            &limits,
            &|| false,
        );
        assert!(matches!(result, Ok(Some(_))));
    }

    // Freedom (bounded identity evaluation): a lenient load within limits
    // gives what `get_from_objects` gives, while it fits; one change past
    // any limit stops it, before that change is read.
    #[test]
    fn a_load_within_limits_stops_at_them() {
        use crate::object::collaboration::get_within;

        let (_dir, repo) = setup();
        let root = store(&repo, vec![], "root");
        let child = store(&repo, vec![root.id], "child");
        let tip = store(&repo, vec![child.id], "tip");
        let roomy = Limits {
            changes: 3,
            operations: 3,
            bytes: 1 << 20,
        };
        let get = |limits: &Limits, spent: &mut Spent, extra: &dyn Fn(&Oid, u64) -> u64| {
            get_within::<NonEmpty<Entry>, _>(
                &repo,
                root.type_name(),
                &root.id.into(),
                &[tip.id],
                limits,
                spent,
                extra,
            )
        };

        let mut spent = Spent::default();
        let object = get(&roomy, &mut spent, &|_, _| 0).unwrap().unwrap();
        let lenient = get_from_objects::<NonEmpty<Entry>, _>(
            &repo,
            root.type_name(),
            &root.id.into(),
            &objects(tip.id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(object.history, lenient.history);
        assert_eq!((spent.changes, spent.operations), (3, 3));
        let bytes = spent.bytes;

        // Each limit, one short.
        for (limits, what) in [
            (
                Limits {
                    changes: 2,
                    ..roomy
                },
                "changes",
            ),
            (
                Limits {
                    operations: 2,
                    ..roomy
                },
                "operations",
            ),
            (
                Limits {
                    bytes: bytes - 1,
                    ..roomy
                },
                "bytes",
            ),
        ] {
            let result = get(&limits, &mut Spent::default(), &|_, _| 0);
            assert!(
                matches!(&result, Err(crate::object::collaboration::error::Retrieve::Limit(e)) if e.what == what),
                "{what}: {result:?}"
            );
        }
        // What evaluating a change reads besides is charged with it.
        let result = get(
            &Limits {
                bytes: bytes + 2,
                ..roomy
            },
            &mut Spent::default(),
            &|_, _| 1,
        );
        assert!(result.is_err());
        // Loads sharing what they spent are bounded together.
        let mut spent = Spent {
            changes: 1,
            ..Spent::default()
        };
        assert!(get(&roomy, &mut spent, &|_, _| 0).is_err());
    }

    // A change that doesn't load is counted, once, however many changes
    // name it as a parent, and left out, as the lenient load leaves it out.
    #[test]
    fn a_change_that_does_not_load_is_tried_once() {
        use crate::object::collaboration::get_within;

        let (_dir, repo) = setup();
        let root = store(&repo, vec![], "root");
        let missing: Oid = "1111111111111111111111111111111111111111".parse().unwrap();
        let mut tips = Vec::new();
        for i in 0..4 {
            let entry = store(&repo, vec![root.id], &format!("child {i}"));
            tips.push(with_parent(&repo, &entry, missing));
        }
        let limits = Limits {
            changes: 6,
            operations: 6,
            bytes: 1 << 20,
        };
        let mut spent = Spent::default();
        let object = get_within::<NonEmpty<Entry>, _>(
            &repo,
            root.type_name(),
            &root.id.into(),
            &tips,
            &limits,
            &mut spent,
            &|_, _| 0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(spent.changes, 6);
        assert_eq!(object.history.tips(), BTreeSet::from([root.id]));
    }
}
