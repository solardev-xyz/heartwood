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
            graph.dependency(child_id, parent_id);
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
        // Evaluate the root separately, since we can't have a COB without a valid root.
        // Then, traverse the graph starting from the root's dependents.
        let mut object =
            T::init(&root.value, store).map_err(|e| EvaluateError::Init(Box::new(e)))?;
        let children = Vec::from_iter(root.dependents.iter().cloned());
        let manifest = root.manifest.clone();
        let root = root.id;

        self.graph.prune_by(
            &children,
            |_, entry, siblings| {
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
                ControlFlow::Continue(())
            },
            Self::chronological,
        );

        Ok(CollaborativeObject {
            manifest,
            object,
            history: History::new(root, self.graph),
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
