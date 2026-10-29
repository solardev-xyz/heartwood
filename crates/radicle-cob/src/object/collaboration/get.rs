// Copyright © 2022 The Radicle Link Contributors

use oid::Oid;

use crate::change_graph::{ChangeGraph, Limits, StrictError};
use crate::{CollaborativeObject, Evaluate, ObjectId, TypeName};

use super::error;

/// Get a [`CollaborativeObject`], if it exists.
///
/// The `storage` is the backing storage for storing
/// [`crate::Entry`]s at content-addressable locations. Please see
/// [`crate::Store`] for further information.
///
/// The `typename` is the type of object to be found, while the
/// `object_id` is the identifier for the particular object under that
/// type.
pub fn get<T, S>(
    storage: &S,
    typename: &TypeName,
    oid: &ObjectId,
) -> Result<Option<CollaborativeObject<T>>, error::Retrieve>
where
    T: Evaluate<S>,
    S: crate::object::Storage,
    S: crate::change::Storage<
            ObjectId = crate::object::Oid,
            Parent = crate::object::Oid,
            PublicKey = crypto::PublicKey,
            Signature = crypto::Signature,
        >,
{
    let tip_refs = storage
        .objects(typename, oid)
        .map_err(|err| error::Retrieve::Refs { err: Box::new(err) })?;

    ChangeGraph::load(storage, tip_refs.iter(), typename, oid)
        .map(|graph| graph.evaluate(storage).map_err(error::Retrieve::evaluate))
        .transpose()
}

/// Get a [`CollaborativeObject`] strictly, from the changes `tips` reach
/// alone, within `limits`, if it exists.
///
/// Where [`get`] leaves out a change that doesn't load, or a branch whose
/// signature is invalid or whose actions don't apply, this fails, so a
/// caller never takes a partial object for the whole one. So does a change
/// of another type, or another object's history among `tips`. `stop` is
/// asked before each change: once it says so, the load fails with
/// [`StrictError::Stopped`]. `None` if `tips` is empty.
pub fn get_strict<T, S>(
    storage: &S,
    typename: &TypeName,
    oid: &ObjectId,
    tips: &[Oid],
    limits: &Limits,
    stop: &dyn Fn() -> bool,
) -> Result<Option<CollaborativeObject<T>>, StrictError>
where
    T: Evaluate<S>,
    S: crate::change::Storage<
            ObjectId = crate::object::Oid,
            Parent = crate::object::Oid,
            PublicKey = crypto::PublicKey,
            Signature = crypto::Signature,
        >,
{
    let Some(graph) = ChangeGraph::load_strict(storage, tips, typename, oid, limits, stop)? else {
        return Ok(None);
    };
    graph.evaluate_strict(storage, stop).map(Some)
}
