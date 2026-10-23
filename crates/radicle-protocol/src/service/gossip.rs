pub mod store;

use super::*;
use crate::bounded::BoundedVec;
use radicle::node::PROTOCOL_VERSION;

pub use store::{AnnouncementId, Error, RelayStatus, Store};

/// A configuration with more external addresses than a node announcement
/// carries.
#[derive(Debug, thiserror::Error)]
#[error("{0} external addresses, over the limit of {ADDRESS_LIMIT}")]
pub struct TooManyAddresses(pub usize);

pub fn node(config: &Config, timestamp: Timestamp) -> Result<NodeAnnouncement, TooManyAddresses> {
    let features = config.features();
    let alias = config.alias.clone();
    let addresses: BoundedVec<_, ADDRESS_LIMIT> = config
        .external_addresses
        .clone()
        .try_into()
        .map_err(|_| TooManyAddresses(config.external_addresses.len()))?;

    let agent = config.user_agent();

    let version = PROTOCOL_VERSION;

    Ok(NodeAnnouncement {
        features,
        version,
        timestamp,
        alias,
        addresses,
        nonce: 0,
        agent,
    })
}

pub fn inventory(
    timestamp: Timestamp,
    inventory: impl IntoIterator<Item = RepoId>,
) -> InventoryAnnouncement {
    let inventory = inventory.into_iter().collect::<Vec<_>>();
    if inventory.len() > INVENTORY_LIMIT {
        warn!(
            target: "service",
            "inventory announcement limit ({}) exceeded, other nodes will see only some of your projects",
            inventory.len()
        );
    }

    InventoryAnnouncement {
        inventory: BoundedVec::truncate(inventory),
        timestamp,
    }
}
