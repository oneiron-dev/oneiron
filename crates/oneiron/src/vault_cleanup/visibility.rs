//! Local archive visibility. Retained index rows remain usable after restore.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;

pub(crate) fn is_archived_in_txn(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, id)?.archived)
}
