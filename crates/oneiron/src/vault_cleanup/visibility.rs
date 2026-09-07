//! Local archive visibility. Retained index rows remain usable after restore.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;

pub(crate) fn is_archived_in_txn(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    // Even malformed markers hide rows. Only restore decodes/accepts byte 5.
    Ok(store
        .sync_state()
        .get(txn, crate::deletion::archive_tombstone_key(id).as_str())?
        .is_some())
}
