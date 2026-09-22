//! Refuse generic body writes that bypass a storage-owned document or conversation ledger.

use crate::EntityId;
use crate::error::Result;
use crate::store::Store;
use heed::RoTxn;

pub(super) fn guard_storage_owned_body(
    store: &Store,
    wtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    crate::origin::lfs::guard_lfs_asset_put(store, wtxn, id, entity_type, data)?;
    #[cfg(feature = "sync")]
    crate::entity_doc::guard_record_put(store, wtxn, id, data)?;
    if entity_type == crate::registry::ENTITY_TYPE_CONVERSATION {
        crate::conversation::validate_put_in_txn(store, wtxn, *id, data, replicated)?;
    }
    Ok(())
}
