//! Refuse generic body writes that bypass a storage-owned document or conversation ledger.

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, RecordError, Result};
use crate::store::Store;
use crate::temporal::TimeRange;
use heed::RoTxn;

pub(super) fn guard_storage_owned_body(
    store: &Store,
    wtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    crate::origin::lfs::guard_lfs_asset_put(store, wtxn, id, data)?;
    #[cfg(feature = "sync")]
    crate::entity_doc::guard_record_put(store, wtxn, id, data)?;
    if store
        .vault_meta
        .get(
            wtxn,
            &[b"conversation_dag:record:v1:".as_slice(), id.as_bytes()].concat(),
        )?
        .is_some()
        && let Some(raw) = store.entities.get(wtxn, id.as_bytes())?
    {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("DAG record header"))?;
        if raw[ENTITY_METADATA_HEADER_LEN..] != *data
            || header.occurred_start != occurred.start
            || header.occurred_end != occurred.end
        {
            return Err(Error::Record(RecordError::ConversationState(
                "DAG records are append-only",
            )));
        }
    }
    if entity_type == crate::registry::ENTITY_TYPE_CONVERSATION {
        crate::conversation::validate_put_in_txn(store, wtxn, *id, data, replicated)?;
    }
    Ok(())
}
