//! Snapshot-then-update recovery and transactional text-plane persistence.

use crate::error::{Error, Result};
use crate::ports::{DocumentRowStore, DocumentSlot};
use crate::{EntityId, Vault};
use loro::VersionVector;

pub(crate) use crate::note::storage::{
    import_complete, load, load_for_erasure, snapshot, state_copy,
};

/// Appends one update at the entity's next sequence. The cached state vector is marked stale by
/// its absence; recovery never trusts it.
pub(crate) fn append(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    bytes: &[u8],
) -> Result<u32> {
    vault
        .store
        .port_document_update_append(txn, DocumentSlot::of(id), bytes)
}

pub(crate) fn decode_vv(bytes: &[u8]) -> Result<VersionVector> {
    VersionVector::decode(bytes).map_err(|source| {
        Error::Sync(crate::error::SyncError::CrdtDecodeError {
            context: "entity document version vector",
            source,
        })
    })
}

/// A closed document is compacted under the write lock, so no stale read can overwrite an append.
pub(crate) fn compact(vault: &Vault, id: EntityId, erased: bool) -> Result<()> {
    vault.with_write_txn(|txn| {
        if !erased
            && vault.get_entity_type_in_txn(txn, &id)? == Some(crate::registry::ENTITY_TYPE_NOTE)
        {
            // The NOTE-specific purge door owns cited-frontier retention.
            return Ok(());
        }
        if erased {
            return crate::note::delete_document_in_txn(&vault.store, txn, &id);
        }
        let doc = load(vault, txn, id)?;
        snapshot(vault, txn, id, &doc, true)
    })
}
