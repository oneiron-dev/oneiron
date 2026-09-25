//! Snapshot-then-update recovery and transactional text-plane persistence.

use crate::error::{Error, Result, SyncProtocolValidation};
use crate::{EntityId, Vault};
use loro::VersionVector;

pub(crate) use crate::note::storage::{
    import_complete, load, load_for_erasure, snapshot, state_copy,
};

pub(crate) fn append(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    bytes: &[u8],
) -> Result<u32> {
    let hex = id.to_hex();
    let seq_key = format!("m:u_seq:e:{hex}");
    let seq = match vault.store.sync_state.get(txn, &seq_key)? {
        Some(bytes) => u32::from_be_bytes(
            bytes[..]
                .try_into()
                .map_err(|_| Error::sync_protocol(SyncProtocolValidation::InvalidDocumentKey))?,
        ),
        None => 0,
    }
    .checked_add(1)
    .ok_or(Error::InvariantViolation("document sequence exhausted"))?;
    vault
        .store
        .sync_state
        .put(txn, &format!("u:e:{hex}:{seq:08x}"), bytes)?;
    vault
        .store
        .sync_state
        .put(txn, &seq_key, &seq.to_be_bytes())?;
    // Absence denotes a stale cached state vector. Recovery never trusts it.
    vault.store.sync_state.delete(txn, &format!("sv:e:{hex}"))?;
    Ok(seq)
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
