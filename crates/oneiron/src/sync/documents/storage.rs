//! Snapshot-then-update recovery and transactional text-plane persistence.
//! A NOTE's text plane is its NOTE storage; every other record's is its
//! entity document's (`entity_doc::sync`), which writes its own rows.

use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use loro::VersionVector;

pub(crate) use crate::note::storage::{
    import_complete, load, load_for_erasure, snapshot, state_copy,
};

pub(crate) fn decode_vv(bytes: &[u8]) -> Result<VersionVector> {
    VersionVector::decode(bytes).map_err(|source| {
        Error::Sync(crate::error::SyncError::CrdtDecodeError {
            context: "entity document version vector",
            source,
        })
    })
}

/// A closed document is compacted under the write lock, so no stale read can overwrite an append.
/// An entity document is its owner's to compact, ahead of the NOTE loader (FIX 10159).
pub(crate) fn compact(vault: &Vault, id: EntityId, erased: bool) -> Result<()> {
    if crate::entity_doc::compact_entity_doc_for_sweep(vault, &id, erased)? {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        if !erased
            && vault.get_entity_type_in_txn(txn, &id)? == Some(crate::registry::ENTITY_TYPE_NOTE)
        {
            // The NOTE-specific purge door owns cited-frontier retention.
            return Ok(());
        }
        // A held document keeps its bytes and its history (OF-470, FIX
        // 10160): the state-only snapshot drops its history as the delete
        // drops it all.
        vault.store.reject_legal_holds_in_txn(
            txn,
            &[id],
            &crate::store::legal_hold::HoldActor::TIMER,
        )?;
        if erased {
            return crate::note::delete_document_in_txn(&vault.store, txn, &id);
        }
        // Ordinary compaction folds the updates into a full snapshot and keeps
        // the history; only an authorized purge drops it (FIX 8874).
        let doc = load(vault, txn, id)?;
        snapshot(vault, txn, id, &doc, false)
    })
}
