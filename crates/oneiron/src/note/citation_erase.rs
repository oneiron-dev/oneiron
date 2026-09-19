//! Hard-erase dependency fences. No source text or substring matching is stored here.

use crate::error::RecordError;
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

pub(crate) const PENDING_CITATION_ERASE: &str = "note.erase/pending/";

pub(super) fn erased_key(id: EntityId) -> String {
    format!("note.erase/source/{}", id.to_hex())
}

pub(super) fn pending_prefix(id: EntityId) -> String {
    format!("{PENDING_CITATION_ERASE}{}:", id.to_hex())
}

pub(crate) fn ensure_citations_ready(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<()> {
    if store
        .vault_meta
        .prefix_iter(txn, pending_prefix(id).as_bytes())?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "NOTE citation erasure pending",
        )));
    }
    Ok(())
}

/// Feature-independent first half. A featureless engine must retain the edited
/// document, not replace it with its birth record. The pending row puts the
/// exact dependent document beyond use until a sync-capable sweep can scrub it.
pub(super) fn fence_dependents(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<Vec<EntityId>> {
    let dependents = super::pin_index::dependents(store, txn, id)?;
    store.vault_meta.put(txn, erased_key(id).as_bytes(), &[])?;
    for citing in &dependents {
        store.vault_meta.put(
            txn,
            format!("{}{}", pending_prefix(*citing), id.to_hex()).as_bytes(),
            &[],
        )?;
    }
    Ok(dependents.into_iter().collect())
}

pub(crate) fn erase_citations_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let dependents = fence_dependents(&vault.store, txn, *id)?;
    #[cfg(feature = "sync")]
    for citing in dependents {
        if citing != *id {
            super::citation_scrub::scrub_pending(vault, txn, citing)?;
        }
    }
    #[cfg(not(feature = "sync"))]
    let _ = dependents;
    Ok(())
}

#[cfg(feature = "sync")]
pub(super) fn pin_is_erased(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &super::NotePin,
) -> Result<bool> {
    for id in [pin.document, pin.claim] {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
            || vault
                .store
                .vault_meta
                .get(txn, erased_key(id).as_bytes())?
                .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "sync")]
pub(crate) fn validate_pins(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pins: &[super::NotePin],
) -> Result<()> {
    for pin in pins {
        if pin_is_erased(vault, txn, pin)? {
            return Err(super::document::invalid("NOTE citation source was erased"));
        }
    }
    Ok(())
}
