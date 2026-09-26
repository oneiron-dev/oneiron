//! Hard-erase dependency fences. No source text or substring matching is stored here.

use crate::error::RecordError;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

use super::side_keys::HexPair;

/// Fence marking a citing document's dependency on an erased source until
/// scrubbed. Key: hex32(citing) ":" hex32(erased source).
pub(super) const NOTE_ERASE_PENDING: SideTable<HexPair, (), Raw> =
    SideTable::new(&side_table::NOTE_ERASE_PENDING);
/// Marker that a NOTE/CLAIM source has been citation-erased. Key: hex32(id).
pub(super) const NOTE_ERASE_SOURCE: SideTable<HexId, (), Raw> =
    SideTable::new(&side_table::NOTE_ERASE_SOURCE);
/// Saved oplog version-vector floor an authority rebase cannot cross past a
/// scrub. Key: hex32(id).
pub(super) const NOTE_ERASE_AUTHORITY_FLOOR: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_ERASE_AUTHORITY_FLOOR);

/// Whether any citation-erase fence is still pending, anywhere in the vault.
/// Rows are not decoded: any row at all, well-formed or not, is a pending
/// fence (the hard-erase sweep fails closed on it).
pub(crate) fn any_citation_erase_pending(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(NOTE_ERASE_PENDING
        .iter_raw_from(store, txn, &[])?
        .next()
        .transpose()?
        .is_some())
}

pub(crate) fn ensure_citations_ready(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let prefix = format!("{}:", id.to_hex());
    if NOTE_ERASE_PENDING
        .iter_from(store, txn, prefix.as_bytes())?
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
    NOTE_ERASE_SOURCE.put(store, txn, &HexId(id), &())?;
    for citing in &dependents {
        NOTE_ERASE_PENDING.put(store, txn, &HexPair(HexId(*citing), HexId(id)), &())?;
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

pub(super) fn pin_is_erased(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &super::NotePin,
) -> Result<bool> {
    for id in [pin.document, pin.claim] {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
            || NOTE_ERASE_SOURCE.contains(&vault.store, txn, &HexId(id))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

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
