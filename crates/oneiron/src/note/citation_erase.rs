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

/// Returns the citing documents whose readable state changed: rebuilt without
/// the erased pin, or (featureless) fenced until a sync-capable sweep runs.
/// The caller notifies them only after its transaction commits.
pub(crate) fn erase_citations_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut dependents = fence_dependents(&vault.store, txn, *id)?;
    scrub_stored_proposal_citations(vault, txn)?;
    scrub_retired_canonical_citations(vault, txn)?;
    dependents.retain(|citing| citing != id);
    #[cfg(feature = "sync")]
    for citing in &dependents {
        super::citation_scrub::scrub_pending(vault, txn, *citing)?;
    }
    Ok(dependents)
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

/// Remove erased citations without changing authored text or surviving pins.
pub(super) fn remove_erased_pins(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &super::document::NoteDocument,
) -> Result<bool> {
    let pins = doc.doc.get_map("pins");
    let mut remove = Vec::new();
    let entries: Vec<_> = pins
        .keys()
        .filter_map(|key| pins.get(&key).map(|value| (key, value)))
        .collect();
    for (key, value) in entries {
        let loro::ValueOrContainer::Value(loro::LoroValue::String(value)) = value else {
            return Err(super::document::invalid("invalid NOTE pin value"));
        };
        let pin: super::NotePin = serde_json::from_str(&value)
            .map_err(|_| super::document::invalid("invalid NOTE pin"))?;
        pin.validate()?;
        if pin_is_erased(vault, txn, &pin)? {
            remove.push(key.to_string());
        }
    }
    let changed = !remove.is_empty();
    for key in remove {
        pins.delete(&key)
            .map_err(|_| super::document::invalid("NOTE citation erase"))?;
    }
    Ok(changed)
}

/// Retired heads can retain authenticated pins after the live head stopped
/// citing their source. They are not all in the live reverse-pin index.
fn scrub_stored_proposal_citations(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    for key in super::documents::NOTE_PROPOSAL_DOC.scan_keys(&vault.store, txn, &[])? {
        let Some(raw) = super::documents::NOTE_PROPOSAL_DOC.get(&vault.store, txn, &key)? else {
            continue;
        };
        let doc = super::document::NoteDocument::load((key.0).0, &raw)?;
        if remove_erased_pins(vault, txn, &doc)? {
            super::proposals::preserve_recovery_basis(vault, txn, (key.0).0, (key.1).0, &doc.doc)?;
            doc.doc.commit();
            // A normal snapshot would keep the removed quote in its oplog.
            let clean = super::storage::state_copy(&doc.doc)?;
            let retained = super::document::NoteDocument::load((key.0).0, &clean)?;
            validate_pins(vault, txn, &retained.pins()?)?;
            super::documents::NOTE_PROPOSAL_DOC.put(&vault.store, txn, &key, &clean)?;
        }
    }
    Ok(())
}

/// A switched-away canonical slot keeps its own snapshot and update journal,
/// independently of the proposal carrier and the current reverse-pin index.
fn scrub_retired_canonical_citations(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, UpdateSeq};

    let mut slots = std::collections::BTreeSet::new();
    for (note, head) in super::documents::NOTE_HEAD_DOC.scan_keys(&vault.store, txn, &[])? {
        slots.insert((note, note));
        slots.insert((note, head));
    }
    for (note, head) in slots {
        if head == super::documents::head_in(&vault.store, txn, note)?.0 {
            continue;
        }
        let slot = DocumentSlot::of(head);
        let snapshot = vault
            .store
            .port_document_row(txn, slot, DocumentRow::Snapshot)?;
        let updates = vault.store.port_document_updates(txn, slot)?;
        let doc = match snapshot {
            Some(snapshot) => {
                let doc = loro::LoroDoc::new();
                super::storage::import_complete(&doc, &snapshot)?;
                doc
            }
            None if updates.is_empty() => continue,
            None if head == note => super::document_birth_in_txn(vault, txn, note)?
                .ok_or_else(|| super::document::invalid("NOTE original document birth missing"))?,
            None => return Err(super::document::invalid("NOTE head document missing")),
        };
        for update in updates {
            if !matches!(update.seq, Some(UpdateSeq::Sequence(_))) {
                return Err(super::document::invalid(
                    "invalid canonical document update key",
                ));
            }
            super::storage::import_complete(&doc, &update.bytes)?;
        }
        let retained = super::document::NoteDocument::from_loro(note, doc)?;
        if !remove_erased_pins(vault, txn, &retained)? {
            continue;
        }
        retained.doc.commit();
        let snapshot = super::storage::state_copy(&retained.doc)?;
        let clean = super::document::NoteDocument::load(note, &snapshot)?;
        validate_pins(vault, txn, &clean.pins()?)?;
        vault
            .store
            .port_document_snapshot_put(txn, slot, &snapshot)?;
        vault
            .store
            .port_document_state_vector_put(txn, slot, &clean.doc.oplog_vv().encode())?;
        vault.store.port_document_shallow_since_put(
            txn,
            slot,
            &clean.doc.shallow_since_vv().to_vv().encode(),
        )?;
        vault.store.port_document_updates_delete(txn, slot)?;
    }
    Ok(())
}
