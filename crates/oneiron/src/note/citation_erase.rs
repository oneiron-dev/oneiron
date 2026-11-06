//! Hard-erase dependency fences. No source text or substring matching is stored here.

use std::collections::BTreeSet;

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
    mark_erased(store, txn, id)?;
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
    let mut scrubbed = scrub_stored_proposal_citations(vault, txn)?;
    scrubbed.extend(scrub_retired_canonical_citations(vault, txn)?);
    // A retained head or proposal held the erased pin: the NOTE's saved
    // full-view receipts may hold it too (FIX 18270).
    for note in &scrubbed {
        redact_view_receipts(vault, txn, *note)?;
    }
    dependents.retain(|citing| citing != id);
    #[cfg(feature = "sync")]
    for citing in &dependents {
        super::citation_scrub::scrub_pending(vault, txn, *citing)?;
    }
    // A NOTE held only as a residence copy is in no index this read: its
    // copy goes whole, the source now marked (FIX 18400).
    #[cfg(feature = "sync")]
    for note in super::citation_residence::erase_residence_citations_in_txn(vault, txn)? {
        if note != *id && !dependents.contains(&note) {
            dependents.push(note);
        }
    }
    Ok(dependents)
}

/// A restore's citation erase (KS7, FIX 18270). An image cut before a
/// record's erase holds the citations NOTE documents make of it, quote
/// included: the citing NOTE's compartment opens, the erased record's does
/// not, and the reverse pin rows that depended on that record are gone, so
/// the reverse index no longer finds the citing NOTE. Each of `erased` is
/// marked citation-erased, as the live erase marks the record it erases. A
/// queued citation request that names one goes. Every NOTE whose current
/// document pins one is rebuilt without that citation, history included
/// ([`rebuild_restored`]), and its reverse rows left without their pin row
/// go. Retained heads and proposal documents are scrubbed as the live erase
/// scrubs them, and the saved receipts of every NOTE a scrub changed lose
/// the erased pins ([`redact_view_receipts`]). In the restore's own
/// transaction, before it commits; nothing is notified.
///
/// # Errors
///
/// Storage errors, or a scrubbed document that does not read or write.
pub(crate) fn erase_restored_citations_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    if erased.is_empty() {
        return Ok(());
    }
    let store = &vault.store;
    for id in erased {
        mark_erased(store, txn, *id)?;
    }
    for (citing, request) in super::pin_index::requests_citing(store, txn, erased)? {
        let queued = HexPair(HexId(citing), HexId(request));
        super::sync_rows::SYNC_QN_E.delete(store, txn, &queued)?;
        super::pin_index::remove_citation_request(store, txn, citing, request)?;
    }
    let citing = restored_citers(vault, txn, erased)?;
    super::pin_index::drop_dangling_citing(store, txn, &citing)?;
    for note in &citing {
        rebuild_restored(vault, txn, *note)?;
        drop_edit_frames(store, txn, *note)?;
    }
    let mut scrubbed = scrub_stored_proposal_citations(vault, txn)?;
    scrubbed.extend(scrub_retired_canonical_citations(vault, txn)?);
    for note in citing.iter().chain(&scrubbed) {
        redact_view_receipts(vault, txn, *note)?;
    }
    // Residence copies the image held: an erased item's own, and every
    // cached NOTE's that cites one (FIX 18400).
    #[cfg(feature = "sync")]
    {
        super::citation_residence::erase_own_copies_in_txn(store, txn, erased.iter().copied())?;
        super::citation_residence::erase_residence_citations_in_txn(vault, txn)?;
    }
    Ok(())
}

/// Each NOTE whose current document pins one of `erased`. Every NOTE's
/// document is read whole: the reverse rows that would name it went with the
/// record the restore did not open. An erased NOTE cites nothing. A document
/// that does not load is passed over: its readers load it the same way, so
/// none serves it.
fn restored_citers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let notes = crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        crate::registry::ENTITY_TYPE_NOTE,
        None,
    )?
    .collect::<Result<Vec<EntityId>>>()?;
    let mut citing = BTreeSet::new();
    for note in notes {
        if erased.contains(&note) {
            continue;
        }
        let read = super::storage::load_for_erasure(vault, txn, note)
            .and_then(|doc| super::document::NoteDocument::from_loro(note, doc))
            .and_then(|doc| doc.pins());
        let Ok(pins) = read else {
            continue;
        };
        if pins
            .iter()
            .any(|pin| erased.contains(&pin.document) || erased.contains(&pin.claim))
        {
            citing.insert(note);
        }
    }
    Ok(citing)
}

/// Rebuilds a restored NOTE's current document without its erased citations
/// (FIX 18270): each erased pin goes, and so does every byte of it in the
/// document's history (a state-only copy, as the live scrub stores one),
/// its text, authorship and surviving pins kept; its reverse rows are written
/// again from the pins that stay, and a fence the image carried for it is
/// cleared, as the live scrub clears it. Unlike the live scrub it writes only the
/// document and those rows: the body is the one the image held, admitted
/// when it was written, so it is neither admitted nor projected again, and
/// no custody read runs before the restore commits.
fn rebuild_restored(vault: &Vault, txn: &mut heed::RwTxn<'_>, note: EntityId) -> Result<()> {
    let doc = super::document::NoteDocument::from_loro(
        note,
        super::storage::load_for_erasure(vault, txn, note)?,
    )?;
    let floor = HexId(note);
    if NOTE_ERASE_AUTHORITY_FLOOR
        .get(&vault.store, txn, &floor)?
        .is_none()
    {
        let vv = doc.doc.oplog_vv().encode();
        NOTE_ERASE_AUTHORITY_FLOOR.put(&vault.store, txn, &floor, &vv)?;
    }
    remove_erased_pins(vault, txn, &doc)?;
    doc.doc.commit();
    let clean = super::document::NoteDocument::load(note, &super::storage::state_copy(&doc.doc)?)?;
    let pins = clean.pins()?;
    validate_pins(vault, txn, &pins)?;
    super::storage::snapshot(vault, txn, note, &clean.doc, true)?;
    super::pin_index::remove_citing(&vault.store, txn, note)?;
    super::pin_index::index_pins(&vault.store, txn, note, &pins)?;
    // A fence the image carried for this NOTE is done with: its document no
    // longer holds what any fenced source left in it.
    let key_prefix = format!("{}:", note.to_hex()).into_bytes();
    NOTE_ERASE_PENDING.delete_from(&vault.store, txn, &key_prefix)?;
    Ok(())
}

/// Drops `note`'s unacknowledged local edit frames and disclosure floors, as
/// the live scrub does once it has rebuilt the document: they were cut from
/// the history the rebuild left behind.
fn drop_edit_frames(store: &Store, txn: &mut heed::RwTxn<'_>, note: EntityId) -> Result<()> {
    let key_prefix = format!("{}:", note.to_hex()).into_bytes();
    super::sync_rows::SYNC_QD_E.delete_from(store, txn, &key_prefix)?;
    super::sync_rows::SYNC_AD_E.delete_from(store, txn, &key_prefix)?;
    Ok(())
}

/// Takes the erased citations out of `note`'s saved receipts (FIX 18270).
/// An applied receipt holds a whole old document view, pins and quotes
/// included: each erased pin leaves that view. The receipt itself stays,
/// with its request, command hash, actor and the rest of its view, so a
/// replay of its request is still answered from it and never applied
/// again, whichever head now stands and whatever authorship that head
/// holds (an actor erase keeps receipts for the same reason, FIX 3879).
/// The queued delivery copies (`nc:e:`) go: a host delivers a queued
/// receipt only while it equals the saved one.
pub(super) fn redact_view_receipts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
) -> Result<()> {
    let store = &vault.store;
    let key_prefix = format!("{}:", note.to_hex()).into_bytes();
    super::sync_rows::SYNC_NC_E.delete_from(store, txn, &key_prefix)?;
    let saved = super::sync_rows::NOTE_RECEIPT_BY_REQUEST.scan_from(store, txn, &key_prefix)?;
    for (key, (by, mut receipt)) in saved {
        let super::document::NoteScalarEditOutcome::Applied(view) = &mut receipt.outcome else {
            continue;
        };
        let before = view.pins.len();
        let mut kept = Vec::with_capacity(before);
        for pin in std::mem::take(&mut view.pins) {
            if !pin_is_erased(vault, txn, &pin)? {
                kept.push(pin);
            }
        }
        let changed = kept.len() != before;
        view.pins = kept;
        if changed {
            super::sync_rows::NOTE_RECEIPT_BY_REQUEST.put(store, txn, &key, &(by, receipt))?;
        }
    }
    Ok(())
}

/// Marks `id` erased here, and the copy id its masked copy takes
/// (`copy_id`): a copy of an erased record is erased with it, and no copy
/// of it is cached again under that id (FIX 18400).
pub(super) fn mark_erased(store: &Store, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    NOTE_ERASE_SOURCE.put(store, txn, &HexId(id), &())?;
    if let Ok(copy) = crate::origin::secret_projection::copy_id::copy_id(&id) {
        NOTE_ERASE_SOURCE.put(store, txn, &HexId(copy), &())?;
    }
    Ok(())
}

/// Whether `id` is erased here: its hard-delete marker, or its citation
/// erase mark ([`mark_erased`]).
pub(super) fn is_erased(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<bool> {
    Ok(vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        || NOTE_ERASE_SOURCE.contains(&vault.store, txn, &HexId(id))?)
}

pub(super) fn pin_is_erased(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &super::NotePin,
) -> Result<bool> {
    for id in [pin.document, pin.claim] {
        if is_erased(vault, txn, id)? {
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
/// Returns the NOTEs whose proposal documents lost a pin.
fn scrub_stored_proposal_citations(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let mut scrubbed = BTreeSet::new();
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
            scrubbed.insert((key.0).0);
        }
    }
    Ok(scrubbed)
}

/// A switched-away canonical slot keeps its own snapshot and update journal,
/// independently of the proposal carrier and the current reverse-pin index.
/// Returns the NOTEs whose retained heads lost a pin.
fn scrub_retired_canonical_citations(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, UpdateSeq};

    let mut scrubbed = BTreeSet::new();
    let mut slots = BTreeSet::new();
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
        scrubbed.insert(note);
    }
    Ok(scrubbed)
}
