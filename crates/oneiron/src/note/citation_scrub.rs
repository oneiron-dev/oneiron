//! Pin-only live-state rebuild. Authored prose and surviving provenance stay intact.

use super::document::{NoteDocument, invalid};
use super::sync_rows::{SYNC_AD_E, SYNC_DS_E, SYNC_QD_E, SYNC_QN_E};
use crate::side_table::HexId;
use crate::{EntityId, Result, Vault};

pub(crate) fn scrub_pending_citations(vault: &Vault) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let mut documents = std::collections::BTreeSet::new();
        for key in super::citation_erase::NOTE_ERASE_PENDING.scan_keys(&vault.store, txn, &[])? {
            documents.insert((key.0).0);
        }
        for id in documents {
            scrub_pending(vault, txn, id)?;
        }
        Ok(())
    })
}

pub(super) fn scrub_pending(vault: &Vault, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    // Only this recovery door bypasses the pending fence. It replays every
    // committed update before rebuilding, under the same LMDB writer lock.
    let doc = NoteDocument::from_loro(
        id,
        crate::sync::documents::storage::load_for_erasure(vault, txn, id)?,
    )?;
    let floor_key = HexId(id);
    if super::citation_erase::NOTE_ERASE_AUTHORITY_FLOOR
        .get(&vault.store, txn, &floor_key)?
        .is_none()
    {
        super::citation_erase::NOTE_ERASE_AUTHORITY_FLOOR.put(
            &vault.store,
            txn,
            &floor_key,
            &doc.doc.oplog_vv().encode(),
        )?;
    }
    super::citation_erase::remove_erased_pins(vault, txn, &doc)?;
    doc.doc.commit();
    // A normal snapshot retains deleted map values in its oplog. StateOnly
    // removes those bytes while keeping live text op IDs/cursors and authorship.
    let clean = NoteDocument::load(id, &crate::sync::documents::storage::state_copy(&doc.doc)?)?;
    super::citation_erase::validate_pins(vault, txn, &clean.pins()?)?;
    // Saved receipts contain full old document views. They stay as replay
    // guards, without the erased pins; their queued copies go (FIX 18270).
    let key_prefix = format!("{}:", id.to_hex()).into_bytes();
    SYNC_QD_E.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_AD_E.delete_from(&vault.store, txn, &key_prefix)?;
    super::citation_erase::redact_view_receipts(vault, txn, id)?;
    // Keep unrelated queued semantic edits. Only a Cite of an erased dependency
    // is obsolete; it must not be transmitted by reconnect.
    let pending = SYNC_QN_E.scan_from(&vault.store, txn, &key_prefix)?;
    for (key, bytes) in pending {
        let queued = super::PendingNoteRequest::decode(&bytes)
            .ok_or_else(|| invalid("NOTE pending request"))?
            .frame;
        let frame = crate::sync::transport::decode_document(
            queued
                .get(1..)
                .ok_or_else(|| invalid("NOTE pending frame"))?,
        )
        .map_err(|_| invalid("NOTE pending frame"))?;
        // A fork upload's marker holds no text (FIX 12789): only commands
        // carry a citation.
        if frame.kind != crate::sync::transport::document_sub_tags::NOTE_OPS {
            continue;
        }
        let operation = super::NoteOperation::decode(frame.payload)?;
        if let super::NoteChange::Cite { pin } = operation.change
            && super::citation_erase::pin_is_erased(vault, txn, &pin)?
        {
            SYNC_QN_E.delete(&vault.store, txn, &key)?;
            super::pin_index::remove_citation_request(&vault.store, txn, id, operation.request_id)?;
        }
    }
    super::citation_erase::NOTE_ERASE_PENDING.delete_from(&vault.store, txn, &key_prefix)?;
    if SYNC_DS_E.contains(&vault.store, txn, &HexId(id))? {
        super::document_store::persist_replica(vault, txn, &clean)?;
    } else {
        super::document_store::persist_authoritative(vault, txn, &clean)?;
    }
    let indexed_before = super::revision::indexed_input_in_txn(vault, txn, id)?;
    crate::sync::documents::storage::snapshot(vault, txn, id, &clean.doc, true)?;
    super::revision::index_stored_note_in_txn(vault, txn, id, indexed_before.as_deref(), None)
}
