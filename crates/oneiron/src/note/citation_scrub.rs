//! Pin-only live-state rebuild. Authored prose and surviving provenance stay intact.

use super::document::{NoteDocument, invalid};
use super::sync_rows::{NOTE_RECEIPT_BY_REQUEST, SYNC_AD_E, SYNC_NC_E, SYNC_QD_E, SYNC_QN_E};
use crate::side_table::HexId;
use crate::{EntityId, Result, Vault};

pub(crate) fn scrub_pending_citations(vault: &Vault) -> Result<()> {
    vault.with_write_txn(|txn| {
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
    let pins = doc.doc.get_map("pins");
    let mut remove = Vec::new();
    let entries: Vec<_> = pins
        .keys()
        .filter_map(|key| pins.get(&key).map(|value| (key, value)))
        .collect();
    for (key, value) in entries {
        let loro::ValueOrContainer::Value(loro::LoroValue::String(value)) = value else {
            return Err(invalid("invalid NOTE pin value"));
        };
        let pin: super::NotePin =
            serde_json::from_str(&value).map_err(|_| invalid("invalid NOTE pin"))?;
        pin.validate()?;
        if super::citation_erase::pin_is_erased(vault, txn, &pin)? {
            remove.push(key.to_string());
        }
    }
    for key in remove {
        pins.delete(&key)
            .map_err(|_| invalid("NOTE citation erase"))?;
    }
    doc.doc.commit();
    // A normal snapshot retains deleted map values in its oplog. StateOnly
    // removes those bytes while keeping live text op IDs/cursors and authorship.
    let clean = NoteDocument::load(id, &crate::sync::documents::storage::state_copy(&doc.doc)?)?;
    super::citation_erase::validate_pins(vault, txn, &clean.pins()?)?;
    // Saved receipts contain full old document views. Their authored operation
    // IDs survive in the authorship map, so replay cannot restore old responses.
    let key_prefix = format!("{}:", id.to_hex()).into_bytes();
    SYNC_QD_E.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_AD_E.delete_from(&vault.store, txn, &key_prefix)?;
    NOTE_RECEIPT_BY_REQUEST.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_NC_E.delete_from(&vault.store, txn, &key_prefix)?;
    // Keep unrelated queued semantic edits. Only a Cite of an erased dependency
    // is obsolete; it must not be transmitted by reconnect.
    let pending = SYNC_QN_E.scan_from(&vault.store, txn, &key_prefix)?;
    for (key, bytes) in pending {
        let frame = crate::sync::transport::decode_document(
            bytes
                .get(1..)
                .ok_or_else(|| invalid("NOTE pending frame"))?,
        )
        .map_err(|_| invalid("NOTE pending frame"))?;
        let operation = super::NoteOperation::decode(frame.payload)?;
        if let super::NoteChange::Cite { pin } = operation.change
            && super::citation_erase::pin_is_erased(vault, txn, &pin)?
        {
            SYNC_QN_E.delete(&vault.store, txn, &key)?;
            super::pin_index::remove_citation_request(&vault.store, txn, id, operation.request_id)?;
        }
    }
    super::citation_erase::NOTE_ERASE_PENDING.delete_from(&vault.store, txn, &key_prefix)?;
    super::document_store::persist(vault, txn, &clean)?;
    crate::sync::documents::storage::snapshot(vault, txn, id, &clean.doc, true)
}
