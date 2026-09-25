//! Pin-only live-state rebuild. Authored prose and surviving provenance stay intact.

use super::document::{NoteDocument, invalid};
use crate::{EntityId, Result, Vault};

pub(super) fn authority_floor_key(id: EntityId) -> String {
    format!("note.erase/authority-floor/{}", id.to_hex())
}

pub(crate) fn scrub_pending_citations(vault: &Vault) -> Result<()> {
    vault.with_write_txn(|txn| {
        let mut documents = std::collections::BTreeSet::new();
        for row in vault.store.vault_meta.prefix_iter(
            txn,
            super::citation_erase::PENDING_CITATION_ERASE.as_bytes(),
        )? {
            let (key, _) = row?;
            let suffix =
                std::str::from_utf8(&key[super::citation_erase::PENDING_CITATION_ERASE.len()..])
                    .map_err(|_| invalid("NOTE erasure dependency key"))?;
            let (document, source) = suffix
                .split_once(':')
                .ok_or_else(|| invalid("NOTE erasure dependency key"))?;
            EntityId::from_hex(source)?;
            documents.insert(EntityId::from_hex(document)?);
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
    let floor_key = authority_floor_key(id);
    if vault
        .store
        .vault_meta
        .get(txn, floor_key.as_bytes())?
        .is_none()
    {
        vault
            .store
            .vault_meta
            .put(txn, floor_key.as_bytes(), &doc.doc.oplog_vv().encode())?;
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
    for prefix in ["qd:e:", "ad:e:", "nr:e:", "nc:e:"] {
        super::delete::delete_sync_prefix(&vault.store, txn, &format!("{prefix}{}:", id.to_hex()))?;
    }
    // Keep unrelated queued semantic edits. Only a Cite of an erased dependency
    // is obsolete; it must not be transmitted by reconnect.
    let pending = vault
        .store
        .sync_state
        .prefix_iter(txn, &format!("qn:e:{}:", id.to_hex()))?
        .map(|row| row.map(|(key, bytes)| (key.to_string(), bytes.to_vec())))
        .collect::<std::result::Result<Vec<_>, _>>()?;
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
            vault.store.sync_state.delete(txn, &key)?;
            super::pin_index::remove_citation_request(&vault.store, txn, id, operation.request_id)?;
        }
    }
    let prefix = super::citation_erase::pending_prefix(id);
    let keys = vault
        .store
        .vault_meta
        .prefix_iter(txn, prefix.as_bytes())?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        vault.store.vault_meta.delete(txn, &key)?;
    }
    super::document_store::persist(vault, txn, &clean)?;
    crate::sync::documents::storage::snapshot(vault, txn, id, &clean.doc, true)
}
