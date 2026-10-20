//! Pin-only live-state rebuild. Authored prose and surviving provenance stay intact.
//! The hard mode (an erasure) runs with sync; a delete's default mode runs in
//! both feature graphs and keeps the citing document's history.

use super::document::{NoteDocument, invalid};
use super::sync_rows::SYNC_DS_E;
#[cfg(feature = "sync")]
use super::sync_rows::{NOTE_RECEIPT_BY_REQUEST, SYNC_AD_E, SYNC_NC_E, SYNC_QD_E, SYNC_QN_E};
use crate::side_table::HexId;
use crate::{EntityId, Result, Vault};

/// Commit message of a delete's pin removal.
const DELETE_SCRUB: &str = "oneiron.note/v1 delete_scrub";

#[cfg(feature = "sync")]
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

#[cfg(feature = "sync")]
pub(super) fn scrub_pending(vault: &Vault, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    // Only this recovery door bypasses the pending fence. It replays every
    // committed update before rebuilding, under the same LMDB writer lock.
    let doc = NoteDocument::from_loro(id, super::storage::load_for_erasure(vault, txn, id)?)?;
    let floor_key = HexId(id);
    if super::citation_erase::NOTE_ERASE_AUTHORITY_FLOOR
        .get(&vault.store, txn, &floor_key)?
        .is_none()
    {
        // A replica's own delete scrubs are not authority operations.
        super::citation_erase::NOTE_ERASE_AUTHORITY_FLOOR.put(
            &vault.store,
            txn,
            &floor_key,
            &authority_vv(id, &doc.doc).encode(),
        )?;
    }
    let pins = doc.doc.get_map("pins");
    for key in pin_keys(vault, txn, &doc, super::citation_erase::pin_is_erased)? {
        pins.delete(&key)
            .map_err(|_| invalid("NOTE citation erase"))?;
    }
    doc.doc.commit();
    // A normal snapshot retains deleted map values in its oplog. StateOnly
    // removes those bytes while keeping live text op IDs/cursors and authorship.
    let clean = NoteDocument::load(id, &super::storage::state_copy(&doc.doc)?)?;
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
    drop_queued_cites(vault, txn, id, super::citation_erase::pin_is_erased)?;
    super::citation_erase::NOTE_ERASE_PENDING.delete_from(&vault.store, txn, &key_prefix)?;
    if SYNC_DS_E.contains(&vault.store, txn, &HexId(id))? {
        super::document_store::persist_replica(vault, txn, &clean)?;
    } else {
        super::document_store::persist_authoritative(vault, txn, &clean)?;
    }
    super::storage::snapshot(vault, txn, id, &clean.doc, true)
}

/// Default mode (a delete, C050): drops the live pins of `source`, and any
/// queued Cite of it, from the citing document `id`. Unlike the hard mode it
/// writes no fence, source marker or authority floor, and it keeps the full
/// oplog and the saved full-view receipts: the old quote stays only in that
/// history. Returns whether anything changed.
pub(super) fn scrub_deleted(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    source: EntityId,
) -> Result<bool> {
    let doc = NoteDocument::from_loro(id, super::storage::load_for_erasure(vault, txn, id)?)?;
    let keys = pin_keys(vault, txn, &doc, |_, _, pin| {
        Ok(pin.document == source || pin.claim == source)
    })?;
    let changed = delete_pins(vault, txn, &doc, &keys)?;
    if changed {
        super::document_store::persist_scrubbed(vault, txn, &doc)?;
    }
    #[cfg(feature = "sync")]
    let changed = drop_queued_cites(vault, txn, id, |_, _, pin| {
        Ok(pin.document == source || pin.claim == source)
    })? || changed;
    Ok(changed)
}

/// An authority state can still hold a pin of a source this replica deleted.
/// The source's own delete-level state (its row fence or tombstone, which an
/// archive does not write) drops the pin again as the replica's own scrub, so
/// a delete outlasts a rebase with no authority floor.
#[cfg(feature = "sync")]
pub(super) fn rescrub_replica(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &NoteDocument,
) -> Result<()> {
    let keys = pin_keys(vault, txn, doc, source_deleted)?;
    delete_pins(vault, txn, doc, &keys)?;
    Ok(())
}

/// `doc`'s version without this replica's own delete scrubs: what its
/// authority can hold.
#[cfg(feature = "sync")]
pub(super) fn authority_vv(id: EntityId, doc: &loro::LoroDoc) -> loro::VersionVector {
    let mut vv = doc.oplog_vv();
    vv.remove(&replica_scrub_peer(id));
    vv
}

/// A replica writes its own delete scrubs of `id` as this one peer. No
/// authority holds its operations: a replica sends none of its own.
fn replica_scrub_peer(id: EntityId) -> u64 {
    let seed = blake3::derive_key("oneiron/note/replica-delete-scrub/v1", id.as_bytes());
    let mut peer = [0; 8];
    peer.copy_from_slice(&seed[..8]);
    u64::from_le_bytes(peer)
}

/// The keys of `doc`'s live pins that `drops` names.
fn pin_keys(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &NoteDocument,
    drops: impl Fn(&Vault, &heed::RoTxn<'_>, &super::NotePin) -> Result<bool>,
) -> Result<Vec<String>> {
    let pins = doc.doc.get_map("pins");
    let mut keys = Vec::new();
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
        if drops(vault, txn, &pin)? {
            keys.push(key.to_string());
        }
    }
    Ok(keys)
}

/// A delete's removal of the pins `keys`, in one commit. A replica writes it
/// as [`replica_scrub_peer`]. Returns whether any pin went.
fn delete_pins(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &NoteDocument,
    keys: &[String],
) -> Result<bool> {
    if keys.is_empty() {
        return Ok(false);
    }
    if SYNC_DS_E.contains(&vault.store, txn, &HexId(doc.id))? {
        doc.doc
            .set_peer_id(replica_scrub_peer(doc.id))
            .map_err(|_| invalid("NOTE scrub peer"))?;
    }
    let pins = doc.doc.get_map("pins");
    for key in keys {
        pins.delete(key)
            .map_err(|_| invalid("NOTE citation scrub"))?;
    }
    doc.doc
        .commit_with(loro::CommitOptions::new().commit_msg(DELETE_SCRUB));
    Ok(true)
}

/// Drops each queued Cite that `drops` names, with its request rows. Other
/// queued semantic edits stay. Returns whether any went.
#[cfg(feature = "sync")]
fn drop_queued_cites(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    drops: impl Fn(&Vault, &heed::RoTxn<'_>, &super::NotePin) -> Result<bool>,
) -> Result<bool> {
    let mut dropped = false;
    let key_prefix = format!("{}:", id.to_hex()).into_bytes();
    for (key, bytes) in SYNC_QN_E.scan_from(&vault.store, txn, &key_prefix)? {
        let frame = crate::sync::transport::decode_document(
            bytes
                .get(1..)
                .ok_or_else(|| invalid("NOTE pending frame"))?,
        )
        .map_err(|_| invalid("NOTE pending frame"))?;
        let operation = super::NoteOperation::decode(frame.payload)?;
        if let super::NoteChange::Cite { pin } = operation.change
            && drops(vault, txn, &pin)?
        {
            SYNC_QN_E.delete(&vault.store, txn, &key)?;
            super::pin_index::remove_citation_request(&vault.store, txn, id, operation.request_id)?;
            dropped = true;
        }
    }
    Ok(dropped)
}

/// Whether this vault holds the pin's document or claim deleted. A sanctioned
/// re-put of the row lifts its fence, and the pin stays.
#[cfg(feature = "sync")]
fn source_deleted(vault: &Vault, txn: &heed::RoTxn<'_>, pin: &super::NotePin) -> Result<bool> {
    Ok(
        crate::ports::removed_in_txn(&vault.store, txn, &pin.document)?
            || crate::ports::removed_in_txn(&vault.store, txn, &pin.claim)?,
    )
}
