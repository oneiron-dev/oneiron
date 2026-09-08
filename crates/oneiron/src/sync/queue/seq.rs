//! Seq allocation, delete-bearing seqs, embed-job txn helpers.

use super::codec::{
    decode_delete_bearing_key, decode_embed_job_value, decode_last_update_seq_metadata,
    decode_update_key, encode_delete_bearing_key, encode_embed_job_value, encode_embed_key,
    encode_update_key, encode_update_value, unix_millis_now,
};
use super::{DELETE_BEARING_PREFIX, LAST_UPDATE_SEQ_KEY, UPDATE_PREFIX};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::sync::window::DeleteBearingUpdate;
use std::collections::HashSet;

// ─── Delete-path transaction helpers (ONE-1135) ─────────────────────────────
//
// The carrier-15 scrub and the delete-bearing push run inside the DELETE
// path's own LMDB transaction (`Vault::write_crdt_tombstone` /
// `sync::window::replay_pending_tombstones`), atomically with the window-doc
// snapshot persist — both DBs live in the same LMDB env. They are free
// functions taking `&Vault` because the delete path holds `&Vault`, not the
// `Arc<Vault>` a `SyncQueue` handle wants.

pub(crate) fn push_embed_job_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity_id: &EntityId,
    priority: u8,
) -> Result<()> {
    let key = encode_embed_key(entity_id);
    let (priority, queued_at) = match store.sync_queue.get(wtxn, &key)? {
        Some(existing) => match decode_embed_job_value(&existing) {
            Ok((existing_priority, existing_queued_at)) if existing_priority <= priority => {
                (existing_priority, existing_queued_at)
            }
            _ => (priority, unix_millis_now()),
        },
        None => (priority, unix_millis_now()),
    };
    let value = encode_embed_job_value(priority, queued_at);
    store.sync_queue.put(wtxn, &key, &value)?;
    Ok(())
}

pub(crate) fn delete_embed_job_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity_id: &EntityId,
) -> Result<bool> {
    let key = encode_embed_key(entity_id);
    store.sync_queue.delete(wtxn, &key)
}

pub(super) fn allocate_next_update_seq_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let current = ensure_last_update_seq_metadata_in_txn(vault, wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("sync queue sequence"))?;
    if vault
        .store
        .sync_queue
        .get(&*wtxn, &encode_update_key(next))?
        .is_some()
    {
        return Err(Error::CorruptedIndex("sync queue metadata"));
    }
    vault
        .store
        .sync_queue
        .put(wtxn, LAST_UPDATE_SEQ_KEY, &next.to_le_bytes())?;
    Ok(next)
}

pub(super) fn ensure_last_update_seq_metadata_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let metadata = match vault.store.sync_queue.get(&*wtxn, LAST_UPDATE_SEQ_KEY)? {
        Some(raw) => decode_last_update_seq_metadata(&raw).ok(),
        None => None,
    };
    let max_valid_seq = max_valid_update_seq_in_txn(vault, wtxn)?;
    let repaired = match metadata {
        Some(seq) if seq >= max_valid_seq => seq,
        _ => max_valid_seq,
    };
    vault
        .store
        .sync_queue
        .put(wtxn, LAST_UPDATE_SEQ_KEY, &repaired.to_le_bytes())?;
    Ok(repaired)
}

/// Highest sequence number that must never be re-allocated: the max over
/// surviving valid `q:` rows AND `d:{seq}` sidecar markers.
///
/// Including the markers is the fail-closed leg of the sidecar invariant
/// (ONE-1135 review item 15): if the metadata cursor is lost after a
/// delete-bearing `q:` row vanished (legacy prune, crash window), an
/// orphan `d:` marker must never see its sequence reused — an unrelated
/// future `q:` row at that seq would silently inherit every
/// delete-bearing clear/scrub exemption.
pub(super) fn max_valid_update_seq_in_txn(vault: &Vault, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
    let mut max_valid_seq = 0_u64;
    let iter = vault.store.sync_queue.prefix_iter(wtxn, UPDATE_PREFIX)?;
    for result in iter {
        let (key, _) = result?;
        if let Ok(seq) = decode_update_key(&key) {
            max_valid_seq = max_valid_seq.max(seq);
        }
    }
    for result in vault
        .store
        .sync_queue
        .prefix_iter(wtxn, DELETE_BEARING_PREFIX)?
    {
        let (key, _) = result?;
        if let Some(seq) = decode_delete_bearing_key(&key) {
            max_valid_seq = max_valid_seq.max(seq);
        }
    }
    Ok(max_valid_seq)
}

/// Returns the set of sequence numbers carrying a `d:{seq:8BE}` sidecar
/// marker. Malformed marker keys are ignored (they protect nothing).
pub(super) fn delete_bearing_seqs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<HashSet<u64>> {
    let mut seqs = HashSet::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(txn, DELETE_BEARING_PREFIX)?
    {
        let (key, _) = row?;
        if let Some(seq) = decode_delete_bearing_key(&key) {
            seqs.insert(seq);
        }
    }
    Ok(seqs)
}

/// Pushes a delete-bearing update row + its `d:{seq:8BE}` marker inside the
/// caller's transaction (the delete path commits it atomically with the
/// window-doc snapshot persist and the carrier-15 scrub).
///
/// The [`DeleteBearingUpdate`] parameter is the confinement pin (ONE-1135
/// review item 14): its single constructor is
/// [`export_tombstone_commit_delta`](crate::sync::window::export_tombstone_commit_delta),
/// so a `d:` marker — and the clear/scrub exemptions it grants — can only
/// ever cover a real tombstone-commit delta, never arbitrary caller bytes.
pub(crate) fn push_delete_bearing_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    update: &DeleteBearingUpdate,
) -> Result<u64> {
    let value = encode_update_value(window_key, update.as_bytes())?;
    let seq = allocate_next_update_seq_in_txn(vault, wtxn)?;
    vault
        .store
        .sync_queue
        .put(wtxn, &encode_update_key(seq), &value)?;
    vault
        .store
        .sync_queue
        .put(wtxn, &encode_delete_bearing_key(seq), &[1u8])?;
    Ok(seq)
}
