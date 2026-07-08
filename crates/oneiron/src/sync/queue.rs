//! Persistent offline queue backed by LMDB.
//!
//! Stores pending sync updates, embed jobs, and hard-delete sweep jobs in the
//! `sync_queue` database (#25).
//! Updates are keyed by monotonic sequence number for ordered replay.
//!
//! Key format (per ARCH-023b §5.4):
//! - `q:{seq:8BE}` → `[window_key_len:1][window_key][encoded_update]`
//! - `e:{entity_id:16}` → `[priority:1][queued_at:8BE]`
//! - `h:{seq:8BE}` → ARCH-0038 hard-delete historical-carrier sweep job
//! - `d:{seq:8BE}` → `[1]` — engine-internal DELETE-BEARING sidecar marker
//!   (ONE-1135): the matching `q:{seq}` row carries a tombstone-commit
//!   delta. Delete-bearing rows are EXEMPT from every optimistic clear
//!   (`clear_through` / `clear_updates` / `clear_all`) and are removed only
//!   by [`SyncQueue::clear_through_confirmed`] once the server VV confirms
//!   receipt (protocol lands in M4-12). Losing one would silently lose a
//!   GDPR delete on an unconfirmed reconnect — fail-closed: keep until
//!   confirmed.
//!
//!   Constructed ONLY by the tombstone-commit path: `push_delete_bearing_in_txn`
//!   takes a `DeleteBearingUpdate`, whose single constructor is
//!   `export_tombstone_commit_delta`
//!   — arbitrary payloads can never acquire the marker and its clear/scrub
//!   exemptions (ONE-1135 review item 14). Invariant: a `d:{seq}` marker
//!   never outlives its `q:{seq}` row — the malformed-row prune drops both
//!   in the same txn, and sequence recovery treats any surviving (orphan)
//!   marker's seq as allocated so it is never reused (ONE-1135 review
//!   item 15).

use std::collections::HashSet;
use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::sync::transport::MAX_WINDOW_KEY_LEN;
use crate::sync::types::parse_window_key_str;
use crate::sync::window::DeleteBearingUpdate;
use crate::types::EntityId;

/// Maximum number of queue entries before triggering re-bootstrap.
const MAX_QUEUE_SIZE: usize = 10_000;

/// Prefix for update queue entries.
const UPDATE_PREFIX: &[u8] = b"q:";
/// Prefix for embed job entries.
const EMBED_PREFIX: &[u8] = b"e:";
/// Prefix for delete-bearing sidecar markers (ONE-1135).
pub(crate) const DELETE_BEARING_PREFIX: &[u8] = b"d:";
/// Metadata key storing the last allocated update sequence number.
const LAST_UPDATE_SEQ_KEY: &[u8] = b"m:last_update_seq";
const ERR_SYNC_QUEUE_UPDATE_ROW: &str = "sync queue update row";
const ERR_SYNC_QUEUE_EMBED_ROW: &str = "sync queue embed row";

/// A queued update ready for replay on reconnect.
#[derive(Debug)]
pub struct QueuedUpdate {
    /// Sequence number for ordering.
    pub seq: u64,
    /// Window key (YYYY-MM format).
    pub window_key: String,
    /// Raw CRDT update bytes (will be wire-encoded during replay via `encode_window_sync`).
    pub encoded: Vec<u8>,
}

/// A queued embed job for background processing.
#[derive(Debug)]
pub struct QueuedEmbedJob {
    /// Entity requiring embedding.
    pub entity_id: EntityId,
    /// Priority (`0` surfaced-hot, `1` server, `2` device, `3` backfill).
    pub priority: u8,
    /// When the job was queued (Unix ms).
    pub queued_at: u64,
}

/// Persistent offline queue backed by LMDB `sync_queue` database.
///
/// LMDB serializes writers and the queue relies on monotonic `u64` sequence
/// numbers in metadata for ordering. `drain_updates`, `drain_embed_jobs`,
/// and `clear_through` drop their read txn before opening a fresh write
/// txn for the prune/metadata step — concurrent writers between the two
/// txns would race. Under the single-sync-client design (one `SyncClient`
/// per `Vault`) this is benign. If multi-writer semantics are ever
/// required, collapse read-then-prune into a single write txn.
pub struct SyncQueue {
    vault: Arc<Vault>,
}

impl SyncQueue {
    /// Creates a new queue.
    pub fn new(vault: Arc<Vault>) -> Result<Self> {
        Ok(Self { vault })
    }

    /// Pushes a sync update to the persistent queue.
    ///
    /// Returns the assigned sequence number.
    pub fn push(&self, window_key: &str, update_bytes: &[u8]) -> Result<u64> {
        let value = encode_update_value(window_key, update_bytes)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let seq = self.allocate_next_update_seq(&mut wtxn)?;
        let key = encode_update_key(seq);
        self.vault.store.sync_queue.put(&mut wtxn, &key, &value)?;
        wtxn.commit()?;

        Ok(seq)
    }

    /// Test-only variant of the delete path's queue write: pushes a
    /// DELETE-BEARING `q:` row + `d:{seq:8BE}` sidecar marker with
    /// synthetic bytes, bypassing the [`DeleteBearingUpdate`] construction
    /// pin. NOT part of the public API (ONE-1135 review item 14: a public
    /// raw-byte entry point let any caller mark arbitrary payloads
    /// delete-bearing, granting them every clear/scrub exemption).
    /// Production delete-bearing rows are written exclusively by
    /// [`push_delete_bearing_in_txn`] with a delta exported by
    /// `export_tombstone_commit_delta`.
    ///
    /// Delete-bearing rows replay like any other `q:` row on reconnect but
    /// are exempt from the optimistic clears; only
    /// [`clear_through_confirmed`](Self::clear_through_confirmed) (the
    /// VV-confirmed path, M4-12) removes them.
    #[cfg(test)]
    fn push_delete_bearing(&self, window_key: &str, update_bytes: &[u8]) -> Result<u64> {
        let update = DeleteBearingUpdate::for_test(update_bytes.to_vec());
        let mut wtxn = self.vault.store.env.write_txn()?;
        let seq = push_delete_bearing_in_txn(&self.vault, &mut wtxn, window_key, &update)?;
        wtxn.commit()?;
        Ok(seq)
    }

    /// Pushes an embed job for background processing.
    pub fn push_embed_job(&self, entity_id: &EntityId, priority: u8) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        push_embed_job_in_txn(&self.vault.store, &mut wtxn, entity_id, priority)?;
        wtxn.commit()?;

        Ok(())
    }

    /// Drains all pending update entries ordered by sequence number.
    ///
    /// Does not remove entries — use `clear_through` after convergence.
    pub fn drain_updates(&self) -> Result<Vec<QueuedUpdate>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut updates = Vec::new();
        let mut malformed_keys = Vec::new();

        let iter = self.vault.store.sync_queue.iter(&rtxn)?;
        for result in iter {
            let (key, value) = result?;
            if !key.starts_with(UPDATE_PREFIX) {
                continue;
            }
            let update = match decode_update_row(key, value) {
                Ok(update) => update,
                Err(Error::CorruptedIndex(_)) => {
                    malformed_keys.push(key.to_vec());
                    continue;
                }
                Err(err) => return Err(err),
            };
            updates.push(update);
        }
        drop(rtxn);

        self.prune_malformed_rows(&malformed_keys, decode_update_row)?;

        Ok(updates)
    }

    /// Drains all pending embed jobs.
    pub fn drain_embed_jobs(&self) -> Result<Vec<QueuedEmbedJob>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut jobs = Vec::new();
        let mut malformed_keys = Vec::new();

        let iter = self.vault.store.sync_queue.iter(&rtxn)?;
        for result in iter {
            let (key, value) = result?;
            if !key.starts_with(EMBED_PREFIX) {
                continue;
            }
            let job = match decode_embed_job_row(key, value) {
                Ok(job) => job,
                Err(Error::CorruptedIndex(_)) => {
                    malformed_keys.push(key.to_vec());
                    continue;
                }
                Err(err) => return Err(err),
            };
            jobs.push(job);
        }
        drop(rtxn);

        self.prune_malformed_rows(&malformed_keys, decode_embed_job_row)?;
        jobs.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.queued_at.cmp(&right.queued_at))
                .then_with(|| left.entity_id.as_bytes().cmp(right.entity_id.as_bytes()))
        });

        Ok(jobs)
    }

    /// Clears all update entries with sequence number <= `max_seq` —
    /// EXCEPT delete-bearing rows (ONE-1135).
    ///
    /// Called after the OPTIMISTIC reconnect replay. The replay is
    /// unconfirmed: the server may never have applied what was sent, so a
    /// delete-bearing update (the only durable propagation record of a
    /// GDPR/hard delete once the carrier-15 scrub ran) must be kept until
    /// the VV-confirmed clear (`clear_through_confirmed`,
    /// protocol lands in M4-12).
    pub fn clear_through(&self, max_seq: u64) -> Result<()> {
        self.clear_through_inner(max_seq, false)
    }

    /// Clears all update entries with sequence number <= `max_seq`,
    /// INCLUDING delete-bearing rows and their `d:` sidecar markers.
    ///
    /// VV-CONFIRMED path only (M4-12): the caller must have verified —
    /// via the bidirectional version-vector exchange — that the server's
    /// VV dominates every cleared update. Calling this on an optimistic
    /// (unconfirmed) replay silently loses offline deletes.
    pub fn clear_through_confirmed(&self, max_seq: u64) -> Result<()> {
        self.clear_through_inner(max_seq, true)
    }

    fn clear_through_inner(&self, max_seq: u64, include_delete_bearing: bool) -> Result<()> {
        let rtxn = self.vault.store.env.read_txn()?;
        let delete_bearing = delete_bearing_seqs_in_txn(&self.vault, &rtxn)?;
        let mut keys_to_delete = Vec::new();
        let mut malformed_keys = Vec::new();
        let metadata_seq = self
            .vault
            .store
            .sync_queue
            .get(&rtxn, LAST_UPDATE_SEQ_KEY)?
            .and_then(|raw| decode_last_update_seq_metadata(raw).ok());
        let mut remaining_max_seq = 0_u64;
        let iter = self.vault.store.sync_queue.iter(&rtxn)?;
        for result in iter {
            let (key, _) = result?;
            if !key.starts_with(UPDATE_PREFIX) {
                continue;
            }
            let seq = match decode_update_key(key) {
                Ok(seq) => seq,
                Err(Error::CorruptedIndex(_)) => {
                    malformed_keys.push(key.to_vec());
                    continue;
                }
                Err(err) => return Err(err),
            };
            if seq <= max_seq {
                if delete_bearing.contains(&seq) {
                    if include_delete_bearing {
                        keys_to_delete.push(key.to_vec());
                        keys_to_delete.push(encode_delete_bearing_key(seq).to_vec());
                    } else {
                        // Exempt: kept until VV-confirmed.
                        remaining_max_seq = remaining_max_seq.max(seq);
                    }
                } else {
                    keys_to_delete.push(key.to_vec());
                }
            } else {
                remaining_max_seq = remaining_max_seq.max(seq);
            }
        }
        drop(rtxn);

        let mut wtxn = self.vault.store.env.write_txn()?;
        for key in &keys_to_delete {
            self.vault.store.sync_queue.delete(&mut wtxn, key)?;
        }
        let preserved_seq = metadata_seq
            .unwrap_or(0)
            .max(remaining_max_seq)
            .max(max_seq);
        self.vault.store.sync_queue.put(
            &mut wtxn,
            LAST_UPDATE_SEQ_KEY,
            &preserved_seq.to_le_bytes(),
        )?;
        wtxn.commit()?;

        self.prune_malformed_rows(&malformed_keys, decode_update_row)?;

        Ok(())
    }

    /// Clears only update entries (`q:` prefix), preserving embed jobs
    /// (`e:` prefix) and delete-bearing rows (ONE-1135 — an unconfirmed
    /// clear must never drop a queued delete).
    ///
    /// Use this after convergence or when clearing stale updates without
    /// disrupting pending embed work.
    pub fn clear_updates(&self) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let _ = self.ensure_last_update_seq_metadata(&mut wtxn)?;
        let delete_bearing = delete_bearing_seqs_in_txn(&self.vault, &wtxn)?;
        let mut keys_to_delete = Vec::new();
        let iter = self.vault.store.sync_queue.iter(&wtxn)?;
        for result in iter {
            let (key, _) = result?;
            if key.starts_with(UPDATE_PREFIX)
                && !decode_update_key(key).is_ok_and(|seq| delete_bearing.contains(&seq))
            {
                keys_to_delete.push(key.to_vec());
            }
        }
        for key in &keys_to_delete {
            self.vault.store.sync_queue.delete(&mut wtxn, key)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Clears update and embed-job rows for re-bootstrap.
    ///
    /// Hard-delete sweep jobs (`h:`), metadata counters (`m:`), and
    /// delete-bearing update rows + their `d:` markers (ONE-1135) are
    /// intentionally preserved. Reconnect overflow is about the offline
    /// update queue only; wiping sweep jobs after a GDPR delete receipt has
    /// committed would strand historical carriers past the Art.17 SLA, and
    /// wiping a delete-bearing update before the server confirmed it would
    /// silently lose the delete itself.
    pub fn clear_all(&self) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let preserved_seq = self.recover_last_update_seq_for_clear(&wtxn)?;
        let delete_bearing = delete_bearing_seqs_in_txn(&self.vault, &wtxn)?;
        let mut keys_to_delete: Vec<Vec<u8>> = self
            .keys_with_prefix(&wtxn, UPDATE_PREFIX)?
            .into_iter()
            .filter(|key| !decode_update_key(key).is_ok_and(|seq| delete_bearing.contains(&seq)))
            .collect();
        keys_to_delete.extend(self.keys_with_prefix(&wtxn, EMBED_PREFIX)?);

        for key in &keys_to_delete {
            self.vault.store.sync_queue.delete(&mut wtxn, key)?;
        }
        self.vault.store.sync_queue.put(
            &mut wtxn,
            LAST_UPDATE_SEQ_KEY,
            &preserved_seq.to_le_bytes(),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Returns the number of valid update entries in the queue, INCLUDING
    /// delete-bearing rows (it matches what `drain_updates` replays).
    pub fn len(&self) -> Result<usize> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut count = 0;
        let iter = self
            .vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, UPDATE_PREFIX)?;
        for result in iter {
            let (key, value) = result?;
            match validate_update_row(key, value) {
                Ok(_) => count += 1,
                Err(Error::CorruptedIndex(_)) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(count)
    }

    /// Returns true if the queue has no update entries.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Returns true if the queue has reached its maximum capacity.
    ///
    /// Capacity gates the reconnect-overflow re-bootstrap (`is_full` →
    /// [`clear_all`](Self::clear_all)), so it counts ONLY rows that clear
    /// could actually drop: delete-bearing rows are exempt from every
    /// unconfirmed clear (they are removed solely by the VV-confirmed
    /// [`clear_through_confirmed`](Self::clear_through_confirmed)) and are
    /// excluded here. Counting them would let pending unconfirmed deletes
    /// wedge the queue permanently "full" — every reconnect re-firing a
    /// re-bootstrap that frees nothing (ONE-1135 review rider).
    pub fn is_full(&self) -> Result<bool> {
        Ok(self.clearable_len()? >= MAX_QUEUE_SIZE)
    }

    /// Counts the valid update rows the UNCONFIRMED clears may drop — i.e.
    /// [`len`](Self::len) minus delete-bearing rows.
    fn clearable_len(&self) -> Result<usize> {
        let rtxn = self.vault.store.env.read_txn()?;
        let delete_bearing = delete_bearing_seqs_in_txn(&self.vault, &rtxn)?;
        let mut count = 0;
        let iter = self
            .vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, UPDATE_PREFIX)?;
        for result in iter {
            let (key, value) = result?;
            match validate_update_row(key, value) {
                Ok(())
                    if !decode_update_key(key).is_ok_and(|seq| delete_bearing.contains(&seq)) =>
                {
                    count += 1;
                }
                Ok(()) => {}
                Err(Error::CorruptedIndex(_)) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(count)
    }

    fn allocate_next_update_seq(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        allocate_next_update_seq_in_txn(&self.vault, wtxn)
    }

    /// Ensures queue sequence metadata exists and matches the persisted queue.
    fn ensure_last_update_seq_metadata(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        ensure_last_update_seq_metadata_in_txn(&self.vault, wtxn)
    }

    fn recover_last_update_seq_for_clear(&self, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
        let metadata_seq = self
            .vault
            .store
            .sync_queue
            .get(wtxn, LAST_UPDATE_SEQ_KEY)?
            .and_then(|raw| decode_last_update_seq_metadata(raw).ok());
        let max_valid_seq = max_valid_update_seq_in_txn(&self.vault, wtxn)?;
        Ok(metadata_seq.unwrap_or(0).max(max_valid_seq))
    }

    fn keys_with_prefix(&self, wtxn: &heed::RwTxn<'_>, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        let iter = self.vault.store.sync_queue.prefix_iter(wtxn, prefix)?;
        for result in iter {
            let (key, _) = result?;
            keys.push(key.to_vec());
        }
        Ok(keys)
    }

    /// Deletes persisted rows whose decode still fails under a fresh write
    /// transaction. The `decode` closure determines what "malformed" means for
    /// a given row family (update vs embed job).
    fn prune_malformed_rows<T>(
        &self,
        malformed_keys: &[Vec<u8>],
        decode: impl Fn(&[u8], &[u8]) -> Result<T>,
    ) -> Result<()> {
        if malformed_keys.is_empty() {
            return Ok(());
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        for key in malformed_keys {
            let Some(value) = self.vault.store.sync_queue.get(&wtxn, key)? else {
                continue;
            };
            if decode(key, value).is_err() {
                self.vault.store.sync_queue.delete(&mut wtxn, key)?;
                // Sidecar invariant (ONE-1135 review item 15): a `d:{seq}`
                // marker must never outlive its `q:{seq}` row — a stale
                // orphan marker would grant the delete-bearing clear/scrub
                // exemptions to a future unrelated row if the sequence
                // were ever reused after metadata loss. The marker itself
                // protects no payload (the `q:` row IS the payload), so
                // dropping it is safe exactly here: the `q:` row is
                // provably gone, deleted in THIS txn. Embed keys never
                // decode as update keys, so this arm is a no-op for the
                // embed family.
                if let Ok(seq) = decode_update_key(key) {
                    self.vault
                        .store
                        .sync_queue
                        .delete(&mut wtxn, &encode_delete_bearing_key(seq))?;
                }
            }
        }
        wtxn.commit()?;
        Ok(())
    }
}

pub(crate) fn push_embed_job_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity_id: &EntityId,
    priority: u8,
) -> Result<()> {
    let key = encode_embed_key(entity_id);
    let (priority, queued_at) = match store.sync_queue.get(wtxn, &key)? {
        Some(existing) => match decode_embed_job_value(existing) {
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
    Ok(store.sync_queue.delete(wtxn, &key)?)
}

// ─── Delete-path transaction helpers (ONE-1135) ─────────────────────────────
//
// The carrier-15 scrub and the delete-bearing push run inside the DELETE
// path's own LMDB transaction (`Vault::write_crdt_tombstone` /
// `sync::window::replay_pending_tombstones`), atomically with the window-doc
// snapshot persist — both DBs live in the same LMDB env. They are free
// functions taking `&Vault` because the delete path holds `&Vault`, not the
// `Arc<Vault>` a `SyncQueue` handle wants.

fn allocate_next_update_seq_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
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

fn ensure_last_update_seq_metadata_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let metadata = match vault.store.sync_queue.get(&*wtxn, LAST_UPDATE_SEQ_KEY)? {
        Some(raw) => decode_last_update_seq_metadata(raw).ok(),
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
fn max_valid_update_seq_in_txn(vault: &Vault, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
    let mut max_valid_seq = 0_u64;
    let iter = vault.store.sync_queue.prefix_iter(wtxn, UPDATE_PREFIX)?;
    for result in iter {
        let (key, _) = result?;
        if let Ok(seq) = decode_update_key(key) {
            max_valid_seq = max_valid_seq.max(seq);
        }
    }
    for result in vault
        .store
        .sync_queue
        .prefix_iter(wtxn, DELETE_BEARING_PREFIX)?
    {
        let (key, _) = result?;
        if let Some(seq) = decode_delete_bearing_key(key) {
            max_valid_seq = max_valid_seq.max(seq);
        }
    }
    Ok(max_valid_seq)
}

/// Returns the set of sequence numbers carrying a `d:{seq:8BE}` sidecar
/// marker. Malformed marker keys are ignored (they protect nothing).
fn delete_bearing_seqs_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<HashSet<u64>> {
    let mut seqs = HashSet::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(txn, DELETE_BEARING_PREFIX)?
    {
        let (key, _) = row?;
        if let Some(seq) = decode_delete_bearing_key(key) {
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

/// ARCH-0038 carrier 15 ("Pending sync ops in the outgoing queue: drop ops
/// within the redacted span before transmission"), fail-closed
/// simplification (ONE-1135 OWNER-DECISION): drop EVERY pending `q:` row
/// addressed to `window_key` — plus any malformed `q:` row, which cannot be
/// proven payload-free — rather than inspecting opaque Loro update bytes
/// for the redacted span. Over-dropping is healed by the window's
/// full-resync marker (`fr:w:{key}`); leaking is not healable.
///
/// Delete-bearing rows are NEVER scrubbed: their payload is a
/// tombstone-commit delta (tombstone value + key-delete ops — opaque ids
/// only, no entity payload), and dropping one would lose a prior
/// unconfirmed delete. `e:` / `h:` / `m:` and unknown key families are
/// untouched.
pub(crate) fn scrub_window_updates_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
) -> Result<u32> {
    let delete_bearing = delete_bearing_seqs_in_txn(vault, wtxn)?;
    let mut doomed = Vec::new();
    for row in vault.store.sync_queue.prefix_iter(&*wtxn, UPDATE_PREFIX)? {
        let (key, value) = row?;
        let Ok(seq) = decode_update_key(key) else {
            doomed.push(key.to_vec());
            continue;
        };
        if delete_bearing.contains(&seq) {
            continue;
        }
        match decode_update_value_parts(value) {
            Ok((row_window, _)) if row_window == window_key => doomed.push(key.to_vec()),
            Ok(_) => {}
            // Fail-closed: a row that cannot prove which window it belongs
            // to cannot prove it is payload-free either.
            Err(_) => doomed.push(key.to_vec()),
        }
    }
    for key in &doomed {
        vault.store.sync_queue.delete(wtxn, key)?;
    }
    Ok(u32::try_from(doomed.len()).unwrap_or(u32::MAX))
}

/// Receiver-side carrier-15 scrub (ONE-1165): on a remote HARD delete applied
/// via live replay (Observer B) or recovery (forward_rematerialize), the
/// receiver's own `q:` outbox may carry the now-deleted payload. Mirror the
/// origin scrub: drop the window's pending `q:` rows (delete-bearing rows
/// preserved by the inner scrub) and set `fr:w:{key}` so any over-dropped
/// non-deleted op is re-sent on next connect.
///
/// Window-granular by design: Loro update bytes are opaque, so per-entity
/// filtering is impossible; over-drop is healed by full-resync, leak is not
/// healable.
pub(crate) fn scrub_receiver_outbox_on_remote_hard_delete_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
) -> Result<u32> {
    #[cfg(test)]
    maybe_inject_receiver_scrub_failure()?;

    let dropped = scrub_window_updates_in_txn(vault, wtxn, window_key)?;
    let fr_key = format!("fr:w:{window_key}");
    vault.store.sync_state.put(wtxn, &fr_key, &[1_u8])?;
    Ok(dropped)
}

#[cfg(test)]
thread_local! {
    static INJECT_RECEIVER_SCRUB_FAILURES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn maybe_inject_receiver_scrub_failure() -> Result<()> {
    let inject = INJECT_RECEIVER_SCRUB_FAILURES.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    });
    if inject {
        return Err(Error::Io(std::io::Error::other(
            "injected receiver outbox scrub failure (test hook)",
        )));
    }
    Ok(())
}

// ─── Key Encoding ────────────────────────────────────────────────────────────

/// Encodes an update queue key: `q:{seq:8BE}` (10 bytes).
fn encode_update_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(UPDATE_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Encodes a delete-bearing marker key: `d:{seq:8BE}` (10 bytes).
fn encode_delete_bearing_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(DELETE_BEARING_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Decodes the sequence number from a delete-bearing marker key.
fn decode_delete_bearing_key(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(DELETE_BEARING_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

/// Decodes the sequence number from an update queue key.
fn decode_update_key(key: &[u8]) -> Result<u64> {
    let seq = key
        .strip_prefix(UPDATE_PREFIX)
        .ok_or(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW))?;
    Ok(u64::from_be_bytes(seq.try_into().map_err(|_| {
        Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW)
    })?))
}

/// Encodes an update value: `[window_key_len:1][window_key][encoded_update]`.
fn encode_update_value(window_key: &str, update_bytes: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = window_key.as_bytes();
    if key_bytes.is_empty()
        || key_bytes.len() > MAX_WINDOW_KEY_LEN
        || parse_window_key_str(window_key).is_none()
    {
        return Err(Error::InvalidKey);
    }
    let mut value = Vec::with_capacity(1 + key_bytes.len() + update_bytes.len());
    value.push(key_bytes.len() as u8);
    value.extend_from_slice(key_bytes);
    value.extend_from_slice(update_bytes);
    Ok(value)
}

/// Decodes an update value into (window_key, encoded_update).
fn decode_update_value(value: &[u8]) -> Result<(String, Vec<u8>)> {
    let (window_key, encoded) = decode_update_value_parts(value)?;
    Ok((window_key.to_string(), encoded.to_vec()))
}

fn decode_update_value_parts(value: &[u8]) -> Result<(&str, &[u8])> {
    let Some((&key_len, rest)) = value.split_first() else {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    };
    let key_len = key_len as usize;
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    let Some((window_key_bytes, encoded)) = rest.split_at_checked(key_len) else {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    };
    let window_key = std::str::from_utf8(window_key_bytes)
        .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW))?;
    if parse_window_key_str(window_key).is_none() {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    Ok((window_key, encoded))
}

fn decode_update_row(key: &[u8], value: &[u8]) -> Result<QueuedUpdate> {
    let seq = decode_update_key(key)?;
    let (window_key, encoded) = decode_update_value(value)?;
    Ok(QueuedUpdate {
        seq,
        window_key,
        encoded,
    })
}

fn validate_update_row(key: &[u8], value: &[u8]) -> Result<()> {
    let _ = decode_update_key(key)?;
    let _ = decode_update_value_parts(value)?;
    Ok(())
}

/// Encodes an embed job key: `e:{entity_id:16}` (18 bytes).
fn encode_embed_key(entity_id: &EntityId) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[0..2].copy_from_slice(EMBED_PREFIX);
    key[2..18].copy_from_slice(entity_id.as_bytes());
    key
}

/// Decodes an entity ID from an embed job key.
fn decode_embed_key(key: &[u8]) -> Result<EntityId> {
    let bytes = key
        .strip_prefix(EMBED_PREFIX)
        .ok_or(Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?;
    EntityId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?,
    )
    .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))
}

fn decode_embed_job_row(key: &[u8], value: &[u8]) -> Result<QueuedEmbedJob> {
    let entity_id = decode_embed_key(key)?;
    let (priority, queued_at) = decode_embed_job_value(value)?;
    Ok(QueuedEmbedJob {
        entity_id,
        priority,
        queued_at,
    })
}

fn encode_embed_job_value(priority: u8, queued_at: u64) -> [u8; 9] {
    let mut value = [0_u8; 9];
    value[0] = priority;
    value[1..].copy_from_slice(&queued_at.to_be_bytes());
    value
}

fn decode_embed_job_value(value: &[u8]) -> Result<(u8, u64)> {
    let Some((&priority, queued_at_bytes)) = value.split_first() else {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW));
    };
    let queued_at = u64::from_be_bytes(
        queued_at_bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?,
    );
    Ok((priority, queued_at))
}

fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn decode_last_update_seq_metadata(raw: &[u8]) -> Result<u64> {
    if raw.len() != 8 {
        return Err(Error::CorruptedIndex("sync queue metadata"));
    }
    let bytes = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("sync queue metadata"))?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;
