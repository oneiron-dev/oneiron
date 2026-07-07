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
mod tests {
    use super::*;
    use crate::deletion::{
        HardEraseSweepExtras, LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionScope, TombstoneReason,
        TombstoneValueV2, encode_hard_erase_sweep_job, encode_hard_erase_sweep_key,
    };
    use crate::sync::WindowKey;
    use crate::sync::bridge::{self, Materializer};
    use crate::sync::quarantine;
    use crate::sync::schema::create_window_doc;
    use crate::sync::window::forward_rematerialize;
    use crate::types::{ENTITY_TYPE_TASK, TimeRange, VaultConfig};
    use core::assert_matches;

    const RECEIVER_SCRUB_WINDOW: &str = "2026-03";
    const RECEIVER_SCRUB_LEARNED_AT: u64 = 1_772_400_000;

    struct ReceiverOutboxFixture {
        queue: SyncQueue,
        victim_payload_seq: u64,
        other_payload_seq: u64,
        delete_bearing_seq: u64,
    }

    struct PurgeFailureReset;

    impl Drop for PurgeFailureReset {
        fn drop(&mut self) {
            quarantine::INJECT_PURGE_FAILURES.with(|cell| cell.set(0));
        }
    }

    struct ReceiverScrubFailureReset;

    impl Drop for ReceiverScrubFailureReset {
        fn drop(&mut self) {
            INJECT_RECEIVER_SCRUB_FAILURES.with(|cell| cell.set(0));
        }
    }

    fn test_vault() -> Arc<Vault> {
        let dir = tempfile::tempdir().unwrap();
        let config = VaultConfig::device();
        Arc::new(Vault::open(dir.path(), config).unwrap())
    }

    fn arm_purge_failures(count: u32) -> PurgeFailureReset {
        quarantine::INJECT_PURGE_FAILURES.with(|cell| cell.set(count));
        PurgeFailureReset
    }

    fn arm_receiver_scrub_failures(count: u32) -> ReceiverScrubFailureReset {
        INJECT_RECEIVER_SCRUB_FAILURES.with(|cell| cell.set(count));
        ReceiverScrubFailureReset
    }

    fn receiver_hard_tombstone_value() -> [u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN] {
        TombstoneValueV2 {
            reason: TombstoneReason::GdprDelete,
            deleted_at: RECEIVER_SCRUB_LEARNED_AT,
            request_id: [0xA5; 16],
        }
        .encode()
    }

    fn receiver_soft_tombstone_value() -> [u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN] {
        TombstoneValueV2 {
            reason: TombstoneReason::UserDelete,
            deleted_at: RECEIVER_SCRUB_LEARNED_AT,
            request_id: [0x5A; 16],
        }
        .encode()
    }

    fn task_body() -> Vec<u8> {
        crate::types::task_body_for_test(crate::types::TaskRole::Task)
    }

    fn put_receiver_entity(vault: &Vault, id: &EntityId, _body: &[u8]) {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: RECEIVER_SCRUB_LEARNED_AT,
                    end: RECEIVER_SCRUB_LEARNED_AT,
                },
                RECEIVER_SCRUB_LEARNED_AT,
                &task_body(),
            )
            .unwrap();
    }

    fn seed_receiver_outbox(vault: &Arc<Vault>) -> ReceiverOutboxFixture {
        let queue = SyncQueue::new(Arc::clone(vault)).unwrap();
        let victim_payload_seq = queue
            .push(RECEIVER_SCRUB_WINDOW, b"queued victim payload")
            .unwrap();
        let other_payload_seq = queue
            .push(RECEIVER_SCRUB_WINDOW, b"queued unrelated payload")
            .unwrap();
        let delete_bearing_seq = queue
            .push_delete_bearing(RECEIVER_SCRUB_WINDOW, b"queued delete delta")
            .unwrap();
        ReceiverOutboxFixture {
            queue,
            victim_payload_seq,
            other_payload_seq,
            delete_bearing_seq,
        }
    }

    fn queued_update_seqs(queue: &SyncQueue) -> Vec<u64> {
        queue
            .drain_updates()
            .unwrap()
            .iter()
            .map(|update| update.seq)
            .collect()
    }

    fn assert_receiver_outbox_scrubbed(vault: &Vault, outbox: &ReceiverOutboxFixture) {
        let seqs = queued_update_seqs(&outbox.queue);
        assert!(
            !seqs.contains(&outbox.victim_payload_seq),
            "victim payload q: row must be scrubbed"
        );
        assert!(
            !seqs.contains(&outbox.other_payload_seq),
            "receiver scrub is window-granular: unrelated same-window q: row is over-dropped"
        );
        assert!(
            seqs.contains(&outbox.delete_bearing_seq),
            "delete-bearing q: row must survive the receiver scrub"
        );
        assert_eq!(
            vault
                .sync_state_get(&format!("fr:w:{RECEIVER_SCRUB_WINDOW}"))
                .unwrap()
                .as_deref(),
            Some([1_u8].as_slice()),
            "fr:w marker must heal over-dropped non-deleted ops"
        );
    }

    fn assert_receiver_outbox_intact(vault: &Vault, outbox: &ReceiverOutboxFixture) {
        let seqs = queued_update_seqs(&outbox.queue);
        assert!(
            seqs.contains(&outbox.victim_payload_seq),
            "victim payload q: row must remain"
        );
        assert!(
            seqs.contains(&outbox.other_payload_seq),
            "unrelated same-window q: row must remain"
        );
        assert!(
            seqs.contains(&outbox.delete_bearing_seq),
            "delete-bearing q: row must remain"
        );
        assert!(
            vault
                .sync_state_get(&format!("fr:w:{RECEIVER_SCRUB_WINDOW}"))
                .unwrap()
                .is_none(),
            "fr:w is HARD-success-only"
        );
    }

    #[test]
    fn push_and_drain_roundtrip() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        queue.push("2026-03", &[1, 2, 3]).unwrap();
        queue.push("2026-02", &[4, 5, 6]).unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].seq, 1);
        assert_eq!(updates[0].window_key, "2026-03");
        assert_eq!(updates[0].encoded, vec![1, 2, 3]);
        assert_eq!(updates[1].seq, 2);
        assert_eq!(updates[1].window_key, "2026-02");
        assert_eq!(updates[1].encoded, vec![4, 5, 6]);
    }

    #[test]
    fn clear_through_removes_up_to_seq() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        queue.push("2026-03", &[2]).unwrap();
        queue.push("2026-03", &[3]).unwrap();

        queue.clear_through(2).unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 3);
    }

    #[test]
    fn push_rejects_invalid_window_key_without_burning_sequence() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        let err = queue
            .push("", &[1])
            .expect_err("empty window key must fail");
        assert_matches!(err, Error::InvalidKey);

        let overlong = "x".repeat(MAX_WINDOW_KEY_LEN + 1);
        let err = queue
            .push(&overlong, &[2])
            .expect_err("overlong window key must fail");
        assert_matches!(err, Error::InvalidKey);

        for invalid in [
            "2026-13", "2026-00", "abcdefg", "2026-3", "1969-12", "0000-01",
        ] {
            let err = queue
                .push(invalid, &[9])
                .expect_err("invalid calendar window key must fail");
            assert_matches!(err, Error::InvalidKey);
        }

        let seq = queue.push("2026-03", &[3]).unwrap();
        assert_eq!(seq, 1);

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);
        assert_eq!(updates[0].window_key, "2026-03");
        assert_eq!(updates[0].encoded, vec![3]);
    }

    #[test]
    fn clear_all_resets_queue() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        queue.push("2026-03", &[2]).unwrap();

        queue.clear_all().unwrap();

        assert_eq!(queue.len().unwrap(), 0);
        assert!(!queue.is_full().unwrap());

        let seq = queue.push("2026-03", &[3]).unwrap();
        assert_eq!(seq, 3);
    }

    #[test]
    fn clear_all_preserves_hard_erase_sweeps_and_metadata_counters() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let update_seq = queue.push("2026-03", &[1]).unwrap();
        let embed_id = EntityId::now();
        queue.push_embed_job(&embed_id, 1).unwrap();

        let sweep_seq = 7_u64;
        let sweep_key = encode_hard_erase_sweep_key(sweep_seq);
        let sweep_value = encode_hard_erase_sweep_job(
            RedactionScope::entity(&EntityId::now()),
            HardEraseSweepExtras::default(),
            1_772_000_000,
        )
        .unwrap();
        let embed_key = encode_embed_key(&embed_id);

        // An UNKNOWN key family (`zz:`) the queue does not own: every clear
        // and scrub must leave foreign families untouched (ONE-1135). NOTE:
        // `x:` no longer qualifies — it is the quarantine family (ONE-1124)
        // whose retention pass evicts rows that do not parse as x:{seq}.
        let unknown_key = b"zz:future-family";
        let unknown_value = b"opaque";

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &sweep_key, &sweep_value)
            .unwrap();
        vault
            .store
            .sync_queue
            .put(
                &mut wtxn,
                LAST_HARD_ERASE_SWEEP_SEQ_KEY,
                &sweep_seq.to_le_bytes(),
            )
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, unknown_key.as_slice(), unknown_value.as_slice())
            .unwrap();
        wtxn.commit().unwrap();

        // ONE-1124 AC6 — quarantine rows (x:) and their m: counters live in
        // the same DB and must survive every queue clear path.
        let quarantine_seq = quarantine::quarantine_rejected_op(
            &vault,
            "2026-03",
            quarantine::QuarantineContainer::Entities,
            "deadbeef",
            &Error::InvalidKey,
            b"payload",
        )
        .unwrap();
        let quarantine_key = quarantine::encode_quarantine_key(quarantine_seq);

        queue.clear_all().unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_update_key(update_seq))
                .unwrap()
                .is_none(),
            "clear_all must drop queued update rows",
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &embed_key)
                .unwrap()
                .is_none(),
            "clear_all must drop queued embed-job rows",
        );
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &sweep_key).unwrap(),
            Some(sweep_value.as_slice()),
            "clear_all must preserve hard-erase sweep jobs",
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &quarantine_key)
                .unwrap()
                .is_some(),
            "clear_all must preserve quarantine rows (x:)",
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, quarantine::LAST_QUARANTINE_SEQ_KEY)
                .unwrap(),
            Some(quarantine_seq.to_le_bytes().as_slice()),
            "clear_all must preserve the quarantine sequence cursor",
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, LAST_UPDATE_SEQ_KEY)
                .unwrap(),
            Some(update_seq.to_le_bytes().as_slice()),
            "clear_all must preserve the update sequence cursor",
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)
                .unwrap(),
            Some(sweep_seq.to_le_bytes().as_slice()),
            "clear_all must preserve the hard-erase sweep cursor",
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, unknown_key.as_slice())
                .unwrap(),
            Some(unknown_value.as_slice()),
            "clear_all must preserve unknown key families",
        );
        drop(rtxn);

        // ONE-1091 durability closure: surviving the overflow re-bootstrap
        // byte-identically is not enough — the preserved obligation must
        // still be ACTIONABLE. The sweep executor consumes it end-to-end
        // (decode → execute → row deleted) after the clear.
        let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
        assert_eq!(
            report.sweep_jobs_processed, 1,
            "the h: row preserved across clear_all must still execute"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &sweep_key)
                .unwrap()
                .is_none(),
            "the executed obligation row is consumed"
        );
    }

    /// ONE-1135: `push_delete_bearing` writes the `q:` row AND the pinned
    /// `d:{seq:8BE}` sidecar marker. The marker key bytes are asserted as
    /// LITERALS (`d`, `:`, 8-byte big-endian sequence), not via the
    /// encoder.
    #[test]
    fn push_delete_bearing_writes_literal_sidecar_marker() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        let seq = queue.push_delete_bearing("2026-03", &[9, 9]).unwrap();
        assert_eq!(seq, 2);

        let expected_marker: Vec<u8> = [b'd', b':', 0, 0, 0, 0, 0, 0, 0, 2].to_vec();
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &expected_marker).unwrap(),
            Some([1u8].as_slice()),
            "delete-bearing sidecar marker must be d: + seq u64 BE",
        );
        // The q: row itself replays like any other update.
        drop(rtxn);
        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[1].seq, 2);
        assert_eq!(updates[1].encoded, vec![9, 9]);
    }

    /// ONE-1135 AC3: delete-bearing rows are EXEMPT from the optimistic
    /// `clear_through` (kept until VV-confirmed); the VV-confirmed variant
    /// removes the row AND its sidecar marker. An implementation that
    /// optimistically clears delete rows FAILS here — that is a silently
    /// lost offline GDPR delete.
    #[test]
    fn clear_through_keeps_delete_bearing_until_confirmed() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        let delete_seq = queue.push_delete_bearing("2026-03", &[2]).unwrap();
        queue.push("2026-03", &[3]).unwrap();

        // Optimistic clear after an unconfirmed replay.
        queue.clear_through(3).unwrap();
        let updates = queue.drain_updates().unwrap();
        assert_eq!(
            updates.len(),
            1,
            "non-delete rows cleared, delete-bearing row kept"
        );
        assert_eq!(updates[0].seq, delete_seq);
        assert_eq!(updates[0].encoded, vec![2]);

        let marker = encode_delete_bearing_key(delete_seq);
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &marker)
                .unwrap()
                .is_some(),
            "sidecar marker survives the optimistic clear"
        );
        drop(rtxn);

        // Sequence allocation continues monotonically past the kept row.
        let next = queue.push("2026-03", &[4]).unwrap();
        assert_eq!(next, 4);

        // VV-confirmed clear removes the delete row and its marker.
        queue.clear_through_confirmed(delete_seq).unwrap();
        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 4);
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &marker)
                .unwrap()
                .is_none(),
            "confirmed clear must remove the sidecar marker too"
        );
    }

    /// ONE-1135: the unconfirmed bulk clears (`clear_updates`, `clear_all`)
    /// preserve delete-bearing rows and their markers too.
    #[test]
    fn bulk_clears_preserve_delete_bearing_rows() {
        for clear in ["clear_updates", "clear_all"] {
            let vault = test_vault();
            let queue = SyncQueue::new(vault.clone()).unwrap();

            queue.push("2026-03", &[1]).unwrap();
            let delete_seq = queue.push_delete_bearing("2026-03", &[2]).unwrap();

            match clear {
                "clear_updates" => queue.clear_updates().unwrap(),
                _ => queue.clear_all().unwrap(),
            }

            let updates = queue.drain_updates().unwrap();
            assert_eq!(updates.len(), 1, "{clear} must keep the delete row");
            assert_eq!(updates[0].seq, delete_seq, "{clear}");
            let rtxn = vault.store.env.read_txn().unwrap();
            assert!(
                vault
                    .store
                    .sync_queue
                    .get(&rtxn, &encode_delete_bearing_key(delete_seq))
                    .unwrap()
                    .is_some(),
                "{clear} must keep the sidecar marker"
            );
        }
    }

    /// ONE-1135 review item 14: ordinary pushes can NEVER acquire a
    /// delete-bearing marker. The `d:` family is written exclusively by
    /// the tombstone-commit path (`push_delete_bearing_in_txn` taking a
    /// `DeleteBearingUpdate`, constructible only by
    /// `export_tombstone_commit_delta`); `SyncQueue::push` writes the `q:`
    /// row alone, so its rows keep ZERO clear/scrub exemptions.
    #[test]
    fn ordinary_push_never_acquires_delete_bearing_marker() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        queue.push("2026-04", &[2]).unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        let markers = vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, DELETE_BEARING_PREFIX)
            .unwrap()
            .count();
        assert_eq!(markers, 0, "ordinary q: rows must have no d: sidecar");
        drop(rtxn);

        // Consequently the unconfirmed clear drops them all.
        queue.clear_updates().unwrap();
        assert_eq!(queue.len().unwrap(), 0);
    }

    /// ONE-1135 review item 15: a `d:{seq}` sidecar marker must never
    /// outlive its `q:{seq}` row. When the malformed-row prune drops a
    /// delete-bearing `q:` row (key decodes, value no longer does), the
    /// matching `d:` marker is deleted in the SAME write txn — a stale
    /// orphan marker would otherwise grant the delete-bearing clear/scrub
    /// exemptions to a future unrelated row at a reused sequence.
    #[test]
    fn prune_removes_sidecar_marker_with_its_malformed_q_row() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        let delete_seq = queue.push_delete_bearing("2026-03", &[2]).unwrap();

        // Corrupt the delete-bearing row's VALUE in place (torn write /
        // bitrot shape): the key still decodes, the value does not.
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(delete_seq), &[0])
            .unwrap();
        wtxn.commit().unwrap();

        // drain_updates prunes rows whose decode fails.
        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_update_key(delete_seq))
                .unwrap()
                .is_none(),
            "malformed q: row must be pruned"
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_delete_bearing_key(delete_seq))
                .unwrap()
                .is_none(),
            "d: sidecar must be deleted in the same txn as its q: row"
        );
    }

    /// ONE-1135 review item 15, fail-closed leg: an orphan `d:` marker
    /// with no matching `q:` row (legacy prune before this fix, crash
    /// window) must never see its sequence reused. Sequence recovery
    /// includes marker seqs, so after metadata loss a later unrelated `q:`
    /// row cannot land on the marked seq and inherit the delete-bearing
    /// exemptions. The orphan marker itself is KEPT (it protects nothing,
    /// but its presence keeps the seq out of circulation — fail closed).
    #[test]
    fn orphan_sidecar_marker_never_poisons_a_reused_seq() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        // Inject an orphan d:1 with NO q: rows and NO metadata cursor —
        // the post-crash shape where pre-fix recovery rebuilt the cursor
        // from q: rows alone and handed out seq 1 again.
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_delete_bearing_key(1), &[1u8])
            .unwrap();
        wtxn.commit().unwrap();

        let seq = queue.push("2026-03", &[7]).unwrap();
        assert_eq!(seq, 2, "orphan marker seq must never be reused");

        // The new ordinary row is NOT delete-bearing: the optimistic clear
        // drops it (pre-fix, at the reused seq 1, the orphan marker
        // exempted it — a silently undeletable garbage row).
        queue.clear_through(seq).unwrap();
        assert_eq!(
            queue.len().unwrap(),
            0,
            "ordinary row must not inherit the delete-bearing exemption"
        );

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_delete_bearing_key(1))
                .unwrap()
                .is_some(),
            "orphan marker kept — fail closed, seq stays blocked"
        );
    }

    /// ONE-1135 AC4 (carrier-15 scrub): only the target window's
    /// non-delete-bearing `q:` rows are dropped. Delete-bearing rows,
    /// other windows' rows, and the `e:` / `h:` / `m:` / unknown (`x:`)
    /// families are untouched.
    #[test]
    fn scrub_window_updates_drops_only_target_window_payload_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let target_payload = queue.push("2026-02", &[0xAA]).unwrap();
        let other_window = queue.push("2026-03", &[0xBB]).unwrap();
        let target_delete = queue.push_delete_bearing("2026-02", &[0xCC]).unwrap();

        let embed_id = EntityId::now();
        queue.push_embed_job(&embed_id, 2).unwrap();

        let sweep_key = encode_hard_erase_sweep_key(1);
        let sweep_value = encode_hard_erase_sweep_job(
            RedactionScope::entity(&EntityId::now()),
            HardEraseSweepExtras::default(),
            1_772_000_000,
        )
        .unwrap();
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &sweep_key, &sweep_value)
            .unwrap();
        vault
            .store
            .sync_queue
            .put(
                &mut wtxn,
                b"x:future-family".as_slice(),
                b"opaque".as_slice(),
            )
            .unwrap();
        wtxn.commit().unwrap();

        let scrubbed = vault
            .with_write_txn(|wtxn| scrub_window_updates_in_txn(&vault, wtxn, "2026-02"))
            .unwrap();
        assert_eq!(scrubbed, 1, "exactly the target payload row is dropped");

        let updates = queue.drain_updates().unwrap();
        let seqs: Vec<u64> = updates.iter().map(|u| u.seq).collect();
        assert!(
            !seqs.contains(&target_payload),
            "target-window payload row must be scrubbed (carrier 15)"
        );
        assert!(
            seqs.contains(&other_window),
            "other windows' rows must survive"
        );
        assert!(
            seqs.contains(&target_delete),
            "delete-bearing rows must NEVER be scrubbed — dropping one loses a prior delete"
        );

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_embed_key(&embed_id))
                .unwrap()
                .is_some(),
            "e: family untouched"
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &sweep_key)
                .unwrap()
                .is_some(),
            "h: family untouched"
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, LAST_UPDATE_SEQ_KEY)
                .unwrap()
                .is_some(),
            "m: family untouched"
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, b"x:future-family".as_slice())
                .unwrap()
                .is_some(),
            "unknown families untouched"
        );
    }

    #[test]
    fn receiver_live_hard_tombstone_scrubs_window_outbox_and_sets_fr() {
        let vault = test_vault();
        let outbox = seed_receiver_outbox(&vault);
        let victim = EntityId::now();
        put_receiver_entity(&vault, &victim, b"payload to erase");

        let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
        let doc = create_window_doc("remote", &window_key);
        let materializer = Arc::new(Materializer::new());
        let _subs = bridge::register_observer_b(&doc, &vault, &materializer, RECEIVER_SCRUB_WINDOW);

        let hard = receiver_hard_tombstone_value();
        doc.get_map("tombstones")
            .insert(&victim.to_hex(), hard.as_slice())
            .unwrap();
        doc.commit();

        assert!(
            vault.get(&victim).unwrap().is_none(),
            "live hard tombstone must purge the active store first"
        );
        assert_receiver_outbox_scrubbed(&vault, &outbox);
    }

    #[test]
    fn receiver_forward_remat_hard_tombstone_scrubs_window_outbox_and_sets_fr() {
        let vault = test_vault();
        let outbox = seed_receiver_outbox(&vault);
        let victim = EntityId::now();
        put_receiver_entity(&vault, &victim, b"payload to erase");

        let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
        let doc = create_window_doc("remote", &window_key);
        let hard = receiver_hard_tombstone_value();
        doc.get_map("tombstones")
            .insert(&victim.to_hex(), hard.as_slice())
            .unwrap();
        doc.commit();

        let materializer = Materializer::new();
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

        assert!(
            vault.get(&victim).unwrap().is_none(),
            "recovery hard tombstone must purge the active store first"
        );
        assert_receiver_outbox_scrubbed(&vault, &outbox);
    }

    #[test]
    fn receiver_forward_remat_scrub_failure_keeps_outbox_and_sets_rm_retry() {
        let vault = test_vault();
        let outbox = seed_receiver_outbox(&vault);
        let victim = EntityId::now();
        put_receiver_entity(&vault, &victim, b"payload purged before scrub failure");

        let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
        let doc = create_window_doc("remote", &window_key);
        let hard = receiver_hard_tombstone_value();
        doc.get_map("tombstones")
            .insert(&victim.to_hex(), hard.as_slice())
            .unwrap();
        doc.commit();

        let _reset = arm_receiver_scrub_failures(1);
        let materializer = Materializer::new();
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

        assert!(
            vault.get(&victim).unwrap().is_none(),
            "hard tombstone purge should not roll back when scrub bookkeeping fails"
        );
        assert_receiver_outbox_intact(&vault, &outbox);
        assert_eq!(
            vault
                .sync_state_get(&format!("rm:w:{RECEIVER_SCRUB_WINDOW}:{}", victim.to_hex()))
                .unwrap()
                .as_deref(),
            Some([1_u8].as_slice()),
            "scrub failure must set rm: so recovery retries the receiver outbox scrub"
        );
    }

    #[test]
    fn receiver_live_soft_tombstone_keeps_outbox_and_does_not_set_fr() {
        let vault = test_vault();
        let outbox = seed_receiver_outbox(&vault);
        let victim = EntityId::now();
        put_receiver_entity(&vault, &victim, b"payload kept as soft shell");

        let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
        let doc = create_window_doc("remote", &window_key);
        let materializer = Arc::new(Materializer::new());
        let _subs = bridge::register_observer_b(&doc, &vault, &materializer, RECEIVER_SCRUB_WINDOW);

        let soft = receiver_soft_tombstone_value();
        doc.get_map("tombstones")
            .insert(&victim.to_hex(), soft.as_slice())
            .unwrap();
        doc.commit();

        assert!(
            vault.get(&victim).unwrap().is_some(),
            "soft tombstone keeps the local shell"
        );
        assert_receiver_outbox_intact(&vault, &outbox);
    }

    #[test]
    fn receiver_live_failed_hard_apply_keeps_outbox_and_sets_rm_retry() {
        let vault = test_vault();
        let outbox = seed_receiver_outbox(&vault);
        let victim = EntityId::now();
        put_receiver_entity(&vault, &victim, b"payload still live on injected failure");

        let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
        let doc = create_window_doc("remote", &window_key);
        let materializer = Arc::new(Materializer::new());
        let _subs = bridge::register_observer_b(&doc, &vault, &materializer, RECEIVER_SCRUB_WINDOW);

        let _reset = arm_purge_failures(1);
        let hard = receiver_hard_tombstone_value();
        doc.get_map("tombstones")
            .insert(&victim.to_hex(), hard.as_slice())
            .unwrap();
        doc.commit();

        assert!(
            vault.get(&victim).unwrap().is_some(),
            "failed hard replay must not purge active state"
        );
        assert_receiver_outbox_intact(&vault, &outbox);
        assert_eq!(
            vault
                .sync_state_get(&format!("rm:w:{RECEIVER_SCRUB_WINDOW}:{}", victim.to_hex()))
                .unwrap()
                .as_deref(),
            Some([1_u8].as_slice()),
            "failed hard replay must durably flag rm: retry"
        );
    }

    /// Fail-closed: a malformed `q:` row cannot prove which window it
    /// belongs to, so the carrier-15 scrub drops it (over-dropping is
    /// healed by the full resync; leaking is not healable).
    #[test]
    fn scrub_window_updates_drops_malformed_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();
        queue.push("2026-03", &[1]).unwrap();

        let bad_key = b"q:\x00".to_vec();
        let well_formed_key = encode_update_key(7);
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &[1, b'x'])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &well_formed_key, &[0])
            .unwrap();
        wtxn.commit().unwrap();

        vault
            .with_write_txn(|wtxn| scrub_window_updates_in_txn(&vault, wtxn, "2026-02"))
            .unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &bad_key)
                .unwrap()
                .is_none(),
            "malformed key must be dropped by the scrub"
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &well_formed_key)
                .unwrap()
                .is_none(),
            "row with undecodable value must be dropped by the scrub"
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_update_key(1))
                .unwrap()
                .is_some(),
            "well-formed rows of OTHER windows survive"
        );
    }

    #[test]
    fn own_device_sync_cap_counts_clearable_rows_at_capacity() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();
        let value = encode_update_value("2026-03", &[9]).unwrap();
        let mut wtxn = vault.store.env.write_txn().unwrap();
        for seq in 1..=(MAX_QUEUE_SIZE as u64) {
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &encode_update_key(seq), &value)
                .unwrap();
        }
        vault
            .store
            .sync_queue
            .put(
                &mut wtxn,
                LAST_UPDATE_SEQ_KEY,
                &(MAX_QUEUE_SIZE as u64).to_le_bytes(),
            )
            .unwrap();
        wtxn.commit().unwrap();

        assert!(queue.is_full().unwrap());
        queue.clear_all().unwrap();
        assert!(!queue.is_full().unwrap());
        assert_eq!(queue.len().unwrap(), 0);
    }

    /// ONE-1135 review rider: delete-bearing rows are exempt from every
    /// unconfirmed clear, so they must also be exempt from the capacity
    /// accounting that TRIGGERS the re-bootstrap (`is_full` → `clear_all`).
    /// Pre-fix, a queue holding `MAX_QUEUE_SIZE` delete-bearing rows
    /// reported full forever: `clear_all` preserved every row, the overflow
    /// check re-fired on each reconnect, and nothing was ever freed — a
    /// permanent re-bootstrap loop.
    #[test]
    fn is_full_excludes_delete_bearing_rows_from_capacity() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        // Seed MAX_QUEUE_SIZE delete-bearing rows in ONE txn (the public
        // push would be 10k commits) — exact row + marker bytes the delete
        // path writes.
        let value = encode_update_value("2026-03", &[9]).unwrap();
        let mut wtxn = vault.store.env.write_txn().unwrap();
        for seq in 1..=(MAX_QUEUE_SIZE as u64) {
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &encode_update_key(seq), &value)
                .unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &encode_delete_bearing_key(seq), &[1u8])
                .unwrap();
        }
        vault
            .store
            .sync_queue
            .put(
                &mut wtxn,
                LAST_UPDATE_SEQ_KEY,
                &(MAX_QUEUE_SIZE as u64).to_le_bytes(),
            )
            .unwrap();
        wtxn.commit().unwrap();

        assert_eq!(
            queue.len().unwrap(),
            MAX_QUEUE_SIZE,
            "len still counts every replayable row"
        );
        assert!(
            !queue.is_full().unwrap(),
            "unconfirmed-clear-exempt rows must not count toward overflow capacity"
        );

        // The re-bootstrap path frees clearable rows and converges to
        // not-full instead of looping.
        let normal_seq = queue.push("2026-03", &[1]).unwrap();
        queue.clear_all().unwrap();
        assert!(!queue.is_full().unwrap());
        assert_eq!(
            queue.len().unwrap(),
            MAX_QUEUE_SIZE,
            "delete-bearing rows preserved, the normal row dropped"
        );
        let remaining: Vec<u64> = queue
            .drain_updates()
            .unwrap()
            .iter()
            .map(|u| u.seq)
            .collect();
        assert!(!remaining.contains(&normal_seq));

        // VV-confirmed clear is what actually frees the delete rows.
        queue
            .clear_through_confirmed(MAX_QUEUE_SIZE as u64)
            .unwrap();
        assert_eq!(queue.len().unwrap(), 0);
        assert!(!queue.is_full().unwrap());
    }

    /// ONE-1124 AC6 — `clear_updates` and `clear_through` (including its
    /// malformed-row pruning) never touch quarantine rows or counters.
    #[test]
    fn clear_updates_and_clear_through_preserve_quarantine_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let quarantine_seq = quarantine::quarantine_rejected_op(
            &vault,
            "2026-03",
            quarantine::QuarantineContainer::Edges,
            "some-edge-key",
            &Error::InvalidEdgeWeight { value: 1.5 },
            b"edge-bytes",
        )
        .unwrap();
        let quarantine_key = quarantine::encode_quarantine_key(quarantine_seq);
        let evictions_value = 3u64.to_le_bytes();
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(
                &mut wtxn,
                quarantine::QUARANTINE_EVICTIONS_KEY,
                &evictions_value,
            )
            .unwrap();
        wtxn.commit().unwrap();

        let assert_quarantine_intact = |label: &str| {
            let rtxn = vault.store.env.read_txn().unwrap();
            assert!(
                vault
                    .store
                    .sync_queue
                    .get(&rtxn, &quarantine_key)
                    .unwrap()
                    .is_some(),
                "{label} must preserve quarantine rows (x:)",
            );
            assert_eq!(
                vault
                    .store
                    .sync_queue
                    .get(&rtxn, quarantine::LAST_QUARANTINE_SEQ_KEY)
                    .unwrap(),
                Some(quarantine_seq.to_le_bytes().as_slice()),
                "{label} must preserve the quarantine sequence cursor",
            );
            assert_eq!(
                vault
                    .store
                    .sync_queue
                    .get(&rtxn, quarantine::QUARANTINE_EVICTIONS_KEY)
                    .unwrap(),
                Some(evictions_value.as_slice()),
                "{label} must preserve the quarantine eviction counter",
            );
        };

        queue.push("2026-03", &[1]).unwrap();
        queue.clear_updates().unwrap();
        assert_eq!(queue.len().unwrap(), 0);
        assert_quarantine_intact("clear_updates");

        let seq = queue.push("2026-03", &[2]).unwrap();
        queue.clear_through(seq).unwrap();
        assert_eq!(queue.len().unwrap(), 0);
        assert_quarantine_intact("clear_through");

        queue.push("2026-03", &[3]).unwrap();
        queue.clear_all().unwrap();
        assert_eq!(queue.len().unwrap(), 0);
        assert_quarantine_intact("clear_all");
    }

    #[test]
    fn seq_ordering_preserved() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        for i in 0..10u8 {
            queue.push("2026-03", &[i]).unwrap();
        }

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 10);
        for (i, u) in updates.iter().enumerate() {
            assert_eq!(u.seq, (i + 1) as u64);
            assert_eq!(u.encoded, vec![i as u8]);
        }
    }

    #[test]
    fn multiple_handles_allocate_distinct_sequences() {
        let vault = test_vault();
        let queue_a = SyncQueue::new(vault.clone()).unwrap();
        let queue_b = SyncQueue::new(vault).unwrap();

        let first = queue_a.push("2026-03", &[1]).unwrap();
        let second = queue_b.push("2026-03", &[2]).unwrap();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        let updates = queue_a.drain_updates().unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].seq, 1);
        assert_eq!(updates[1].seq, 2);
    }

    #[test]
    fn sequence_metadata_self_heals() {
        // 2x2 table: (corruption shape) x (entry point) — every cell asserts
        // the next push assigns max_existing_seq+1, regardless of what the
        // metadata key holds or whether clear_all ran first.
        #[derive(Copy, Clone)]
        enum Corruption {
            Missing,
            Malformed,
        }
        #[derive(Copy, Clone)]
        enum Entry {
            Push,
            ClearAll,
        }

        let cases: &[(&str, Corruption, Entry, u64, u64)] = &[
            // (case_name, corruption, entry, existing_seq, expected_next_seq)
            ("missing_then_push", Corruption::Missing, Entry::Push, 7, 8),
            (
                "missing_then_clear_all",
                Corruption::Missing,
                Entry::ClearAll,
                7,
                8,
            ),
            (
                "malformed_then_push",
                Corruption::Malformed,
                Entry::Push,
                4,
                5,
            ),
            (
                "malformed_then_clear_all",
                Corruption::Malformed,
                Entry::ClearAll,
                9,
                10,
            ),
        ];

        for (case_name, corruption, entry, existing_seq, expected_next) in cases {
            let vault = test_vault();
            let queue = SyncQueue::new(vault.clone()).unwrap();

            let mut wtxn = vault.store.env.write_txn().unwrap();
            if matches!(corruption, Corruption::Malformed) {
                vault
                    .store
                    .sync_queue
                    .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &[1, 2, 3])
                    .unwrap();
            }
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &encode_update_key(*existing_seq), &[7, b'x'])
                .unwrap();
            wtxn.commit().unwrap();

            match entry {
                Entry::Push => {
                    let next = queue.push("2026-03", &[1]).unwrap();
                    assert_eq!(next, *expected_next, "case {case_name}: push seq mismatch");
                }
                Entry::ClearAll => {
                    queue.clear_all().unwrap();
                    assert_eq!(
                        queue.len().unwrap(),
                        0,
                        "case {case_name}: clear_all left rows behind"
                    );
                    let seq = queue.push("2026-03", &[1]).unwrap();
                    assert_eq!(
                        seq, *expected_next,
                        "case {case_name}: post-clear push seq mismatch"
                    );
                }
            }
        }
    }

    #[test]
    fn decode_last_update_seq_metadata_rejects_bad_len_without_panic() {
        let decoded = decode_last_update_seq_metadata(&42_u64.to_le_bytes()).unwrap();
        assert_eq!(decoded, 42);

        let short = decode_last_update_seq_metadata(&[1, 2, 3])
            .expect_err("short metadata must be rejected");
        assert_matches!(short, Error::CorruptedIndex("sync queue metadata"));

        let overlong = decode_last_update_seq_metadata(&[0_u8; 9])
            .expect_err("overlong metadata must be rejected");
        assert_matches!(overlong, Error::CorruptedIndex("sync queue metadata"));
    }

    #[test]
    fn clear_all_preserves_sequence_generation_for_stale_clear_through() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        for seq in 1..=5u8 {
            queue.push("2026-03", &[seq]).unwrap();
        }

        queue.clear_all().unwrap();

        let fresh_seq = queue.push("2026-03", &[9]).unwrap();
        assert_eq!(fresh_seq, 6);

        queue.clear_through(5).unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 6);
        assert_eq!(updates[0].encoded, vec![9]);
    }

    #[test]
    fn stale_but_parseable_metadata_repairs_upward_before_push() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        for seq in 1..=5u8 {
            queue.push("2026-03", &[seq]).unwrap();
        }

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &1_u64.to_le_bytes())
            .unwrap();
        wtxn.commit().unwrap();

        let next = queue.push("2026-03", &[9]).unwrap();
        assert_eq!(next, 6);

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 6);
        assert_eq!(updates[1].seq, 2);
        assert_eq!(updates[1].encoded, vec![2]);
        assert_eq!(updates[5].seq, 6);
        assert_eq!(updates[5].encoded, vec![9]);
    }

    #[test]
    fn push_self_heals_missing_metadata_without_update_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let seq = queue.push("2026-03", &[1]).unwrap();
        assert_eq!(seq, 1);

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .delete(&mut wtxn, LAST_UPDATE_SEQ_KEY)
            .unwrap();
        vault
            .store
            .sync_queue
            .delete(&mut wtxn, &encode_update_key(1))
            .unwrap();
        wtxn.commit().unwrap();

        let seq = queue.push("2026-03", &[2]).unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn clear_updates_self_heals_malformed_metadata_without_update_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &[1, 2, 3])
            .unwrap();
        wtxn.commit().unwrap();

        queue.clear_updates().unwrap();

        let seq = queue.push("2026-03", &[1]).unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn len_ignores_malformed_update_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let mut bad_key = UPDATE_PREFIX.to_vec();
        bad_key.push(0);
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &[1, b'x'])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(2), &[0])
            .unwrap();
        wtxn.commit().unwrap();

        assert_eq!(queue.len().unwrap(), 1);

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);
        assert_eq!(updates[0].window_key, "2026-03");
        assert_eq!(updates[0].encoded, vec![1]);
    }

    #[test]
    fn drain_updates_prunes_corrupt_rows() {
        // Three corruption shapes get pruned by drain_updates:
        //   (case_name, bad_key, bad_value)
        // - malformed_value: well-formed key, value too short to decode
        // - overlong_key: key with trailing bytes (length != 10)
        // - invalid_calendar_or_pre_epoch: well-formed key, value carries a
        //   window_key string that fails parse_window_key_str (calendar OOB
        //   or pre-epoch year). Both share the same code path.
        let well_formed_key = encode_update_key(2).to_vec();
        let mut overlong_key = Vec::from(encode_update_key(2));
        overlong_key.push(0xAA);

        let mut invalid_calendar_value = vec![7u8];
        invalid_calendar_value.extend_from_slice(b"2026-13");
        invalid_calendar_value.extend_from_slice(&[9, 9]);

        let mut pre_epoch_value = vec![7u8];
        pre_epoch_value.extend_from_slice(b"1969-12");
        pre_epoch_value.extend_from_slice(&[9, 9]);

        let cases: &[(&str, Vec<u8>, Vec<u8>)] = &[
            ("malformed_value", well_formed_key.clone(), vec![0]),
            ("overlong_key", overlong_key, vec![7, b'x']),
            (
                "invalid_calendar_window_key",
                well_formed_key.clone(),
                invalid_calendar_value,
            ),
            ("pre_epoch_window_key", well_formed_key, pre_epoch_value),
        ];

        for (case_name, bad_key, bad_value) in cases {
            let vault = test_vault();
            let queue = SyncQueue::new(vault.clone()).unwrap();

            queue.push("2026-03", &[1]).unwrap();

            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, bad_key, bad_value)
                .unwrap();
            wtxn.commit().unwrap();

            let updates = queue.drain_updates().unwrap();
            assert_eq!(updates.len(), 1, "case {case_name}: should keep valid row");
            assert_eq!(updates[0].seq, 1, "case {case_name}");

            let rtxn = vault.store.env.read_txn().unwrap();
            assert!(
                vault
                    .store
                    .sync_queue
                    .get(&rtxn, bad_key)
                    .unwrap()
                    .is_none(),
                "case {case_name}: corrupt row should be pruned",
            );
        }
    }

    #[test]
    fn clear_through_prunes_malformed_update_keys() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let bad_key = b"q:\x00".to_vec();
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &[1, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        queue.clear_through(1).unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &bad_key)
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_update_key(1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn embed_job_roundtrip() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        let id = EntityId::now();
        queue.push_embed_job(&id, 1).unwrap();

        let jobs = queue.drain_embed_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, id);
        assert_eq!(jobs[0].priority, 1);
        assert!(jobs[0].queued_at > 0);
    }

    #[test]
    fn drain_embed_jobs_prunes_corrupt_rows() {
        // Three corruption shapes get pruned by drain_embed_jobs:
        //   (case_name, bad_key, bad_value)
        // - malformed_key: zeroed entity id portion fails EntityId::from_bytes
        // - overlong_key: key has trailing byte (length != 18)
        // - overlong_value: value has trailing byte (length != 9)
        let mut zero_key = [0u8; 18];
        zero_key[..2].copy_from_slice(EMBED_PREFIX);

        let mut overlong_key = Vec::from(encode_embed_key(&EntityId::now()));
        overlong_key.push(0xAA);

        let proper_key = encode_embed_key(&EntityId::now());

        let mut valid_value = Vec::with_capacity(9);
        valid_value.push(2);
        valid_value.extend_from_slice(&123u64.to_be_bytes());

        let mut overlong_value = valid_value.clone();
        overlong_value.push(0xAA);

        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("malformed_key", zero_key.to_vec(), valid_value.clone()),
            ("overlong_key", overlong_key, valid_value),
            ("overlong_value", proper_key.to_vec(), overlong_value),
        ];

        for (case_name, bad_key, bad_value) in &cases {
            let vault = test_vault();
            let queue = SyncQueue::new(vault).unwrap();

            let valid_id = EntityId::now();
            queue.push_embed_job(&valid_id, 1).unwrap();

            let mut wtxn = queue.vault.store.env.write_txn().unwrap();
            queue
                .vault
                .store
                .sync_queue
                .put(&mut wtxn, bad_key, bad_value)
                .unwrap();
            wtxn.commit().unwrap();

            let jobs = queue.drain_embed_jobs().unwrap();
            assert_eq!(jobs.len(), 1, "case {case_name}: should keep valid job");
            assert_eq!(jobs[0].entity_id, valid_id, "case {case_name}");

            let rtxn = queue.vault.store.env.read_txn().unwrap();
            assert!(
                queue
                    .vault
                    .store
                    .sync_queue
                    .get(&rtxn, bad_key)
                    .unwrap()
                    .is_none(),
                "case {case_name}: corrupt row should be pruned",
            );
        }
    }

    #[test]
    fn prune_malformed_rows_keeps_repaired_embed_row() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        let id = EntityId::now();
        let key = encode_embed_key(&id);

        let mut wtxn = queue.vault.store.env.write_txn().unwrap();
        queue
            .vault
            .store
            .sync_queue
            .put(&mut wtxn, &key, &[1, 2, 3])
            .unwrap();
        wtxn.commit().unwrap();

        let stale_candidates = vec![key.to_vec()];

        let mut repaired = Vec::with_capacity(9);
        repaired.push(2);
        repaired.extend_from_slice(&456u64.to_be_bytes());
        let mut wtxn = queue.vault.store.env.write_txn().unwrap();
        queue
            .vault
            .store
            .sync_queue
            .put(&mut wtxn, &key, &repaired)
            .unwrap();
        wtxn.commit().unwrap();

        queue
            .prune_malformed_rows(&stale_candidates, decode_embed_job_row)
            .unwrap();

        let rtxn = queue.vault.store.env.read_txn().unwrap();
        assert!(
            queue
                .vault
                .store
                .sync_queue
                .get(&rtxn, &key)
                .unwrap()
                .is_some()
        );
        drop(rtxn);

        let jobs = queue.drain_embed_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, id);
        assert_eq!(jobs[0].priority, 2);
        assert_eq!(jobs[0].queued_at, 456);
    }

    #[test]
    fn seq_resumes_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = VaultConfig::device();

        // Open vault and push entries
        {
            let vault = Arc::new(Vault::open(dir.path(), config.clone()).unwrap());
            let queue = SyncQueue::new(vault).unwrap();
            queue.push("2026-03", &[1]).unwrap();
            queue.push("2026-03", &[2]).unwrap();
        }

        // Reopen vault and verify seq resumes
        {
            let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
            let queue = SyncQueue::new(vault).unwrap();
            let seq = queue.push("2026-03", &[3]).unwrap();
            assert_eq!(seq, 3, "sequence should resume from persisted max");

            let updates = queue.drain_updates().unwrap();
            assert_eq!(updates.len(), 3);
        }
    }

    #[test]
    fn key_encoding_roundtrip() {
        // Two key families round-trip through their encode/decode pair.
        // Update keys carry a u64 sequence (boundary values: 0, 1, 255,
        // 65535, u64::MAX). Embed keys carry an EntityId.
        for seq in [0u64, 1, 255, 65535, u64::MAX] {
            let encoded = encode_update_key(seq);
            let decoded = decode_update_key(&encoded)
                .unwrap_or_else(|e| panic!("update_key seq={seq}: decode failed: {e:?}"));
            assert_eq!(decoded, seq, "update_key seq={seq}");
        }

        let id = EntityId::now();
        let encoded = encode_embed_key(&id);
        let decoded = decode_embed_key(&encoded)
            .unwrap_or_else(|e| panic!("embed_key id={id:?}: decode failed: {e:?}"));
        assert_eq!(decoded, id, "embed_key roundtrip");
    }
}
