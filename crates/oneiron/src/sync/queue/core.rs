//! SyncQueue impl: push/drain/clear/prune.

use super::codec::{
    decode_embed_job_row, decode_last_update_seq_metadata, decode_update_key, decode_update_row,
    encode_delete_bearing_key, encode_update_key, encode_update_value, validate_update_row,
};
use super::seq::{
    allocate_next_update_seq_in_txn, delete_bearing_seqs_in_txn,
    ensure_last_update_seq_metadata_in_txn, max_valid_update_seq_in_txn, push_embed_job_in_txn,
};
use super::{
    EMBED_PREFIX, LAST_UPDATE_SEQ_KEY, MAX_QUEUE_SIZE, QueuedEmbedJob, QueuedUpdate, SyncQueue,
    UPDATE_PREFIX,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use std::sync::Arc;

#[cfg(test)]
use super::seq::push_delete_bearing_in_txn;
#[cfg(test)]
use crate::sync::window::DeleteBearingUpdate;

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
    pub(super) fn push_delete_bearing(&self, window_key: &str, update_bytes: &[u8]) -> Result<u64> {
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
            let update = match decode_update_row(&key, &value) {
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
            let job = match decode_embed_job_row(&key, &value) {
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
            .and_then(|raw| decode_last_update_seq_metadata(&raw).ok());
        let mut remaining_max_seq = 0_u64;
        let iter = self.vault.store.sync_queue.iter(&rtxn)?;
        for result in iter {
            let (key, _) = result?;
            if !key.starts_with(UPDATE_PREFIX) {
                continue;
            }
            let seq = match decode_update_key(&key) {
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
                && !decode_update_key(&key).is_ok_and(|seq| delete_bearing.contains(&seq))
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
            match validate_update_row(&key, &value) {
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
            match validate_update_row(&key, &value) {
                Ok(())
                    if !decode_update_key(&key).is_ok_and(|seq| delete_bearing.contains(&seq)) =>
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
            .and_then(|raw| decode_last_update_seq_metadata(&raw).ok());
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
    pub(super) fn prune_malformed_rows<T>(
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
            if decode(key, &value).is_err() {
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
