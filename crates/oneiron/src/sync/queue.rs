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

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::sync::transport::MAX_WINDOW_KEY_LEN;
use crate::sync::types::parse_window_key_str;
use crate::types::EntityId;

/// Maximum number of queue entries before triggering re-bootstrap.
const MAX_QUEUE_SIZE: usize = 10_000;

/// Prefix for update queue entries.
const UPDATE_PREFIX: &[u8] = b"q:";
/// Prefix for embed job entries.
const EMBED_PREFIX: &[u8] = b"e:";
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
    /// Priority (1 = from server, 2 = from device).
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

    /// Pushes an embed job for background processing.
    pub fn push_embed_job(&self, entity_id: &EntityId, priority: u8) -> Result<()> {
        let key = encode_embed_key(entity_id);
        // Saturate to 0 if the wall clock is pre-epoch (NTP regression,
        // suspended VM, embedded device with reset RTC). Panicking here would
        // break enqueue on perfectly recoverable system state.
        let queued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut value = Vec::with_capacity(9);
        value.push(priority);
        value.extend_from_slice(&queued_at.to_be_bytes());

        let mut wtxn = self.vault.store.env.write_txn()?;
        self.vault.store.sync_queue.put(&mut wtxn, &key, &value)?;
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

        Ok(jobs)
    }

    /// Clears all update entries with sequence number <= `max_seq`.
    ///
    /// Called after convergence confirms the server has received all updates.
    pub fn clear_through(&self, max_seq: u64) -> Result<()> {
        let rtxn = self.vault.store.env.read_txn()?;
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
                keys_to_delete.push(key.to_vec());
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

    /// Clears only update entries (`q:` prefix), preserving embed jobs (`e:` prefix).
    ///
    /// Use this after convergence or when clearing stale updates without
    /// disrupting pending embed work.
    pub fn clear_updates(&self) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let _ = self.ensure_last_update_seq_metadata(&mut wtxn)?;
        let mut keys_to_delete = Vec::new();
        let iter = self.vault.store.sync_queue.iter(&wtxn)?;
        for result in iter {
            let (key, _) = result?;
            if key.starts_with(UPDATE_PREFIX) {
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
    /// Hard-delete sweep jobs (`h:`) and metadata counters (`m:`) are
    /// intentionally preserved. Reconnect overflow is about the offline
    /// update queue only; wiping sweep jobs after a GDPR delete receipt has
    /// committed would strand historical carriers past the Art.17 SLA.
    pub fn clear_all(&self) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let preserved_seq = self.recover_last_update_seq_for_clear(&wtxn)?;
        let mut keys_to_delete = self.keys_with_prefix(&wtxn, UPDATE_PREFIX)?;
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

    /// Returns the number of valid update entries in the queue.
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
    pub fn is_full(&self) -> Result<bool> {
        Ok(self.len()? >= MAX_QUEUE_SIZE)
    }

    fn allocate_next_update_seq(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        let current = self.ensure_last_update_seq_metadata(wtxn)?;
        let next = current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("sync queue sequence"))?;
        if self
            .vault
            .store
            .sync_queue
            .get(&*wtxn, &encode_update_key(next))?
            .is_some()
        {
            return Err(Error::CorruptedIndex("sync queue metadata"));
        }
        self.vault
            .store
            .sync_queue
            .put(wtxn, LAST_UPDATE_SEQ_KEY, &next.to_le_bytes())?;
        Ok(next)
    }

    /// Ensures queue sequence metadata exists and matches the persisted queue.
    fn ensure_last_update_seq_metadata(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        let metadata = match self
            .vault
            .store
            .sync_queue
            .get(&*wtxn, LAST_UPDATE_SEQ_KEY)?
        {
            Some(raw) => decode_last_update_seq_metadata(raw).ok(),
            None => None,
        };
        let max_valid_seq = self.max_valid_update_seq(wtxn)?;
        let repaired = match metadata {
            Some(seq) if seq >= max_valid_seq => seq,
            _ => max_valid_seq,
        };
        self.vault
            .store
            .sync_queue
            .put(wtxn, LAST_UPDATE_SEQ_KEY, &repaired.to_le_bytes())?;
        Ok(repaired)
    }

    fn max_valid_update_seq(&self, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
        let mut max_valid_seq = 0_u64;
        let iter = self
            .vault
            .store
            .sync_queue
            .prefix_iter(wtxn, UPDATE_PREFIX)?;
        for result in iter {
            let (key, _) = result?;
            let decoded_seq = decode_update_key(key);
            if let Ok(seq) = decoded_seq {
                max_valid_seq = max_valid_seq.max(seq);
            }
        }
        Ok(max_valid_seq)
    }

    fn recover_last_update_seq_for_clear(&self, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
        let metadata_seq = self
            .vault
            .store
            .sync_queue
            .get(wtxn, LAST_UPDATE_SEQ_KEY)?
            .and_then(|raw| decode_last_update_seq_metadata(raw).ok());
        let max_valid_seq = self.max_valid_update_seq(wtxn)?;
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
            }
        }
        wtxn.commit()?;
        Ok(())
    }
}

// ─── Key Encoding ────────────────────────────────────────────────────────────

/// Encodes an update queue key: `q:{seq:8BE}` (10 bytes).
fn encode_update_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(UPDATE_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Decodes the sequence number from an update queue key.
fn decode_update_key(key: &[u8]) -> Result<u64> {
    if key.len() != 10 || !key.starts_with(UPDATE_PREFIX) {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    Ok(u64::from_be_bytes(key[2..10].try_into().map_err(|_| {
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
    if value.is_empty() {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    let key_len = value[0] as usize;
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    if value.len() < 1 + key_len {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    let window_key = std::str::from_utf8(&value[1..1 + key_len])
        .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW))?;
    if parse_window_key_str(window_key).is_none() {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    Ok((window_key, &value[1 + key_len..]))
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
    if key.len() != 18 || !key.starts_with(EMBED_PREFIX) {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&key[2..18]);
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))
}

fn decode_embed_job_row(key: &[u8], value: &[u8]) -> Result<QueuedEmbedJob> {
    let entity_id = decode_embed_key(key)?;
    if value.len() != 9 {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW));
    }
    let priority = value[0];
    let queued_at = u64::from_be_bytes(
        value[1..9]
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?,
    );
    Ok(QueuedEmbedJob {
        entity_id,
        priority,
        queued_at,
    })
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
        LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionScope, encode_hard_erase_sweep_job,
        encode_hard_erase_sweep_key,
    };
    use crate::types::VaultConfig;

    fn test_vault() -> Arc<Vault> {
        let dir = tempfile::tempdir().unwrap();
        let config = VaultConfig::device();
        Arc::new(Vault::open(dir.path(), config).unwrap())
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
        assert!(matches!(err, Error::InvalidKey));

        let overlong = "x".repeat(MAX_WINDOW_KEY_LEN + 1);
        let err = queue
            .push(&overlong, &[2])
            .expect_err("overlong window key must fail");
        assert!(matches!(err, Error::InvalidKey));

        for invalid in [
            "2026-13", "2026-00", "abcdefg", "2026-3", "1969-12", "0000-01",
        ] {
            let err = queue
                .push(invalid, &[9])
                .expect_err("invalid calendar window key must fail");
            assert!(matches!(err, Error::InvalidKey));
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
        let sweep_value =
            encode_hard_erase_sweep_job(RedactionScope::entity(&EntityId::now()), 1_772_000_000)
                .unwrap();
        let embed_key = encode_embed_key(&embed_id);

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
        wtxn.commit().unwrap();

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
        assert!(matches!(
            short,
            Error::CorruptedIndex("sync queue metadata")
        ));

        let overlong = decode_last_update_seq_metadata(&[0_u8; 9])
            .expect_err("overlong metadata must be rejected");
        assert!(matches!(
            overlong,
            Error::CorruptedIndex("sync queue metadata")
        ));
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
