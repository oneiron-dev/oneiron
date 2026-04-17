//! Persistent offline queue backed by LMDB.
//!
//! Stores pending sync updates and embed jobs in the `sync_queue` database (#21).
//! Updates are keyed by monotonic sequence number for ordered replay.
//!
//! Key format (per ARCH-023b §5.4):
//! - `q:{seq:8BE}` → `[window_key_len:1][window_key][encoded_update]`
//! - `e:{entity_id:16}` → `[priority:1][queued_at:8BE]`

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::sync::transport::MAX_WINDOW_KEY_LEN;
use crate::sync::types::parse_window_key_str;
use crate::types::EntityId;
use crate::Vault;

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
/// Thread-safe: LMDB metadata coordinates monotonic update sequence numbers
/// across handles, and LMDB itself serializes writers.
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
        let queued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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

        self.prune_malformed_update_rows(&malformed_keys)?;

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
                Err(_) => {
                    malformed_keys.push(key.to_vec());
                    continue;
                }
            };
            jobs.push(job);
        }
        drop(rtxn);

        self.prune_malformed_embed_rows(&malformed_keys)?;

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

        self.prune_malformed_update_rows(&malformed_keys)?;

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

    /// Clears all entries (updates + embed jobs). Used for re-bootstrap.
    pub fn clear_all(&self) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let preserved_seq = self.recover_last_update_seq_for_clear(&wtxn)?;
        self.vault.store.sync_queue.clear(&mut wtxn)?;
        self.vault.store.sync_queue.put(
            &mut wtxn,
            LAST_UPDATE_SEQ_KEY,
            &preserved_seq.to_le_bytes(),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Returns the number of update entries in the queue.
    pub fn len(&self) -> Result<usize> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut count = 0;
        let iter = self.vault.store.sync_queue.iter(&rtxn)?;
        for result in iter {
            let (key, _) = result?;
            if key.starts_with(UPDATE_PREFIX) {
                count += 1;
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
            if let Ok(seq) = decode_update_key(key) {
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

    fn prune_malformed_embed_rows(&self, malformed_keys: &[Vec<u8>]) -> Result<()> {
        if malformed_keys.is_empty() {
            return Ok(());
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        for key in malformed_keys {
            let Some(value) = self.vault.store.sync_queue.get(&wtxn, key)? else {
                continue;
            };
            if decode_embed_job_row(key, value).is_err() {
                self.vault.store.sync_queue.delete(&mut wtxn, key)?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    fn prune_malformed_update_rows(&self, malformed_keys: &[Vec<u8>]) -> Result<()> {
        if malformed_keys.is_empty() {
            return Ok(());
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        for key in malformed_keys {
            let Some(value) = self.vault.store.sync_queue.get(&wtxn, key)? else {
                continue;
            };
            if decode_update_row(key, value).is_err() {
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
        .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW))?
        .to_string();
    if parse_window_key_str(&window_key).is_none() {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    let encoded = value[1 + key_len..].to_vec();
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
    Ok(u64::from_le_bytes(raw.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn missing_sequence_metadata_with_existing_rows_repairs_upward() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(7), &[7, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        let next = queue.push("2026-03", &[1]).unwrap();
        assert_eq!(next, 8);
    }

    #[test]
    fn clear_all_recovers_missing_metadata_with_existing_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(7), &[7, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        queue.clear_all().unwrap();

        assert_eq!(queue.len().unwrap(), 0);
        let seq = queue.push("2026-03", &[1]).unwrap();
        assert_eq!(seq, 8);
    }

    #[test]
    fn malformed_sequence_metadata_repairs_upward() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &[1, 2, 3])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(4), &[7, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        let next = queue.push("2026-03", &[1]).unwrap();
        assert_eq!(next, 5);
    }

    #[test]
    fn clear_all_recovers_malformed_metadata() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &[1, 2, 3])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(9), &[7, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        queue.clear_all().unwrap();

        assert_eq!(queue.len().unwrap(), 0);
        let seq = queue.push("2026-03", &[1]).unwrap();
        assert_eq!(seq, 10);
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
    fn drain_updates_prunes_malformed_update_rows() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let mut bad_key = [0u8; 10];
        bad_key[..2].copy_from_slice(UPDATE_PREFIX);
        bad_key[2..].copy_from_slice(&2_u64.to_be_bytes());

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &[0])
            .unwrap();
        wtxn.commit().unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn drain_updates_prunes_overlong_update_keys() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let mut bad_key = Vec::from(encode_update_key(2));
        bad_key.push(0xAA);

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &[7, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn drain_updates_prunes_invalid_calendar_window_keys() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let mut bad_value = Vec::new();
        bad_value.push(7);
        bad_value.extend_from_slice(b"2026-13");
        bad_value.extend_from_slice(&[9, 9]);

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(2), &bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(2))
            .unwrap()
            .is_none());
    }

    #[test]
    fn drain_updates_prunes_pre_epoch_window_keys() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let mut bad_value = Vec::new();
        bad_value.push(7);
        bad_value.extend_from_slice(b"1969-12");
        bad_value.extend_from_slice(&[9, 9]);

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(2), &bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].seq, 1);

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(2))
            .unwrap()
            .is_none());
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
        assert!(vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none());
        assert!(vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(1))
            .unwrap()
            .is_none());
    }

    #[test]
    fn is_full_at_max_capacity() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        // We don't actually insert 10,000 entries (slow), but we can test
        // that an empty queue is not full.
        assert!(!queue.is_full().unwrap());
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
    fn drain_embed_jobs_prunes_malformed_keys() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        let valid_id = EntityId::now();
        queue.push_embed_job(&valid_id, 1).unwrap();

        let mut bad_key = [0u8; 18];
        bad_key[..2].copy_from_slice(EMBED_PREFIX);
        let mut bad_value = Vec::with_capacity(9);
        bad_value.push(2);
        bad_value.extend_from_slice(&123u64.to_be_bytes());

        let mut wtxn = queue.vault.store.env.write_txn().unwrap();
        queue
            .vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let jobs = queue.drain_embed_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, valid_id);

        let rtxn = queue.vault.store.env.read_txn().unwrap();
        assert!(queue
            .vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn drain_embed_jobs_prunes_overlong_keys() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let valid_id = EntityId::now();
        queue.push_embed_job(&valid_id, 1).unwrap();

        let mut bad_key = Vec::from(encode_embed_key(&EntityId::now()));
        bad_key.push(0xAA);
        let mut bad_value = Vec::with_capacity(9);
        bad_value.push(2);
        bad_value.extend_from_slice(&123u64.to_be_bytes());

        let mut wtxn = queue.vault.store.env.write_txn().unwrap();
        queue
            .vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let jobs = queue.drain_embed_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, valid_id);

        let rtxn = queue.vault.store.env.read_txn().unwrap();
        assert!(queue
            .vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn drain_embed_jobs_prunes_overlong_values() {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        let valid_id = EntityId::now();
        queue.push_embed_job(&valid_id, 1).unwrap();

        let bad_key = encode_embed_key(&EntityId::now());
        let mut bad_value = Vec::with_capacity(10);
        bad_value.push(2);
        bad_value.extend_from_slice(&123u64.to_be_bytes());
        bad_value.push(0xAA);

        let mut wtxn = queue.vault.store.env.write_txn().unwrap();
        queue
            .vault
            .store
            .sync_queue
            .put(&mut wtxn, &bad_key, &bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let jobs = queue.drain_embed_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, valid_id);

        let rtxn = queue.vault.store.env.read_txn().unwrap();
        assert!(queue
            .vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn prune_malformed_embed_rows_keeps_repaired_row() {
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

        queue.prune_malformed_embed_rows(&stale_candidates).unwrap();

        let rtxn = queue.vault.store.env.read_txn().unwrap();
        assert!(queue
            .vault
            .store
            .sync_queue
            .get(&rtxn, &key)
            .unwrap()
            .is_some());
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
    fn update_key_encoding_roundtrip() {
        for seq in [0, 1, 255, 65535, u64::MAX] {
            let encoded = encode_update_key(seq);
            let decoded = decode_update_key(&encoded).unwrap();
            assert_eq!(decoded, seq);
        }
    }

    #[test]
    fn embed_key_encoding_roundtrip() {
        let id = EntityId::now();
        let encoded = encode_embed_key(&id);
        let decoded = decode_embed_key(&encoded).unwrap();
        assert_eq!(decoded, id);
    }
}
