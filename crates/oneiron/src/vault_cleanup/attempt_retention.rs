//! Reversible retention for private queue records; the serialized attempt is never changed.
use super::{CleanupCandidate, CleanupKind};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState, decode_record};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};
use std::ops::Bound;

const PREFIX: &[u8] = b"vault_cleanup.attempt_archive.v1/";
const TASK_PREFIX: &[u8] = b"vault_cleanup.task_attempt_archive.v1/";
const CURSOR: &[u8] = b"vault_cleanup.scan.v1:attempt";
fn key(id: AttemptId) -> Vec<u8> {
    [PREFIX, id.as_bytes()].concat()
}
fn task_prefix(task: &str) -> Vec<u8> {
    [TASK_PREFIX, task.as_bytes(), b"/"].concat()
}

pub(crate) fn attempt_is_archived(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    raw: &[u8],
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(txn, &key(id))?
        .is_some_and(|marker| marker.as_ref() == blake3::hash(raw).as_bytes()))
}

fn eligible(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    raw: &[u8],
) -> Result<Option<AttemptRecord>> {
    let days = super::retention::retention_days_in_txn(vault, txn)?;
    if days == 0 || attempt_is_archived(&vault.store, txn, id, raw)? {
        return Ok(None);
    }
    let record = decode_record(raw, id)?;
    Ok((record.state == AttemptState::Completed
        && crate::unix_seconds_now().saturating_sub(record.updated_at)
            > days.saturating_mul(86_400))
    .then_some(record))
}

pub(super) fn scan(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    limit: usize,
    candidates: &mut Vec<CleanupCandidate>,
) -> Result<(Vec<u8>, Option<EntityId>)> {
    let after = vault.store.vault_meta.get(txn, CURSOR)?;
    let lower = after
        .as_ref()
        .map_or(Bound::Unbounded, |bytes| Bound::Excluded(bytes.as_ref()));
    let upper: Bound<&[u8]> = Bound::Unbounded;
    let mut last = None;
    let mut exhausted = true;
    for (examined, row) in vault
        .store
        .attempt_records
        .range(txn, &(lower, upper))?
        .enumerate()
    {
        let (bytes, raw) = row?;
        if examined == limit {
            exhausted = false;
            break;
        }
        let attempt = AttemptId::from_bytes(&bytes)?;
        let entity = EntityId::from_bytes(*attempt.as_bytes())?;
        last = Some(entity);
        if eligible(vault, txn, attempt, &raw)?.is_some() {
            candidates.push(CleanupCandidate {
                entity,
                kind: CleanupKind::CompletedAttempt,
            });
        }
    }
    Ok((CURSOR.to_vec(), if exhausted { None } else { last }))
}

pub(super) fn archive(vault: &Vault, txn: &mut heed::RwTxn<'_>, entity: EntityId) -> Result<bool> {
    let id = AttemptId::from_bytes(entity.as_bytes())?;
    let Some(raw) = vault.store.attempt_records.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(record) = eligible(vault, txn, id, &raw)? else {
        return Ok(false);
    };
    vault
        .store
        .vault_meta
        .put(txn, &key(id), blake3::hash(&raw).as_bytes())?;
    if let Some(task) = record.task_ref {
        vault.store.vault_meta.put(
            txn,
            &[task_prefix(&task).as_slice(), id.as_bytes()].concat(),
            b"",
        )?;
    }
    Ok(true)
}

pub(crate) fn restore_task_attempts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    let prefix = task_prefix(&task.to_hex());
    let keys = vault
        .store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for index_key in keys {
        let id = AttemptId::from_bytes(&index_key[prefix.len()..])?;
        vault.store.vault_meta.delete(txn, &key(id))?;
        vault.store.vault_meta.delete(txn, &index_key)?;
    }
    Ok(())
}

impl Vault {
    /// Restores a completed queue record without changing its state or payload.
    /// Direct `AttemptQueue::get` always reads it, even while archived.
    pub fn restore_archived_attempt(&self, id: AttemptId) -> Result<()> {
        self.with_write_txn(|txn| {
            let raw = self
                .store
                .attempt_records
                .get(txn, id.as_bytes())?
                .ok_or(Error::InvalidConfig("unknown attempt".into()))?;
            if !attempt_is_archived(&self.store, txn, id, &raw)? {
                return Err(Error::InvalidConfig("attempt is not archived".into()));
            }
            let record = decode_record(&raw, id)?;
            self.store.vault_meta.delete(txn, &key(id))?;
            if let Some(task) = record.task_ref {
                self.store.vault_meta.delete(
                    txn,
                    &[task_prefix(&task).as_slice(), id.as_bytes()].concat(),
                )?;
            }
            Ok(())
        })
    }
}
