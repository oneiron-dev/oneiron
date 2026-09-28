//! Reversible retention for private queue records; the serialized attempt is never changed.
use super::scan::ScanCursorTag;
use super::{CleanupCandidate, CleanupKind};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState, decode_record};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use std::ops::Bound;

const ARCHIVE: SideTable<[u8; 16], [u8; 32], Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_ATTEMPT_ARCHIVE);
const TASK_ARCHIVE: SideTable<TaskAttemptKey, (), Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_TASK_ATTEMPT_ARCHIVE);

/// Index key: an owner-facing task reference string, `/`, then the archived
/// attempt's raw 16 bytes. The attempt is always the trailing 16 bytes, so a
/// task reference containing `/` still decodes correctly.
struct TaskAttemptKey {
    task: String,
    attempt: [u8; 16],
}

impl SideKey for TaskAttemptKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.task.as_bytes());
        out.push(b'/');
        out.extend_from_slice(&self.attempt);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let split = bytes.len().checked_sub(16)?;
        let (head, attempt) = bytes.split_at(split);
        let task = head.strip_suffix(b"/")?;
        Some(Self {
            task: String::from_utf8(task.to_vec()).ok()?,
            attempt: attempt.try_into().ok()?,
        })
    }
}

pub(crate) fn attempt_is_archived(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    raw: &[u8],
) -> Result<bool> {
    Ok(ARCHIVE
        .get(store, txn, id.as_bytes())?
        .is_some_and(|marker| marker == *blake3::hash(raw).as_bytes()))
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
        && vault.now_recorded_at().saturating_sub(record.updated_at) > days.saturating_mul(86_400))
    .then_some(record))
}

pub(super) fn scan(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    limit: usize,
    candidates: &mut Vec<CleanupCandidate>,
) -> Result<(ScanCursorTag, Option<EntityId>)> {
    let after = super::scan::SCAN_CURSOR.get(&vault.store, txn, &ScanCursorTag::Attempt)?;
    let after_bytes = after.map(|id| *id.as_bytes());
    let lower = after_bytes
        .as_ref()
        .map_or(Bound::Unbounded, |bytes| Bound::Excluded(bytes.as_slice()));
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
    Ok((ScanCursorTag::Attempt, if exhausted { None } else { last }))
}

pub(super) fn archive(vault: &Vault, txn: &mut heed::RwTxn<'_>, entity: EntityId) -> Result<bool> {
    let id = AttemptId::from_bytes(entity.as_bytes())?;
    let Some(raw) = vault.store.attempt_records.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(record) = eligible(vault, txn, id, &raw)? else {
        return Ok(false);
    };
    ARCHIVE.put(
        &vault.store,
        txn,
        id.as_bytes(),
        blake3::hash(&raw).as_bytes(),
    )?;
    if let Some(task) = record.task_ref {
        TASK_ARCHIVE.put(
            &vault.store,
            txn,
            &TaskAttemptKey {
                task,
                attempt: *id.as_bytes(),
            },
            &(),
        )?;
    }
    Ok(true)
}

fn task_prefix_bytes(task: &str) -> Vec<u8> {
    [task.as_bytes(), b"/"].concat()
}

pub(crate) fn restore_task_attempts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    let prefix = task_prefix_bytes(&task.to_hex());
    let attempts: Vec<[u8; 16]> = TASK_ARCHIVE
        .scan_keys(&vault.store, txn, &prefix)?
        .into_iter()
        .map(|key| key.attempt)
        .collect();
    for attempt in &attempts {
        ARCHIVE.delete(&vault.store, txn, attempt)?;
    }
    TASK_ARCHIVE.delete_from(&vault.store, txn, &prefix)?;
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
            ARCHIVE.delete(&self.store, txn, id.as_bytes())?;
            if let Some(task) = record.task_ref {
                TASK_ARCHIVE.delete(
                    &self.store,
                    txn,
                    &TaskAttemptKey {
                        task,
                        attempt: *id.as_bytes(),
                    },
                )?;
            }
            Ok(())
        })
    }
}
