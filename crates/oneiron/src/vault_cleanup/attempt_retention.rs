//! Reversible retention for private queue records; the serialized attempt is never changed.
use super::marks::{self, CleanupMark};
use super::run_snapshot::CleanupSnapshotEntry;
use super::{CleanupCandidate, CleanupKind};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState, decode_record};
use crate::error::{Error, MaintenanceError, Result};
use crate::ports::JobQueueRead;
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

const TASK_ARCHIVE: SideTable<TaskAttemptKey, (), Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_TASK_ATTEMPT_ARCHIVE);

/// The BLAKE3 context that names a task reference in the index key.
const TASK_DIGEST_CONTEXT: &str = "oneiron vault_cleanup task attempt index v1";

/// Index key: the domain-separated BLAKE3 of the exact task reference, then
/// the archived attempt's raw 16 bytes (FIX 10196). The key is 48 bytes past
/// its prefix whatever the reference's length, so every task reference the
/// queue admits fits the store's key limit. The reference is hashed whole,
/// never shortened.
struct TaskAttemptKey {
    task_digest: [u8; 32],
    attempt: [u8; 16],
}

impl TaskAttemptKey {
    fn new(task: &str, attempt: [u8; 16]) -> Self {
        Self {
            task_digest: task_digest(task),
            attempt,
        }
    }
}

impl SideKey for TaskAttemptKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.task_digest);
        out.extend_from_slice(&self.attempt);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (task_digest, attempt) = bytes.split_at_checked(32)?;
        Some(Self {
            task_digest: task_digest.try_into().ok()?,
            attempt: attempt.try_into().ok()?,
        })
    }
}

/// The index's name for `task`, and the prefix of its rows: the one
/// derivation archive, forget, erase and every restore share.
fn task_digest(task: &str) -> [u8; 32] {
    blake3::derive_key(TASK_DIGEST_CONTEXT, task.as_bytes())
}

/// Whether the queue row `raw` of `id` is archived: a cleanup run's mark
/// pinned to exactly these bytes.
pub(crate) fn attempt_is_archived(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    raw: &[u8],
) -> Result<bool> {
    Ok(matches!(
        marks::mark_in_txn(store, txn, id.as_bytes())?,
        Some(CleanupMark::Archived { revision, .. }) if revision == marks::revision_of(raw)
    ))
}

/// Moves an attempt's cleanup mark to the bytes its row was rewritten to in
/// this transaction, when the mark bound the row as it stood (`before`): an
/// erase that rewrites a row in place leaves it archived by the same run
/// (FIX 7076), or kept by the owner. A stale or unreadable mark bound bytes
/// the row no longer holds, so it is removed, never rebound: no hash of
/// those bytes outlives the erase (FIX 7615). An absent mark stays absent.
pub(crate) fn refresh_archived_attempt_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    before: &[u8],
    after: &[u8],
) -> Result<()> {
    let bound = marks::revision_of(before);
    let revision = marks::revision_of(after);
    let Some(raw) = marks::raw_in_txn(store, txn, id.as_bytes())? else {
        return Ok(());
    };
    match CleanupMark::decode(&raw).and_then(|mark| mark.moved(&bound, &revision)) {
        Some(moved) => marks::put_in_txn(store, txn, id.as_bytes(), moved),
        None => marks::delete_in_txn(store, txn, id.as_bytes()),
    }
}

/// [`refresh_archived_attempt_in_txn`] over a checkpoint image's sorted
/// `vault_meta` rows (FIX 7115): `id`'s mark moves to `revision` (the BLAKE3
/// of the bytes its row lands as) when it binds `bound`, the revision of the
/// bytes its row was carried as, so a restore that lands the row rewritten
/// (unleased, or its erased text-free form) leaves it archived or kept as it
/// was. An absent, unreadable or stale mark stays as it is; none is made.
pub(crate) fn refresh_archived_attempt_in_rows(
    vault_meta: &mut [(Vec<u8>, Vec<u8>)],
    id: AttemptId,
    bound: &[u8; 32],
    revision: &[u8; 32],
) {
    let key = marks::mark_key(id.as_bytes());
    let Ok(at) = vault_meta.binary_search_by(|(row, _)| row.as_slice().cmp(&key)) else {
        return;
    };
    if let Some(moved) =
        CleanupMark::decode(&vault_meta[at].1).and_then(|mark| mark.moved(bound, revision))
    {
        vault_meta[at].1 = moved.encode();
    }
}

/// Drops the archive markers of an attempt row that left the ledger, so no
/// marker outlives the row it archived.
pub(crate) fn forget_archived_attempt_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    marks::delete_in_txn(store, txn, record.id.as_bytes())?;
    if let Some(task) = &record.task_ref {
        TASK_ARCHIVE.delete(
            store,
            txn,
            &TaskAttemptKey::new(task, *record.id.as_bytes()),
        )?;
    }
    Ok(())
}

/// The record of attempt `id`'s queue row `raw` when the retention arm would
/// archive it now; none when retention is off, the owner kept or a run
/// archived these bytes, the row is job state, or it is not old enough.
pub(super) fn eligible(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    raw: &[u8],
) -> Result<Option<AttemptRecord>> {
    let days = super::retention::retention_days_in_txn(vault, txn)?;
    if days == 0 {
        return Ok(None);
    }
    // Archived at these bytes, or kept at them by the owner: either way the
    // arm leaves them alone until the row changes.
    if matches!(
        marks::mark_in_txn(&vault.store, txn, id.as_bytes())?,
        Some(
            CleanupMark::Archived { revision: bound, .. } | CleanupMark::Kept { revision: bound }
        ) if bound == marks::revision_of(raw)
    ) {
        return Ok(None);
    }
    let record = decode_record(raw, id)?;
    // A job row whose owner prunes and bounds it is job state: cleanup never
    // proposes it, so it never mints a proposal id.
    if crate::attempt_queue::owner_retained_kind(&record.kind) {
        return Ok(None);
    }
    Ok((record.state == AttemptState::Completed
        && vault.now_recorded_at().saturating_sub(record.updated_at) > days.saturating_mul(86_400))
    .then_some(record))
}

/// Every completed queue record retention would archive, the ledger read
/// from its start.
pub(super) fn scan(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidates: &mut Vec<CleanupCandidate>,
) -> Result<()> {
    // Owner-retained rows are job state at the top of the ledger's key
    // order: the arm stops before them, the ledger's other rows all read.
    for row in JobQueueRead::port_job_rows(&vault.store, txn, None)? {
        let (attempt, raw) = row?;
        if crate::attempt_queue::owner_retained_id(&attempt) {
            break;
        }
        let entity = EntityId::from_bytes(*attempt.as_bytes())?;
        if eligible(vault, txn, attempt, &raw)?.is_some() {
            candidates.push(CleanupCandidate {
                entity,
                kind: CleanupKind::CompletedAttempt,
            });
        }
    }
    Ok(())
}

/// Archives one completed attempt for cleanup run `run` and answers its
/// snapshot entry, read before the mark is written. None when the attempt is
/// gone or no longer eligible; nothing is written then.
pub(super) fn archive(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: EntityId,
    run: AttemptId,
) -> Result<Option<CleanupSnapshotEntry>> {
    let id = AttemptId::from_bytes(entity.as_bytes())?;
    let Some(raw) = JobQueueRead::port_job_row(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let Some(record) = eligible(vault, txn, id, &raw)? else {
        return Ok(None);
    };
    let revision = marks::revision_of(&raw);
    let before = marks::raw_in_txn(&vault.store, txn, id.as_bytes())?;
    let after = CleanupMark::Archived { revision, run };
    marks::put_in_txn(&vault.store, txn, id.as_bytes(), after)?;
    if let Some(task) = record.task_ref {
        TASK_ARCHIVE.put(
            &vault.store,
            txn,
            &TaskAttemptKey::new(&task, *id.as_bytes()),
            &(),
        )?;
    }
    Ok(Some(CleanupSnapshotEntry {
        entity,
        kind: CleanupKind::CompletedAttempt,
        revision: Some(revision),
        before,
        after: Some(after.encode()),
    }))
}

/// Keeps attempt `id` at its current queue row: the owner brought it back,
/// so retention does not archive those bytes again. A row that is gone is
/// left unmarked.
pub(super) fn keep_attempt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<()> {
    if let Some(raw) = JobQueueRead::port_job_row(&vault.store, txn, &id)? {
        let revision = marks::revision_of(&raw);
        marks::put_in_txn(
            &vault.store,
            txn,
            id.as_bytes(),
            CleanupMark::Kept { revision },
        )?;
    }
    Ok(())
}

/// Drops every archived-attempt index row of an erased `task` (FIX 7517):
/// the index is private and keyed by the task's id, so its rows go by that
/// key. The attempts' own marks stay as they are, archived or kept: this
/// restores nothing.
pub(super) fn erase_task_index_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task: &EntityId,
) -> Result<()> {
    TASK_ARCHIVE.delete_from(store, txn, &task_digest(&task.to_hex()))?;
    Ok(())
}

/// What a TASK restore does with the attempts archived under the task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttemptRestore {
    /// A re-mention or a returning file: each attempt's mark goes, and none
    /// is kept.
    Ordinary,
    /// The owner brought the TASK back: each attempt is kept at its current
    /// queue row, so retention does not archive those bytes again (FIX 7518).
    OwnerKeeps,
}

/// Restores every attempt archived under `task`, as a re-mention does: each
/// attempt's mark goes and none is kept.
pub(crate) fn restore_task_attempts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    restore_task_attempts_as(vault, txn, task, AttemptRestore::Ordinary)
}

/// [`restore_task_attempts`] under `intent`. The task's index rows go in the
/// same write either way.
pub(super) fn restore_task_attempts_as(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    intent: AttemptRestore,
) -> Result<()> {
    let prefix = task_digest(&task.to_hex());
    let attempts: Vec<[u8; 16]> = TASK_ARCHIVE
        .scan_keys(&vault.store, txn, &prefix)?
        .into_iter()
        .map(|key| key.attempt)
        .collect();
    for attempt in &attempts {
        marks::delete_in_txn(&vault.store, txn, attempt)?;
        if intent == AttemptRestore::OwnerKeeps {
            keep_attempt_in_txn(vault, txn, AttemptId::from_bytes(attempt)?)?;
        }
    }
    TASK_ARCHIVE.delete_from(&vault.store, txn, &prefix)?;
    Ok(())
}

impl Vault {
    /// Every completed queue record cleanup archived that is still archived,
    /// in id order. The queue listing leaves them out; this is how the owner
    /// finds them to restore.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn archived_attempts(&self) -> Result<Vec<AttemptId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for (id, mark) in marks::scan_in_txn(&self.store, &rtxn)? {
            // A kept mark archives nothing, and a kept record's id is no
            // attempt.
            if !matches!(
                CleanupMark::decode(&mark),
                Some(CleanupMark::Archived { .. })
            ) {
                continue;
            }
            let attempt = AttemptId::from_bytes(&id)?;
            if let Some(raw) = JobQueueRead::port_job_row(&self.store, &rtxn, &attempt)?
                && attempt_is_archived(&self.store, &rtxn, attempt, &raw)?
            {
                out.push(attempt);
            }
        }
        Ok(out)
    }

    /// Whether `id` is a completed queue record cleanup archived.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn archived_attempt(&self, id: AttemptId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = JobQueueRead::port_job_row(&self.store, &rtxn, &id)? else {
            return Ok(false);
        };
        attempt_is_archived(&self.store, &rtxn, id, &raw)
    }

    /// Restores a completed queue record without changing its state or payload.
    /// Direct `AttemptQueue::get` always reads it, even while archived.
    pub fn restore_archived_attempt(&self, id: AttemptId) -> Result<()> {
        self.with_write_txn_grouped(|txn| restore_archived_attempt_in_txn(self, txn, id))
    }
}

pub(super) fn restore_archived_attempt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<()> {
    let not_archived = || {
        Error::Maintenance(MaintenanceError::VaultCleanupRestoreNotArchived {
            entity: crate::entity_id::bytes_to_hex_lower(id.as_bytes()),
        })
    };
    let raw = JobQueueRead::port_job_row(&vault.store, txn, &id)?.ok_or_else(not_archived)?;
    if !attempt_is_archived(&vault.store, txn, id, &raw)? {
        return Err(not_archived());
    }
    let record = decode_record(&raw, id)?;
    marks::delete_in_txn(&vault.store, txn, id.as_bytes())?;
    if let Some(task) = record.task_ref {
        TASK_ARCHIVE.delete(
            &vault.store,
            txn,
            &TaskAttemptKey::new(&task, *id.as_bytes()),
        )?;
    }
    Ok(())
}
