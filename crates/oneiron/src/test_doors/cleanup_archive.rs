//! Door for `tests/check_in_delete_effects.rs` (ROLES-CHECKIN 2k5c): the
//! cleanup-archive marker the vault cleanup writes when it archives a
//! record, put on any record, so a test may delete archived NOTEs through
//! `vault.archive.delete.confirm` without aging them past retention. The
//! record's body and indexes stay, as the cleanup's archive keeps them.
//! Row 2k5e: the cleanup mark a run puts on a completed attempt, for
//! `vault.archive.attempt.delete.confirm`.

use crate::attempt_queue::AttemptId;
use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Archives `record` as the vault cleanup does, in one write at the store
/// clock: its cleanup-archive marker, under a fresh request id.
///
/// # Errors
/// A store failure.
pub fn archive_as_cleanup(vault: &Vault, record: &EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        let deleted_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        vault.put_archive_tombstone_in_txn(
            txn,
            record,
            &TombstoneValueV2 {
                reason: TombstoneReason::ArchivedByCleanup,
                deleted_at,
                request_id: *EntityId::now().as_bytes(),
            },
        )
    })
}

/// Archives completed attempt `attempt` as a cleanup run does, in one
/// write: its cleanup mark binds the queue row's bytes as they stand, under
/// a fresh run id. The row stays.
///
/// # Errors
/// `EntityNotFound` for an attempt with no queue row; a store failure.
pub fn archive_attempt_as_cleanup(vault: &Vault, attempt: AttemptId) -> Result<()> {
    use crate::store::attempt_archive_mark::{CleanupMark, put_in_txn, revision_of};
    vault.with_write_txn(|txn| {
        let raw = crate::ports::JobQueueRead::port_job_row(&vault.store, txn, &attempt)?
            .ok_or(crate::error::Error::EntityNotFound)?;
        put_in_txn(
            &vault.store,
            txn,
            attempt.as_bytes(),
            CleanupMark::Archived {
                revision: revision_of(&raw),
                run: AttemptId::now(),
            },
        )
    })
}
