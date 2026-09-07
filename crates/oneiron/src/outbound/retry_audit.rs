//! Atomic persistence of a failed send receipt and its retry.

use super::executor::CONNECTOR_TASK_EXECUTOR_LEASE_OWNER;
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, CompleteAttempt, RetryAttempt};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::receipt::{SendReceiptOutcome, persist_send_receipt_in_txn};

/// Commits the audit row, source finalization, successor and indexes together.
/// No receipt may advertise a retry edge unless that retry also commits. A
/// delivered TASK is sticky: losing that race completes the source in the same
/// transaction without persisting the failed receipt or arming a successor.
pub(super) fn persist_failed_send_receipt_and_retry(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    mut receipt: crate::receipt::ReceiptRecord,
    reason: &str,
    retry_at: u64,
    now: u64,
) -> Result<bool, Error> {
    receipt
        .fields
        .insert("retry_at".to_owned(), retry_at.to_string());
    let queue = AttemptQueue::new(vault);
    vault.with_write_txn(|wtxn| {
        if !persist_send_receipt_in_txn(
            &vault.store,
            wtxn,
            task_ref,
            receipt,
            SendReceiptOutcome::Failed,
            false,
            None,
        )? {
            queue.complete_in_txn(
                wtxn,
                CompleteAttempt {
                    id: attempt.id,
                    lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                },
            )?;
            return Ok(false);
        }
        queue.retry_in_txn(
            wtxn,
            RetryAttempt {
                id: attempt.id,
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                backoff_until: retry_at,
                last_error: Some(reason.to_owned()),
                now,
            },
        )?;
        Ok(true)
    })
}
