//! Atomic send-receipt retry and terminal settlement.

use super::connector_task::{ConnectorSendTaskOutcome, project_connector_send_task_outcome_in_txn};
use super::executor::CONNECTOR_TASK_EXECUTOR_LEASE_OWNER;
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, CompleteAttempt, FailAttempt, RetryAttempt};
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
    receipt: crate::receipt::ReceiptRecord,
    reason: &str,
    retry_at: u64,
    now: u64,
) -> Result<bool, Error> {
    persist_send_receipt_and_retry(
        vault,
        attempt,
        task_ref,
        receipt,
        reason,
        retry_at,
        now,
        SendReceiptOutcome::Failed,
        false,
    )
}

/// Same atomic retry contract for a possibly-delivered, idempotent send.
#[expect(clippy::too_many_arguments)]
pub(super) fn persist_send_receipt_and_retry(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    mut receipt: crate::receipt::ReceiptRecord,
    reason: &str,
    retry_at: u64,
    now: u64,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
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
            outcome,
            transport_dispatched,
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

/// Terminal send facts are one commit: an execution-node receipt alone is not
/// the synced user's audit view. This also keeps the queue claim live on abort.
pub(super) struct TerminalSendSettlement<'a> {
    pub(super) attempt: &'a crate::attempt_queue::AttemptRecord,
    pub(super) task_ref: EntityId,
    pub(super) receipt: crate::receipt::ReceiptRecord,
    pub(super) receipt_outcome: SendReceiptOutcome,
    pub(super) transport_dispatched: bool,
    pub(super) task_outcome: ConnectorSendTaskOutcome,
    pub(super) reason: &'a str,
    pub(super) now: u64,
}

pub(super) fn persist_terminal_send_receipt_and_fail(
    vault: &Vault,
    settlement: TerminalSendSettlement<'_>,
) -> Result<bool, Error> {
    vault.with_write_txn(|wtxn| {
        persist_terminal_send_receipt_and_fail_in_txn(vault, wtxn, settlement)
    })
}

pub(super) fn persist_terminal_send_receipt_and_fail_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    settlement: TerminalSendSettlement<'_>,
) -> Result<bool, Error> {
    let TerminalSendSettlement {
        attempt,
        task_ref,
        receipt,
        receipt_outcome,
        transport_dispatched,
        task_outcome,
        reason,
        now,
    } = settlement;
    let queue = AttemptQueue::new(vault);
    if !persist_send_receipt_in_txn(
        &vault.store,
        wtxn,
        task_ref,
        receipt,
        receipt_outcome,
        transport_dispatched,
        None,
    )? {
        // A delivered receipt won the race. Do not replace it with failure.
        project_connector_send_task_outcome_in_txn(
            vault,
            wtxn,
            task_ref,
            ConnectorSendTaskOutcome::Delivered,
            now,
        )?;
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
    project_connector_send_task_outcome_in_txn(vault, wtxn, task_ref, task_outcome, now)?;
    queue.fail_in_txn(
        wtxn,
        FailAttempt {
            id: attempt.id,
            lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            reason: reason.to_owned(),
            now,
        },
    )?;
    Ok(true)
}

/// Terminal mechanical suppression, or a concurrent delivered winner. Queue
/// settlement and the synced TASK projection share one writer transaction.
pub(super) fn settle_suppressed_send(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    now: u64,
) -> Result<(), Error> {
    use crate::attempt_queue::{CompleteAttempt, FailAttempt};
    let queue = AttemptQueue::new(vault);
    vault.with_write_txn(|wtxn| {
        let delivered = crate::receipt::delivered_send_exists_in_txn(&vault.store, wtxn, task_ref)?;
        if delivered {
            queue.complete_in_txn(
                wtxn,
                CompleteAttempt {
                    id: attempt.id,
                    lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                },
            )?;
        } else {
            queue.fail_in_txn(
                wtxn,
                FailAttempt {
                    id: attempt.id,
                    lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason: "dedupe_suppressed".to_owned(),
                    now,
                },
            )?;
        }
        super::connector_task::project_connector_send_task_suppression_in_txn(
            vault, wtxn, task_ref, now, delivered,
        )?;
        Ok(())
    })
}
