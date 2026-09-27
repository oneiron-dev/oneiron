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

/// Terminal reconciliation is a ledger read/reduce and a receipt/TASK/queue
/// write under ONE writer. It never calls the connector or a live grant door.
pub(super) fn reconcile_connector_task(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &super::connector_task::ConnectorSendTask,
    receipt_id: &str,
    now: u64,
    stop: Option<crate::outbound_intent_ledger::IntentEscalationReason>,
    attempt_receipt: Option<crate::receipt::ReceiptRecord>,
) -> Result<bool, Error> {
    use super::connector_task::connector_send_task_outcome_in_txn;
    use crate::outbound_intent_ledger::{
        ConnectorIntentBinding, IntentResolution, UnconfirmedDelivery,
        reconcile_connector_intent_in_txn,
    };
    let logical_ref = super::executor::connector_logical_send_intent_ref(task);
    let attempt_id = super::dispatch_attempt_id::outbound_dispatch_attempt_id(&logical_ref)
        .map_err(|_| Error::InvariantViolation("invalid connector logical send ref"))?;
    let binding = ConnectorIntentBinding {
        intent: &task.intent,
        actor_ref: task.actor_ref,
        actor_class: task.actor_class.gate_actor_class(),
        counterparty_ref: task.counterparty_ref.as_deref(),
        originating_session_ref: task.originating_session_ref.as_deref(),
        calendar_invite: task.calendar_invite.as_ref(),
    };
    let terminal = vault.with_write_txn(|wtxn| {
        let Some(resolution) =
            reconcile_connector_intent_in_txn(vault, wtxn, attempt_id, &binding, stop, now)
                .map_err(|_| {
                    Error::InvariantViolation("connector TASK frozen ledger binding mismatch")
                })?
        else {
            return Ok(false);
        };
        let (receipt_outcome, task_outcome) = match resolution {
            IntentResolution::Pending { .. } => return Ok(false),
            IntentResolution::Delivered => (
                SendReceiptOutcome::Delivered,
                ConnectorSendTaskOutcome::Delivered,
            ),
            IntentResolution::Stopped {
                delivery: UnconfirmedDelivery::Unresolved,
                ..
            } => (
                SendReceiptOutcome::Ambiguous,
                ConnectorSendTaskOutcome::Ambiguous,
            ),
            IntentResolution::Stopped {
                delivery: UnconfirmedDelivery::DefiniteNonDelivery,
                ..
            } => (SendReceiptOutcome::Failed, ConnectorSendTaskOutcome::Failed),
        };
        let queue = AttemptQueue::new(vault);
        let synced_outcome = connector_send_task_outcome_in_txn(vault, wtxn, task.task_ref)?;
        // A repeated queue row has no new terminal evidence to receipt. The
        // existing synced outcome is already the audit surface.
        if synced_outcome == Some(task_outcome)
            && task_outcome != ConnectorSendTaskOutcome::Delivered
        {
            queue.complete_in_txn(
                wtxn,
                CompleteAttempt {
                    id: attempt.id,
                    lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                },
            )?;
            return Ok(true);
        }
        // A peer's delivered TASK is stronger than an uncertain local stop.
        if synced_outcome == Some(ConnectorSendTaskOutcome::Delivered)
            && task_outcome != ConnectorSendTaskOutcome::Delivered
        {
            queue.complete_in_txn(
                wtxn,
                CompleteAttempt {
                    id: attempt.id,
                    lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                },
            )?;
            return Ok(true);
        }
        let mut receipt = attempt_receipt.unwrap_or_else(|| {
            crate::receipt::outbound_intent_receipt(
                receipt_id.to_owned(),
                format!("intent:task:{}", task.task_ref.to_hex()),
                &task.intent,
                now,
                "failed",
            )
        });
        receipt.outcome = match receipt_outcome {
            SendReceiptOutcome::Delivered => "delivered_to_channel",
            SendReceiptOutcome::Failed => "failed",
            SendReceiptOutcome::Ambiguous => "ambiguous",
        }
        .to_owned();
        super::receipt_fields::append_connector_task_window_receipt(&mut receipt, task);
        if let Some(party) = task.counterparty_ref.as_ref() {
            receipt
                .fields
                .insert("counterparty_ref".to_owned(), party.clone());
        } else {
            receipt.fields.remove("counterparty_ref");
        }
        let transport_dispatched = receipt_outcome == SendReceiptOutcome::Delivered
            || receipt
                .fields
                .get("delivery_may_have_occurred")
                .is_some_and(|value| value == "true");
        let idempotency = if receipt_outcome == SendReceiptOutcome::Delivered {
            task.intent
                .idempotency_key
                .as_deref()
                .map(|key| (task.actor_ref, key))
        } else {
            None
        };
        let wrote = persist_send_receipt_in_txn(
            &vault.store,
            wtxn,
            task.task_ref,
            receipt,
            receipt_outcome,
            transport_dispatched,
            idempotency,
        )?;
        project_connector_send_task_outcome_in_txn(
            vault,
            wtxn,
            task.task_ref,
            if wrote {
                task_outcome
            } else {
                ConnectorSendTaskOutcome::Delivered
            },
            now,
        )?;
        if !wrote || task_outcome == ConnectorSendTaskOutcome::Delivered {
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
                    reason: "terminal_outbound_stop".to_owned(),
                    now,
                },
            )?;
        }
        Ok(true)
    })?;
    if terminal && stop.is_some() {
        crate::outbound_intent_ledger::force_sync(vault)
            .map_err(|_| Error::InvariantViolation("outbound terminal resolution sync failed"))?;
    }
    Ok(terminal)
}
