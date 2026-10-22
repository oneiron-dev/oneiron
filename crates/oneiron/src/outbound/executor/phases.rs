//! The connector-send executor's per-attempt phases: the dispatch request a
//! claimed task replays, and the settlement of a held or failed dispatch.
//! Entry: `connector_dispatch_request`. The claim loop stays in `executor`.

use super::*;

/// The dispatch request one claimed attempt of `task` replays: its actor,
/// audit and ledger identities, frozen delivery-window facts, session,
/// counterparty and committed calendar invite.
pub(super) fn connector_dispatch_request(
    task_ref: EntityId,
    task: &ConnectorSendTask,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
) -> OutboundDispatchRequest {
    let actor = OutboundDispatchActor {
        actor_class: task.actor_class.gate_actor_class().to_owned(),
        actor_ref: Some(task.actor_ref.to_hex()),
        actor_entity_ref: Some(task.actor_ref),
    };
    let originating_session_ref = task.originating_session_ref.clone();
    let logical_send_intent_ref = connector_logical_send_intent_ref(task);
    let mut request = OutboundDispatchRequest::new(
        // A reclaimed lease can execute under the same attempt id. Its
        // audit identity must still differ from the earlier execution.
        format!(
            "outbound:task:{}:attempt:{}:lease:{}",
            task_ref.to_hex(),
            crate::receipt::hex_lower(attempt.id.as_bytes()),
            attempt.attempt_count
        ),
        // Sink-facing scheduled ref: sinks key their per-send plan by
        // `request.intent_ref`, so it must stay the stable task ref the
        // caller registered the plan under. The charge/replay identity
        // travels separately below.
        format!("intent:task:{}", task_ref.to_hex()),
        task.intent.clone(),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    // Ledger identity is the logical-send id (derived from the task
    // idempotency key) so fresh retry attempts stay the same paid intent.
    request.ledger_identity_ref = Some(logical_send_intent_ref.clone());
    // Local wall-clock time is derived from the FROZEN offset at THIS
    // attempt's `now`, never from schedule time. No offset ⇒ no local
    // minute ⇒ the door fails closed instead of guessing midnight.
    if let Some(offset) = task.utc_offset_minutes {
        request = request.delivery_window_local_minute_of_day(local_minute_of_day_at(now, offset));
    }
    if let Some(level) = task.apns_interruption_level {
        request = request.delivery_window_apns_interruption_level(level);
    }
    if let Some(level) = task.resolved_level {
        request = request.delivery_window_resolved_level(level);
    }
    if task.human_explicit_instant {
        request = request.delivery_window_human_explicit_instant();
    }
    if let Some(session_ref) = originating_session_ref {
        request = request.originating_session(session_ref);
    }
    // The frozen party is not the transport target. The live gate and
    // receipt projector must read the explicit counterparty binding.
    if let Some(party) = task.counterparty_ref.as_deref() {
        request = request.counterparty_ref(party);
    }
    // CAL-04: replay the frozen five-field iMIP body the schedule
    // chokepoint committed with this TASK. The executor is the retry
    // lane, so it must never re-derive a UID or a SEQUENCE — it hands
    // the pipeline exactly what was admitted.
    if let Some(payload) = task.calendar_invite.clone() {
        request = request.calendar_invite(payload);
    }
    request
}

/// Settles a held or degraded dispatch: its retry edge first, then its
/// audit receipt and the queue re-arm together.
pub(super) fn settle_held_connector_task(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    task: &ConnectorSendTask,
    mut result: OutboundDispatchResult,
    now: u64,
) -> Result<(), ConnectorTaskExecutorError> {
    // The door supplies a window-edge retry_at when it knows one;
    // a hostless `local_minute_unavailable` hold knows none. Either
    // way the CONCRETE next instant is computed HERE, before the
    // receipt is persisted, so no hold is ever surfaced with an
    // unknown retry edge (ONE-1880: that is what left the executor
    // spinning at now+1 with nothing surfaced).
    let window_edge = result
        .receipt
        .fields
        .get("retry_at")
        .and_then(|value| value.parse().ok());
    let arm = ConnectorRetryArm {
        window_edge,
        provider_retry_after_secs: receipt_provider_retry_after(&result.receipt),
        curve: connector_retry_curve(&result),
    };
    let retry_at = connector_task_retry_at(queue, attempt, now, &arm)?;
    // A parked attempt is still auditable. Its receipt and the
    // queue re-arm commit together so neither can outlive the other.
    append_connector_task_window_receipt(&mut result.receipt, task);
    // The current receipt ledger has Delivered/Failed durability states;
    // retain the actual parked outcome as a field while storing this as an
    // audit-only (non-idempotency) row.
    result.receipt.fields.insert(
        "dispatch_outcome".to_owned(),
        result.outcome.as_str().to_owned(),
    );
    result.receipt.outcome = "failed".to_owned();
    persist_failed_send_receipt_and_retry(
        vault,
        attempt,
        task_ref,
        result.receipt,
        result.outcome.as_str(),
        retry_at,
        now,
    )?;
    Ok(())
}

/// Settles a failed or ambiguous dispatch: an idempotent retry, a stopped
/// intent's reconciliation, or the attempt's terminal settlement.
#[expect(
    clippy::too_many_arguments,
    reason = "the executor's vault, queue, claimed attempt, task identity, receipt id, owned result and clock are distinct settlement inputs"
)]
pub(super) fn settle_failed_connector_task(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    task: &ConnectorSendTask,
    receipt_id: &str,
    mut result: OutboundDispatchResult,
    now: u64,
) -> Result<(), ConnectorTaskExecutorError> {
    let ambiguous = result.outcome == OutboundDispatchOutcome::Ambiguous;
    // A recovered non-idempotent Pending intent may be ambiguous
    // even though this attempt never reached the transport.
    let transport_dispatched = ambiguous
        && result
            .receipt
            .fields
            .get("delivery_may_have_occurred")
            .is_some_and(|value| value == "true");
    let retryable = matches!(
        result.resolution,
        Some(IntentResolution::Pending {
            retry: RetryDisposition::Idempotent,
            ..
        })
    );
    if retryable {
        // A provider that stated its own cool-down (a rate-limit
        // `retry_after`) is obeyed exactly; without one the
        // generic transport curve still applies. The instant is
        // computed HERE, before the receipt is persisted, so the
        // audited retry edge and the queue's `backoff_until`
        // cannot diverge.
        let provider_retry_after_secs = receipt_provider_retry_after(&result.receipt);
        let arm = ConnectorRetryArm {
            window_edge: None,
            provider_retry_after_secs,
            curve: ConnectorRetryCurve::Transport,
        };
        let retry_at = connector_task_retry_at(queue, attempt, now, &arm)?;
        // A retried transport failure is still an auditable outcome.
        // Stored as the audit-only (non-idempotency) row a hold takes,
        // so the provider's stated cool-down, the failure evidence and
        // the instant this re-arms at survive the retry instead of
        // living only inside the queue row that replaces it.
        result.receipt.fields.insert(
            "dispatch_outcome".to_owned(),
            result.outcome.as_str().to_owned(),
        );
        persist_send_receipt_and_retry(
            vault,
            attempt,
            task_ref,
            result.receipt,
            if ambiguous {
                "transport_ambiguous_pending"
            } else {
                "transport_failed_pending"
            },
            retry_at,
            now,
            if ambiguous {
                SendReceiptOutcome::Ambiguous
            } else {
                SendReceiptOutcome::Failed
            },
            transport_dispatched,
        )?;
    } else if matches!(result.resolution, Some(IntentResolution::Stopped { .. })) {
        reconcile_connector_task(
            vault,
            attempt,
            task,
            receipt_id,
            now,
            None,
            Some(result.receipt),
        )?;
    } else {
        // A non-idempotent definite no-wire attempt is terminal
        // for this queue row, but the logical ledger remains
        // Pending and may be manually retried under O6. An
        // earlier attempt the ledger still holds unresolved
        // keeps the terminal outcome ambiguous.
        let ambiguous = ambiguous
            || matches!(
                result.resolution,
                Some(IntentResolution::Pending {
                    delivery: UnconfirmedDelivery::Unresolved,
                    ..
                })
            );
        if ambiguous {
            result.receipt.outcome = "ambiguous".to_owned();
        }
        super::super::retry_audit::persist_terminal_send_receipt_and_fail(
            vault,
            super::super::retry_audit::TerminalSendSettlement {
                attempt,
                task_ref,
                receipt: result.receipt,
                receipt_outcome: if ambiguous {
                    SendReceiptOutcome::Ambiguous
                } else {
                    SendReceiptOutcome::Failed
                },
                transport_dispatched,
                task_outcome: if ambiguous {
                    ConnectorSendTaskOutcome::Ambiguous
                } else {
                    ConnectorSendTaskOutcome::Failed
                },
                reason: if ambiguous {
                    "transport_ambiguous"
                } else {
                    "transport_failed"
                },
                now,
            },
        )?;
    }
    Ok(())
}
