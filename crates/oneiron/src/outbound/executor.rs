use super::OutboundDeliveryWindowDecision;
use super::connector_task::{
    ConnectorSendAttemptPayload, ConnectorSendTask, ConnectorSendTaskOutcome,
    mark_connector_send_task_attempt_started, project_connector_send_task_outcome,
    send_receipt_exists_for_task,
};
use super::dispatch_pipeline::{GATE_OUTCOME_PENDING, PROVIDER_RETRY_AFTER_FIELD};
use super::dispatch_types::{
    OutboundDispatchActor, OutboundDispatchError, OutboundDispatchGate, OutboundDispatchOutcome,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use super::receipt_fields::append_connector_task_window_receipt;
use super::window_door::local_minute_of_day_at;
use crate::Vault;
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, FailAttempt,
    RetryAttempt,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::receipt::{SendReceiptOutcome, persist_send_receipt};

const CONNECTOR_TASK_EXECUTOR_LEASE_OWNER: &str = "connector-task-executor";
/// First re-arm delay for a send the Gate parked on a human decision.
const PENDING_GATE_BACKOFF_BASE_SECS: u64 = 1;
/// Ceiling for that curve: a granted approval waits at most five minutes.
const PENDING_GATE_BACKOFF_CAP_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorTaskExecutorError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Dispatch(#[from] OutboundDispatchError),
    #[error("invalid connector-send TASK: {0}")]
    InvalidTask(&'static str),
    #[error("connector-send TASK dispatch did not reach the transport")]
    NotDispatched,
}

impl Vault {
    /// Counts bridge outbound rows that are not reparented through a valid
    /// connector-send TASK. A newly scheduled send contributes zero.
    pub fn standalone_outbound_intent_count(&self) -> Result<usize, Error> {
        let mut standalone = 0_usize;
        for attempt in AttemptQueue::new(self).list()? {
            if attempt.kind != crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND {
                continue;
            }
            let payload = serde_json::from_slice::<ConnectorSendAttemptPayload>(&attempt.payload);
            let reparented = match payload {
                Ok(payload) => EntityId::from_hex(&payload.task_ref)
                    .ok()
                    .and_then(|task_ref| self.connector_send_task(&task_ref).ok().flatten())
                    .is_some(),
                Err(_) => false,
            };
            if !reparented {
                standalone = standalone.saturating_add(1);
            }
        }
        Ok(standalone)
    }

    /// Claims pending connector-send TASK attempts and runs each through the
    /// existing outbound dispatch pipeline with a real delivery window.
    pub fn run_connector_task_executor<S: OutboundExecutionSink>(
        &self,
        sink: &mut S,
        now: u64,
    ) -> std::result::Result<usize, ConnectorTaskExecutorError> {
        let queue = AttemptQueue::new(self);
        let mut executed = 0_usize;
        loop {
            let attempt = match queue.claim_kind(
                crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                    now,
                },
            )? {
                ClaimOutcome::Empty => break,
                ClaimOutcome::Claimed(attempt) => attempt,
            };
            let payload: ConnectorSendAttemptPayload =
                match serde_json::from_slice(&attempt.payload) {
                    Ok(payload) => payload,
                    Err(_) => {
                        fail_connector_task_attempt(
                            &queue,
                            &attempt,
                            now,
                            "invalid_attempt_payload",
                        )?;
                        continue;
                    }
                };
            let task_ref = match EntityId::from_hex(&payload.task_ref) {
                Ok(task_ref) => task_ref,
                Err(_) => {
                    fail_connector_task_attempt(&queue, &attempt, now, "invalid_task_ref")?;
                    continue;
                }
            };

            if send_receipt_exists_for_task(self, task_ref)? {
                project_connector_send_task_outcome(
                    self,
                    task_ref,
                    ConnectorSendTaskOutcome::Delivered,
                    now,
                )?;
                complete_connector_task_attempt(&queue, &attempt, now)?;
                continue;
            }

            let task = match self.connector_send_task(&task_ref) {
                Ok(Some(task)) => task,
                Ok(None) | Err(_) => {
                    fail_connector_task_attempt(&queue, &attempt, now, "invalid_connector_task")?;
                    continue;
                }
            };
            let attempt_started_node_id = crate::identity::load_or_mint_client_id(self)?;
            mark_connector_send_task_attempt_started(self, task_ref, attempt_started_node_id, now)?;
            let actor = OutboundDispatchActor {
                actor_class: task.actor_class.gate_actor_class().to_owned(),
                actor_ref: Some(task.actor_ref.to_hex()),
                actor_entity_ref: Some(task.actor_ref),
            };
            let originating_session_ref = task.originating_session_ref.clone();
            let idempotency_key = task.intent.idempotency_key.clone();
            let logical_send_intent_ref = connector_logical_send_intent_ref(&task);
            let mut request = OutboundDispatchRequest::new(
                format!("outbound:task:{}", task_ref.to_hex()),
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
            request.ledger_identity_ref = Some(logical_send_intent_ref);
            // Local wall-clock time is derived from the FROZEN offset at THIS
            // attempt's `now`, never from schedule time. No offset ⇒ no local
            // minute ⇒ the door fails closed instead of guessing midnight.
            if let Some(offset) = task.utc_offset_minutes {
                request = request
                    .delivery_window_local_minute_of_day(local_minute_of_day_at(now, offset));
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
            // CAL-04: replay the frozen five-field iMIP body the schedule
            // chokepoint committed with this TASK. The executor is the retry
            // lane, so it must never re-derive a UID or a SEQUENCE — it hands
            // the pipeline exactly what was admitted.
            if let Some(payload) = task.calendar_invite.clone() {
                request = request.calendar_invite(payload);
            }
            let mut result = match self.dispatch_outbound_intent_with_verified_actor(
                request,
                sink,
                task.actor_ref,
                task.actor_class,
            ) {
                Ok(result) => result,
                Err(OutboundDispatchError::InvalidBoundActor) => {
                    // Bound-actor validation fails before the chokepoint admits,
                    // charges, or sends the effect, so this is a definite
                    // non-delivery: fail the attempt terminally and project it.
                    fail_connector_task_attempt(&queue, &attempt, now, "dispatch_rejected")?;
                    project_connector_send_task_outcome(
                        self,
                        task_ref,
                        ConnectorSendTaskOutcome::Failed,
                        now,
                    )?;
                    continue;
                }
                Err(_) => {
                    // The chokepoint runs the transport inside dispatch, so an
                    // error here can surface AFTER the connector was already
                    // called (e.g. a durable commit fails once the sink returned
                    // Acked/Ambiguous). The outcome is unknown, not a definite
                    // failure, so retry and let the replay-first ledger resolve
                    // it (an idempotent resume completes; non-idempotent
                    // uncertainty abandons) instead of projecting a terminal
                    // Failed with no receipt over a possibly-delivered send.
                    retry_connector_task_attempt(
                        &queue,
                        &attempt,
                        now,
                        "dispatch_uncertain",
                        None,
                    )?;
                    continue;
                }
            };
            match result.outcome {
                OutboundDispatchOutcome::DeliveredToChannel => {
                    append_connector_task_window_receipt(&mut result.receipt, &task);
                    let delivered_idempotency =
                        idempotency_key.as_deref().map(|key| (task.actor_ref, key));
                    if persist_send_receipt(
                        self,
                        task_ref,
                        result.receipt,
                        SendReceiptOutcome::Delivered,
                        true,
                        delivered_idempotency,
                    )? {
                        executed = executed.saturating_add(1);
                    }
                    project_connector_send_task_outcome(
                        self,
                        task_ref,
                        ConnectorSendTaskOutcome::Delivered,
                        now,
                    )?;
                    complete_connector_task_attempt(&queue, &attempt, now)?;
                }
                OutboundDispatchOutcome::Held | OutboundDispatchOutcome::Degraded => {
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
                    let retry_at = connector_task_retry_at(&queue, &attempt, now, &arm)?;
                    result
                        .receipt
                        .fields
                        .insert("retry_at".to_owned(), retry_at.to_string());
                    // A parked attempt is still an auditable outcome. Persist it before
                    // replacing the queue row so its policy evidence and retry edge survive.
                    append_connector_task_window_receipt(&mut result.receipt, &task);
                    // The current receipt ledger has Delivered/Failed durability states;
                    // retain the actual parked outcome as a field while storing this as an
                    // audit-only (non-idempotency) row.
                    result.receipt.fields.insert(
                        "dispatch_outcome".to_owned(),
                        result.outcome.as_str().to_owned(),
                    );
                    result.receipt.outcome = "failed".to_owned();
                    persist_send_receipt(
                        self,
                        task_ref,
                        result.receipt,
                        SendReceiptOutcome::Failed,
                        false,
                        None,
                    )?;
                    // The queue re-arms at the SAME instant the receipt surfaced,
                    // so `backoff_until` and the audited retry edge cannot diverge.
                    retry_connector_task_attempt_at(
                        &queue,
                        &attempt,
                        now,
                        result.outcome.as_str(),
                        retry_at,
                    )?;
                }
                OutboundDispatchOutcome::Suppressed | OutboundDispatchOutcome::LetGo => {
                    fail_connector_task_attempt(&queue, &attempt, now, result.outcome.as_str())?;
                    project_connector_send_task_outcome(
                        self,
                        task_ref,
                        ConnectorSendTaskOutcome::Failed,
                        now,
                    )?;
                }
                OutboundDispatchOutcome::Failed => {
                    let intent_pending = result
                        .receipt
                        .fields
                        .get("intent_state")
                        .map(String::as_str)
                        == Some("pending");
                    let delivery_may_have_occurred = result
                        .receipt
                        .fields
                        .get("delivery_may_have_occurred")
                        .is_some_and(|value| value == "true");
                    let provider_retry_is_idempotent = result
                        .receipt
                        .fields
                        .get("retry_class")
                        .is_some_and(|value| value != "non_idempotent_interrupt");
                    if intent_pending
                        && (delivery_may_have_occurred || provider_retry_is_idempotent)
                    {
                        // A provider that stated its own cool-down (a rate-limit
                        // `retry_after`) is obeyed exactly; without one the
                        // generic transport curve still applies. The instant is
                        // computed HERE, before the receipt is persisted, so the
                        // audited retry edge and the queue's `backoff_until`
                        // cannot diverge.
                        let provider_retry_after_secs =
                            receipt_provider_retry_after(&result.receipt);
                        let arm = ConnectorRetryArm {
                            window_edge: None,
                            provider_retry_after_secs,
                            curve: ConnectorRetryCurve::Transport,
                        };
                        let retry_at = connector_task_retry_at(&queue, &attempt, now, &arm)?;
                        result
                            .receipt
                            .fields
                            .insert("retry_at".to_owned(), retry_at.to_string());
                        // A retried transport failure is still an auditable outcome.
                        // Stored as the audit-only (non-idempotency) row a hold takes,
                        // so the provider's stated cool-down, the failure evidence and
                        // the instant this re-arms at survive the retry instead of
                        // living only inside the queue row that replaces it.
                        result.receipt.fields.insert(
                            "dispatch_outcome".to_owned(),
                            result.outcome.as_str().to_owned(),
                        );
                        persist_send_receipt(
                            self,
                            task_ref,
                            result.receipt,
                            SendReceiptOutcome::Failed,
                            false,
                            None,
                        )?;
                        // The queue re-arms at the SAME instant the receipt surfaced.
                        retry_connector_task_attempt_at(
                            &queue,
                            &attempt,
                            now,
                            "transport_failed_pending",
                            retry_at,
                        )?;
                    } else {
                        persist_send_receipt(
                            self,
                            task_ref,
                            result.receipt,
                            SendReceiptOutcome::Failed,
                            false,
                            None,
                        )?;
                        fail_connector_task_attempt(&queue, &attempt, now, "transport_failed")?;
                        project_connector_send_task_outcome(
                            self,
                            task_ref,
                            ConnectorSendTaskOutcome::Failed,
                            now,
                        )?;
                    }
                }
            }
        }
        Ok(executed)
    }
}

fn connector_logical_send_intent_ref(task: &ConnectorSendTask) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.connector.logical_send.v1");
    hasher.update(task.actor_ref.as_bytes());
    if let Some(idempotency_key) = task.intent.idempotency_key.as_deref() {
        hasher.update(b"idempotency_key");
        hasher.update(&(idempotency_key.len() as u64).to_le_bytes());
        hasher.update(idempotency_key.as_bytes());
    } else {
        hasher.update(b"task_ref");
        hasher.update(task.task_ref.as_bytes());
    }
    format!(
        "intent:logical-send:{}",
        crate::entity_id::bytes_to_hex_lower(hasher.finalize().as_bytes())
    )
}

fn complete_connector_task_attempt(
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
) -> Result<(), Error> {
    match queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        now,
    })? {
        CompleteOutcome::Completed(_) | CompleteOutcome::AlreadyCompleted(_) => Ok(()),
    }
}

fn fail_connector_task_attempt(
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
    reason: &str,
) -> Result<(), Error> {
    queue.fail(FailAttempt {
        id: attempt.id,
        lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        reason: reason.to_owned(),
        now,
    })?;
    Ok(())
}

/// Which curve authors the next re-arm instant for a parked send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectorRetryCurve {
    /// The generic transport curve: 60s doubling to a 3,600s ceiling.
    Transport,
    /// The Gate parked this send on a human decision, so it re-arms on the
    /// seconds-scale curve instead of sleeping through the approval.
    GatePending,
}

/// Everything that may author one re-arm instant, in precedence order.
struct ConnectorRetryArm {
    /// The delivery window's own edge. A window is a legality boundary, so it
    /// keeps the authority it already had: nothing below may pull a send
    /// forward past it.
    window_edge: Option<u64>,
    /// What the connector's provider asked for, in seconds from now. The
    /// provider is the only party that knows its own cool-down, so when it
    /// states one it is the exact re-arm instant rather than a guess from a
    /// computed curve.
    provider_retry_after_secs: Option<u64>,
    curve: ConnectorRetryCurve,
}

/// A hold the GATE parked is waiting on a PERSON, not on a transport window:
/// it re-arms on the seconds-scale curve so a granted approval is picked up
/// while it still means something. Every other hold keeps the minute curve.
fn connector_retry_curve(result: &OutboundDispatchResult) -> ConnectorRetryCurve {
    let gate_parked_it = result.gate_outcome == GATE_OUTCOME_PENDING;
    if result.outcome == OutboundDispatchOutcome::Held && gate_parked_it {
        ConnectorRetryCurve::GatePending
    } else {
        ConnectorRetryCurve::Transport
    }
}

/// Reads the provider's stated cool-down off a dispatch receipt.
fn receipt_provider_retry_after(receipt: &crate::receipt::ReceiptRecord) -> Option<u64> {
    receipt
        .fields
        .get(PROVIDER_RETRY_AFTER_FIELD)
        .and_then(|value| value.parse().ok())
}

fn connector_task_retry_at(
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
    arm: &ConnectorRetryArm,
) -> Result<u64, Error> {
    if let Some(edge) = arm.window_edge {
        return Ok(edge.max(now.saturating_add(1)));
    }
    if let Some(secs) = arm.provider_retry_after_secs {
        return Ok(now.saturating_add(secs).max(now.saturating_add(1)));
    }
    if arm.curve == ConnectorRetryCurve::GatePending {
        // Fresh retry rows reset attempt_count, so the retry_of lineage is the
        // only honest exponent — and a corrupt lineage fails CLOSED here rather
        // than silently restarting the curve at its first rung.
        let retry_index = queue.retry_chain_depth(attempt.id)?;
        let delay = PENDING_GATE_BACKOFF_BASE_SECS
            .saturating_mul(1_u64.checked_shl(retry_index).unwrap_or(u64::MAX))
            .min(PENDING_GATE_BACKOFF_CAP_SECS);
        return Ok(now.saturating_add(delay));
    }
    let mut depth = 0_u32;
    let mut cursor = attempt.retry_of;
    // Fresh retry rows reset attempt_count; lineage is the only logical retry counter.
    while let Some(id) = cursor {
        if depth >= 60 {
            break;
        }
        let Some(row) = queue.get(id)? else {
            break;
        };
        depth = depth.saturating_add(1);
        cursor = row.retry_of;
    }
    Ok(now.saturating_add((60_u64.saturating_mul(1_u64 << depth.min(6))).min(3600)))
}

fn retry_connector_task_attempt(
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
    reason: &str,
    provider_retry_after_secs: Option<u64>,
) -> Result<(), Error> {
    let arm = ConnectorRetryArm {
        window_edge: None,
        provider_retry_after_secs,
        curve: ConnectorRetryCurve::Transport,
    };
    let backoff_until = connector_task_retry_at(queue, attempt, now, &arm)?;
    retry_connector_task_attempt_at(queue, attempt, now, reason, backoff_until)
}

/// Re-arms at an ALREADY-COMPUTED instant, so a caller that stamped the exact
/// `retry_at` onto a receipt re-arms the queue at that same instant.
fn retry_connector_task_attempt_at(
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
    reason: &str,
    backoff_until: u64,
) -> Result<(), Error> {
    queue.retry(RetryAttempt {
        id: attempt.id,
        lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        backoff_until,
        last_error: Some(reason.to_owned()),
        now,
    })?;
    Ok(())
}
