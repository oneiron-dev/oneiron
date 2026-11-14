//! Connector-send attempt execution.
//! Entry: `Vault::run_connector_task_executor`.
//! Defines its own items.

use super::OutboundDeliveryWindowDecision;
use super::connector_task::{
    ConnectorSendAttemptPayload, ConnectorSendTask, ConnectorSendTaskOutcome,
    SEND_EXECUTOR_FENCE_FIELD, SEND_EXECUTOR_STOOD_DOWN, SendExecutorFence, SendExecutorLease,
    SendExecutorLeaseTake, log_send_executor_stand_down, mark_send_lookup_cleared,
    project_connector_send_task_outcome, project_connector_send_task_outcome_in_txn,
    renew_send_executor_lease_in_txn, send_receipt_exists_for_task, take_send_executor_lease,
};
use super::dispatch_pipeline::{
    ALTERNATIVE_OUTCOME_FIELD, GATE_OUTCOME_PENDING, PROVIDER_RETRY_AFTER_FIELD,
    ambient_alternative_ref,
};
use super::dispatch_types::{
    OutboundDispatchActor, OutboundDispatchError, OutboundDispatchGate, OutboundDispatchOutcome,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use super::receipt_fields::{PROVIDER_WAIT_FIELD, append_connector_task_window_receipt};
use super::retry_audit::{
    complete_degraded_connector_task, persist_failed_send_receipt_and_retry,
    persist_send_receipt_and_retry, reconcile_connector_task, settle_suppressed_send,
    stop_owner_declined_send,
};
use super::send_lookup::{
    SENT_LOOKUP_CANNOT_TELL, SENT_LOOKUP_FIELD, SENT_LOOKUP_NOT_SENT,
    UNCERTAIN_SEND_ANSWER_POLL_SECS, UNCERTAIN_SEND_AWAITS_OWNER_REASON,
    UNCERTAIN_SEND_LOOKUP_DELAY_SECS, UNCERTAIN_SEND_LOOKUP_DUE_REASON,
    earlier_executor_may_have_sent, engine_send_id, owner_declined_resend,
};
use super::window_door::local_minute_of_day_at;
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, CompleteAttempt, CompleteOutcome, FailAttempt, RetryAttempt,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, IntentResolution, RetryDisposition,
    UnconfirmedDelivery, abandon_attempt_undelivered_intents_in_txn,
};
use crate::receipt::SendReceiptOutcome;

mod alternative_route;
mod phases;
mod send_line;

use self::phases::{
    ambient_alternative_went, connector_dispatch_request, park_uncertain_send,
    settle_failed_connector_task, settle_held_connector_task,
};
use self::send_line::ConnectorSendLine;

pub(super) const CONNECTOR_TASK_EXECUTOR_LEASE_OWNER: &str = "connector-task-executor";
/// The queue reason a provider wait ends with at its caller's deadline (FIX
/// 8818).
const PROVIDER_WAIT_DEADLINE_REASON: &str = "deadline_reached";
/// The receipt field naming the deadline that ended a provider wait.
const PROVIDER_WAIT_DEADLINE_FIELD: &str = "deadline_at";
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
            if attempt.kind != crate::outbound::BRIDGE_OUTBOUND_ATTEMPT_KIND {
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

    /// When the next connector-send attempt becomes claimable, the instant a
    /// served worker sleeps until (OF-187): the same readiness instant the
    /// claim reads. `None` while nothing is queued.
    pub fn next_connector_send_ready_at(&self) -> Result<Option<u64>, Error> {
        // Only the outbound kind's rows are read (FIX 11940).
        let rows = {
            let txn = self.store.env.read_txn()?;
            AttemptQueue::new(self)
                .kind_working_rows_in_txn(&txn, crate::outbound::BRIDGE_OUTBOUND_ATTEMPT_KIND)?
        };
        Ok(rows
            .into_iter()
            .filter(|attempt| {
                matches!(
                    attempt.state,
                    crate::attempt_queue::AttemptState::Queued
                        | crate::attempt_queue::AttemptState::Scheduled
                )
            })
            .map(|attempt| {
                attempt
                    .scheduled_at
                    .or(attempt.backoff_until)
                    .unwrap_or(attempt.created_at)
            })
            .min())
    }

    /// Claims pending connector-send TASK attempts in the fair line's order
    /// (FIX 12157: round-robin across their writers, oldest first within
    /// one) and runs each through the existing outbound dispatch pipeline
    /// with a real delivery window.
    pub fn run_connector_task_executor<S: OutboundExecutionSink>(
        &self,
        sink: &mut S,
        now: u64,
    ) -> std::result::Result<usize, ConnectorTaskExecutorError> {
        let queue = AttemptQueue::new(self);
        let mut executed = 0_usize;
        // The vault clock as the drain starts, beside the caller's `now`: each
        // send's window door measures the time the drain spent from here.
        let drain_clock = self.now_recorded_at();
        // The sends a full window paced all come back at the instant it
        // opens; taken in the fair line's order, they share it by writer.
        let mut line = ConnectorSendLine::default();
        loop {
            let Some(attempt) = line.claim_next(self, &queue, now)? else {
                break;
            };
            let payload: ConnectorSendAttemptPayload =
                match serde_json::from_slice(&attempt.payload) {
                    Ok(payload) => payload,
                    Err(_) => {
                        fail_connector_task_attempt(
                            self,
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
                    fail_connector_task_attempt(self, &attempt, now, "invalid_task_ref")?;
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
                complete_connector_task_attempt(self, &attempt, now)?;
                continue;
            }

            let task = match self.connector_send_task(&task_ref) {
                Ok(Some(task)) => task,
                Ok(None) | Err(_) => {
                    fail_connector_task_attempt(self, &attempt, now, "invalid_connector_task")?;
                    continue;
                }
            };
            // Reconcile an already terminal local logical send before either
            // the synced TASK fence or the live actor/permission checks. This
            // path cannot call the provider.
            let preflight_receipt = format!(
                "outbound:task:{}:attempt:{}:lease:{}",
                task_ref.to_hex(),
                crate::receipt::hex_lower(attempt.id.as_bytes()),
                attempt.attempt_count,
            );
            let reconciled = reconcile_connector_task(
                self,
                &attempt,
                &task,
                &preflight_receipt,
                now,
                None,
                None,
            )?;
            if reconciled {
                continue;
            }
            if task.outcome == Some(ConnectorSendTaskOutcome::Ambiguous) {
                // A terminal possibly-delivered send is not a fresh send permit,
                // even if a duplicate queue row is scheduled later.
                complete_connector_task_attempt(self, &attempt, now)?;
                continue;
            }
            // FIX 4747: the owner answered this TASK's uncertain send with no
            // resend. This machine's own row of the send stops with his
            // word, and nothing is sent.
            if owner_declined_resend(task.outcome) {
                stop_owner_declined_send(self, &attempt, &task, now)?;
                continue;
            }
            // A commitment wake sends only while its approval stands. Asked on
            // every attempt, so a retraction after scheduling stops the send.
            if !crate::commitment_wake::scheduled_commitment_wake_authorised(self, &task)? {
                fail_connector_task_attempt_and_project(
                    self,
                    &queue,
                    &attempt,
                    task_ref,
                    now,
                    "commitment_wake_approval_withdrawn",
                    ConnectorSendTaskOutcome::Failed,
                )?;
                continue;
            }
            #[cfg(test)]
            run_before_attempt_start_hook(self);
            // FIX 4747: only the TASK's sticky send executor sends it.
            let node_id = crate::identity::load_or_mint_client_id(self)?;
            let taken = match take_send_executor_lease(
                self,
                task_ref,
                node_id,
                &engine_send_id(&task),
                now,
            )? {
                SendExecutorLeaseTake::Taken(taken) => taken,
                SendExecutorLeaseTake::HeldElsewhere(held) => {
                    log_send_executor_stand_down(task_ref, node_id, None, Some(held));
                    stand_down_connector_task_attempt(self, &attempt, &task, now)?;
                    continue;
                }
                SendExecutorLeaseTake::Closed => {
                    complete_connector_task_attempt(self, &attempt, now)?;
                    continue;
                }
                // This process is closing: the attempt stays pending, re-armed
                // as a retry, so the send is neither sent nor lost (review
                // #6574).
                SendExecutorLeaseTake::Closing => {
                    retry_connector_task_attempt(
                        self,
                        &queue,
                        &attempt,
                        task_ref,
                        now,
                        "send_executor_closing",
                        None,
                    )?;
                    continue;
                }
            };
            // FIX 4747: a send that may have gone out, which no lookup could
            // settle, sends nothing until the owner answers its ask. The
            // attempt comes back to read his answer, which may come from any
            // machine.
            if taken.uncertain_send.is_some() {
                retry_connector_task_attempt_at(
                    self,
                    &queue,
                    &attempt,
                    task_ref,
                    now,
                    UNCERTAIN_SEND_AWAITS_OWNER_REASON,
                    now.saturating_add(UNCERTAIN_SEND_ANSWER_POLL_SECS),
                )?;
                continue;
            }
            let lease = taken.lease;
            let mut request =
                connector_dispatch_request(task_ref, &task, &attempt, lease, now, drain_clock);
            // FIX 4747: the engine send id rides to the wire and to the
            // provider lookup; a send an earlier executor may have made is
            // looked up first, and the owner's resend goes once unlooked.
            request.engine_send_id = Some(taken.engine_send_id.clone());
            request.owner_released_resend = taken.owner_released_resend;
            request.send_approved_at = Some(task.occurred_at);
            request.earlier_send_lookup =
                !taken.owner_released_resend && earlier_executor_may_have_sent(&taken);
            // FIX 11029: an ambient alternative admitted for this interrupt
            // decides the route; the interrupt does not go after it.
            match alternative_route::route_bound_alternative(
                self,
                sink,
                &queue,
                &attempt,
                &task,
                &mut request,
                now,
            )? {
                alternative_route::RoutedAttempt::Interrupt => {}
                alternative_route::RoutedAttempt::Went => {
                    executed = executed.saturating_add(1);
                    continue;
                }
                alternative_route::RoutedAttempt::Settled => continue,
            }
            let receipt_id = request.receipt_id.clone();
            let result = match self.dispatch_outbound_intent_with_verified_actor(
                request,
                sink,
                task.actor_ref,
                task.actor_class,
            ) {
                Ok(result) => result,
                Err(
                    OutboundDispatchError::InvalidBoundActor
                    | OutboundDispatchError::ObsoleteAskConfirmation,
                ) => {
                    if !reconcile_connector_task(
                        self,
                        &attempt,
                        &task,
                        &receipt_id,
                        now,
                        Some(IntentEscalationReason::BindingInvalid),
                        None,
                    )? {
                        // The actor disappeared before any logical send was
                        // admitted. This attempt certainly did not cross.
                        fail_connector_task_attempt_and_project(
                            self,
                            &queue,
                            &attempt,
                            task_ref,
                            now,
                            "dispatch_rejected",
                            ConnectorSendTaskOutcome::Failed,
                        )?;
                    }
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
                    // FIX 10955: dispatch ran the transport above, so refresh
                    // the drain's `now` before computing this retry's edge.
                    let now = self.now_recorded_at();
                    retry_connector_task_attempt(
                        self,
                        &queue,
                        &attempt,
                        task_ref,
                        now,
                        "dispatch_uncertain",
                        None,
                    )?;
                    continue;
                }
            };
            // FIX 4747: the fence found the lease moved before the transport
            // call, so nothing was sent; the TASK stays the holder's.
            if send_executor_stood_down(&result) {
                stand_down_connector_task_attempt(self, &attempt, &task, self.now_recorded_at())?;
                continue;
            }
            // FIX 4747: what the send's provider lookup found. Nobody can
            // tell: the TASK holds and asks the owner, nothing sent. The
            // provider has no such send: this lease generation's send is
            // cleared to go, and its outcome settles below as any other.
            match sent_lookup_finding(&result) {
                Some(SentLookupFinding::CannotTell) => {
                    park_uncertain_send(self, &attempt, task_ref, &task, result)?;
                    continue;
                }
                Some(SentLookupFinding::NotSent) => {
                    mark_send_lookup_cleared(
                        self,
                        task_ref,
                        lease.generation,
                        self.now_recorded_at(),
                    )?;
                }
                None => {}
            }
            match SendSettlement::of(&result) {
                SendSettlement::Went { deferred: false } => {
                    #[cfg(test)]
                    run_before_delivered_receipt_hook();
                    if reconcile_connector_task(
                        self,
                        &attempt,
                        &task,
                        &receipt_id,
                        now,
                        None,
                        Some(result.receipt),
                    )? {
                        executed = executed.saturating_add(1);
                    }
                }
                // The provider accepted the send as a remote task (FIX 7960):
                // the TASK completes, and the send is never repeated.
                SendSettlement::Went { deferred: true } => {
                    reconcile_connector_task(
                        self,
                        &attempt,
                        &task,
                        &receipt_id,
                        now,
                        None,
                        Some(result.receipt),
                    )?;
                }
                // FIX 7962: the ambient send the interrupt degraded to went,
                // so the TASK's send is carried out; the interrupt is not
                // re-armed.
                SendSettlement::Held { degraded: true } if ambient_alternative_went(&result) => {
                    complete_degraded_connector_task(self, &attempt, &task, result.receipt, now)?;
                    executed = executed.saturating_add(1);
                }
                SendSettlement::Held { .. } => {
                    settle_held_connector_task(
                        self, &queue, &attempt, task_ref, &task, result, now,
                    )?;
                }
                // The common door already recorded the semantic dedupe.
                // Settle this TASK and queue without another send receipt.
                SendSettlement::Deduplicated => {
                    settle_suppressed_send(self, &attempt, task_ref, now)?;
                }
                SendSettlement::Refused { stop } => {
                    // A refusal only stops this attempt. Whether an earlier
                    // attempt of the same logical send may have delivered is
                    // the ledger's to say, not the refusal's.
                    let reason = result.outcome.as_str();
                    if !reconcile_connector_task(
                        self,
                        &attempt,
                        &task,
                        &receipt_id,
                        now,
                        Some(stop),
                        Some(result.receipt),
                    )? {
                        // No logical send was ever admitted for this binding.
                        // The refused attempt certainly did not cross.
                        fail_connector_task_attempt_and_project(
                            self,
                            &queue,
                            &attempt,
                            task_ref,
                            now,
                            reason,
                            ConnectorSendTaskOutcome::Failed,
                        )?;
                    }
                }
                SendSettlement::Failed { .. } => {
                    settle_failed_connector_task(
                        self,
                        &queue,
                        &attempt,
                        task_ref,
                        &task,
                        &receipt_id,
                        result,
                        now,
                    )?;
                }
            }
        }
        Ok(executed)
    }
}

pub(super) fn connector_logical_send_intent_ref(task: &ConnectorSendTask) -> String {
    super::dispatch_attempt_id::connector_logical_send_ref(
        task.actor_ref,
        task.intent.idempotency_key.as_deref(),
        task.task_ref,
    )
}

fn complete_connector_task_attempt(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
) -> Result<(), Error> {
    match vault.with_write_txn_grouped(|txn| {
        crate::ports::JobQueue::port_job_complete(
            vault,
            txn,
            CompleteAttempt {
                id: attempt.id,
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            },
        )
    })? {
        CompleteOutcome::Completed(_) | CompleteOutcome::AlreadyCompleted(_) => Ok(()),
    }
}

/// What a machine that does not hold a TASK's send executor lease does with
/// its own local attempt (FIX 4747): in one writer, it stops its local sends
/// of the TASK that certainly never went, which gives their reserved budget
/// back, and completes the local queue row. A local send that may have gone
/// keeps its state. The synced TASK stays unsettled, so the holder sends and
/// this machine never claims the row again. Engine call (CALLS, FIX 4747):
/// complete, not re-park; a lease handed back here later comes with a fresh
/// local attempt from its handover caller.
fn stand_down_connector_task_attempt(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &ConnectorSendTask,
    now: u64,
) -> Result<(), Error> {
    let ledger_attempt_ids = connector_task_ledger_attempt_ids(task)?;
    match vault.with_write_txn_grouped(|txn| {
        for ledger_attempt_id in &ledger_attempt_ids {
            abandon_attempt_undelivered_intents_in_txn(
                vault,
                txn,
                *ledger_attempt_id,
                IntentEscalationReason::SendExecutorStoodDown,
                now,
            )
            .map_err(|error| match error {
                IntentLedgerError::Engine(error) => error,
                _ => Error::CorruptedIndex("outbound intent ledger row"),
            })?;
        }
        crate::ports::JobQueue::port_job_complete(
            vault,
            txn,
            CompleteAttempt {
                id: attempt.id,
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            },
        )
    })? {
        CompleteOutcome::Completed(_) | CompleteOutcome::AlreadyCompleted(_) => Ok(()),
    }
}

/// The ledger attempt ids `task`'s local sends are keyed under: its logical
/// send's, and its bound ambient alternative's (FIX 7962), each derived from
/// the ledger identity its dispatch request carries. The stand-down abandons
/// under them, and the reaper's take supersedes what it abandoned (FIX 4747).
pub(super) fn connector_task_ledger_attempt_ids(
    task: &ConnectorSendTask,
) -> Result<Vec<AttemptId>, Error> {
    let logical_ref = connector_logical_send_intent_ref(task);
    let mut ledger_refs = Vec::with_capacity(2);
    if let Some(alternative) = task.ambient_alternative.as_ref() {
        ledger_refs.push(ambient_alternative_ref(&logical_ref, &alternative.surface));
    }
    ledger_refs.push(logical_ref);
    ledger_refs
        .iter()
        .map(|ledger_ref| {
            super::dispatch_attempt_id::outbound_dispatch_attempt_id(ledger_ref)
                .map_err(|_| Error::InvariantViolation("invalid connector logical send ref"))
        })
        .collect()
}

/// Whether the send executor fence stood this dispatch down before its
/// transport call (FIX 4747), directly or through its ambient alternative.
fn send_executor_stood_down(result: &OutboundDispatchResult) -> bool {
    result
        .receipt
        .fields
        .get(SEND_EXECUTOR_FENCE_FIELD)
        .is_some_and(|value| value == SEND_EXECUTOR_STOOD_DOWN)
}

/// How a connector send settles by its dispatch result, read the same for
/// the interrupt's own send and for its ambient alternative (FIX 22396). It
/// matches every [`OutboundDispatchOutcome`] and each route matches every
/// settlement, with no catch-all in either, so an outcome added later fails
/// to compile until both routes say how it settles. Each route keeps its own
/// settlement writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendSettlement {
    /// Delivered to the channel, or accepted as a remote task (FIX 7960).
    Went { deferred: bool },
    /// Held, or degraded to an ambient alternative.
    Held { degraded: bool },
    /// Suppressed or let go as a semantic dedupe the common door already
    /// recorded.
    Deduplicated,
    /// Suppressed or let go by a refusal: the send stops for `stop`.
    Refused { stop: IntentEscalationReason },
    /// Failed, or ambiguous; `stopped` when the intent's resolution says the
    /// ledger stopped it.
    Failed { stopped: bool },
}

impl SendSettlement {
    fn of(result: &OutboundDispatchResult) -> Self {
        match result.outcome {
            OutboundDispatchOutcome::DeliveredToChannel => Self::Went { deferred: false },
            OutboundDispatchOutcome::Deferred => Self::Went { deferred: true },
            OutboundDispatchOutcome::Held => Self::Held { degraded: false },
            OutboundDispatchOutcome::Degraded => Self::Held { degraded: true },
            OutboundDispatchOutcome::Suppressed | OutboundDispatchOutcome::LetGo => {
                if result.receipt.fields.get("suppression").map(String::as_str) == Some("dedupe") {
                    Self::Deduplicated
                } else if result.gate_reason_codes.iter().any(|code| {
                    code == crate::gate::GateReasonCode::DenyConnectorKeySuspended.as_str()
                }) {
                    Self::Refused {
                        stop: IntentEscalationReason::ConnectorRevoked,
                    }
                } else {
                    Self::Refused {
                        stop: IntentEscalationReason::BindingInvalid,
                    }
                }
            }
            OutboundDispatchOutcome::Failed | OutboundDispatchOutcome::Ambiguous => Self::Failed {
                stopped: matches!(result.resolution, Some(IntentResolution::Stopped { .. })),
            },
        }
    }
}

/// What a send's provider lookup found, as its dispatch receipt names it
/// (FIX 4747). A lookup that found the send kept settles it delivered as any
/// other delivery, so it needs no reading here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SentLookupFinding {
    NotSent,
    CannotTell,
}

fn sent_lookup_finding(result: &OutboundDispatchResult) -> Option<SentLookupFinding> {
    match result
        .receipt
        .fields
        .get(SENT_LOOKUP_FIELD)
        .map(String::as_str)
    {
        Some(SENT_LOOKUP_NOT_SENT) => Some(SentLookupFinding::NotSent),
        Some(SENT_LOOKUP_CANNOT_TELL) => Some(SentLookupFinding::CannotTell),
        _ => None,
    }
}

fn fail_connector_task_attempt(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    now: u64,
    reason: &str,
) -> Result<(), Error> {
    vault.with_write_txn_grouped(|txn| {
        crate::ports::JobQueue::port_job_fail(
            vault,
            txn,
            FailAttempt {
                id: attempt.id,
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason: reason.to_owned(),
                now,
            },
        )
    })?;
    Ok(())
}

/// No transport receipt exists for a pre-send refusal. Still settle the
/// synced TASK and the queue in one commit so a crash cannot strand it.
fn fail_connector_task_attempt_and_project(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    now: u64,
    reason: &str,
    outcome: ConnectorSendTaskOutcome,
) -> Result<(), Error> {
    vault.with_write_txn_grouped(|wtxn| {
        project_connector_send_task_outcome_in_txn(vault, wtxn, task_ref, outcome, now)?;
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
        Ok(())
    })
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
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
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
    retry_connector_task_attempt_at(vault, queue, attempt, task_ref, now, reason, backoff_until)
}

/// Re-arms at an ALREADY-COMPUTED instant, so a caller that stamped the exact
/// `retry_at` onto a receipt re-arms the queue at that same instant. In the
/// same writer, this machine's send executor lease on `task_ref` is renewed
/// through that instant (FIX 4747 slice 4), so the park keeps its lease.
fn retry_connector_task_attempt_at(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task_ref: EntityId,
    now: u64,
    reason: &str,
    backoff_until: u64,
) -> Result<(), Error> {
    vault.with_write_txn_grouped(|wtxn| {
        queue.retry_in_txn(
            wtxn,
            RetryAttempt {
                id: attempt.id,
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                backoff_until,
                last_error: Some(reason.to_owned()),
                now,
            },
        )?;
        renew_send_executor_lease_in_txn(vault, wtxn, task_ref, backoff_until, now)
    })?;
    vault.store.notify_attempt_observers();
    Ok(())
}

#[cfg(test)]
type BeforeAttemptStartHook = Box<dyn FnOnce(&Vault)>;

#[cfg(test)]
std::thread_local! {
    static BEFORE_ATTEMPT_START: std::cell::RefCell<Option<BeforeAttemptStartHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(super) fn set_before_attempt_start_hook(hook: impl FnOnce(&Vault) + 'static) {
    BEFORE_ATTEMPT_START.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_attempt_start_hook(vault: &Vault) {
    BEFORE_ATTEMPT_START.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook(vault);
        }
    });
}

#[cfg(test)]
std::thread_local! {
    static BEFORE_DELIVERED_RECEIPT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(super) fn set_before_delivered_receipt_hook(hook: impl FnOnce() + 'static) {
    BEFORE_DELIVERED_RECEIPT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_delivered_receipt_hook() {
    BEFORE_DELIVERED_RECEIPT.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}
