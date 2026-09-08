//! Schedule-only dispatch of connector sends through the OF-327 chokepoint.

use super::super::support::{Memory, verify_actor_binding, verify_actor_binding_in_txn};
use super::super::{MemoryError, MemoryResult};
use super::dedupe::outbound_intent_ref;
use super::errors::{
    dispatch_outcome_str, facade_error_from_calendar, facade_error_from_outbound_dispatch,
};
use super::types::{OutboundDraftInput, OutboundIntentReceipt, OutboundScheduleContext};
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger, connector_send_attempt_payload, outbound_verb_contract,
    put_connector_send_task_in_txn,
};
use crate::receipt::delivered_send_receipt_for_task;
/// Attempt-queue kind for bridge-scheduled outbound intents. Pending schedules
/// use the queue's kind-scoped dedupe index; delivered sends use the additive
/// durable client-idempotency index.
pub const BRIDGE_OUTBOUND_ATTEMPT_KIND: &str = "bridge.outbound.schedule";

impl Memory<'_> {
    /// Schedules one connector-send TASK through the OF-327 chokepoint. The
    /// bridge never delivers: it gate-checks under a `Hold` window first, then
    /// durably co-commits the shared TASK and ready execution attempt. Thus no
    /// connector worker can claim the send before schedule admission finishes,
    /// while the gate decision remains a queryable governance receipt.
    pub fn schedule_outbound(
        &self,
        draft: &OutboundDraftInput,
    ) -> MemoryResult<OutboundIntentReceipt> {
        self.schedule_outbound_with_context(draft, &OutboundScheduleContext::default())
    }

    pub fn schedule_outbound_with_context(
        &self,
        draft: &OutboundDraftInput,
        schedule_context: &OutboundScheduleContext,
    ) -> MemoryResult<OutboundIntentReceipt> {
        self.schedule_outbound_inner(draft, schedule_context, None)
    }

    /// The single scheduling implementation.
    ///
    /// `calendar_invite` is CAL-04's typed payload channel: the invite surface
    /// is the only producer, and it is not reachable from the public draft type
    /// — which is exactly what keeps a hand-rolled `OutboundDraftInput` from
    /// scheduling an invite. Such a draft still resolves the registered
    /// capability, but it carries no five-field body, so the chokepoint's verb
    /// wall refuses it at the last durable boundary.
    pub(super) fn schedule_outbound_inner(
        &self,
        draft: &OutboundDraftInput,
        schedule_context: &OutboundScheduleContext,
        calendar_invite: Option<&crate::calendar::CalendarInvitePayload>,
    ) -> MemoryResult<OutboundIntentReceipt> {
        schedule_context.validate()?;
        if schedule_context.apns_interruption_level.is_some()
            && !(draft.channel == "apns" && draft.verb == "push")
        {
            return Err(MemoryError::bad_request_with(
                "APNs interruption level requires an APNs push",
                &["Do not attach APNs levels to chat, email, voice, or ring sends."],
            ));
        }
        let trigger = match draft.trigger.as_str() {
            "commitment" | "commitment_timer_wake" => {
                OutboundIntentTrigger::commitment_timer_wake(draft.trigger_ref.clone())
            }
            "gap_queue" => OutboundIntentTrigger::gap_queue(draft.trigger_ref.clone()),
            "agent_immediate" => OutboundIntentTrigger::agent_immediate(draft.trigger_ref.clone()),
            other => {
                return Err(MemoryError::bad_request_with(
                    format!("unknown outbound trigger {other:?}"),
                    &["Use one of: commitment_timer_wake, gap_queue, agent_immediate."],
                ));
            }
        };
        let trigger = match &draft.job_ref {
            Some(job_ref) => trigger.job_ref(job_ref.clone()),
            None => trigger,
        };
        let originating_session_ref =
            (draft.trigger == "agent_immediate").then(|| draft.trigger_ref.clone());
        let now = draft.occurred_at.unwrap_or_else(crate::unix_seconds_now);

        // A completed attempt no longer owns the generic queue dedupe row.
        // Consult the additive delivered-only index before any new gate or
        // enqueue work so a client retry cannot charge or send twice.
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if let Some(idempotency_key) = draft.idempotency_key.as_deref()
            && let Some(task_ref) = self
                .vault
                .store
                .get_delivered_send_task_by_idempotency(&self.actor, idempotency_key)?
        {
            let receipt =
                delivered_send_receipt_for_task(self.vault, task_ref)?.ok_or_else(|| {
                    MemoryError::from(Error::CorruptedIndex("send idempotency index"))
                })?;
            let actor_ref = self.actor.to_hex();
            if receipt.actor.as_deref() != Some(actor_ref.as_str())
                || receipt.fields.get("idempotency_key").map(String::as_str)
                    != Some(idempotency_key)
            {
                return Err(MemoryError::from(Error::CorruptedIndex(
                    "send idempotency index",
                )));
            }
            return Ok(OutboundIntentReceipt {
                intent_ref: receipt
                    .fields
                    .get("intent_ref")
                    .cloned()
                    .unwrap_or_else(|| format!("intent:task:{}", task_ref.to_hex())),
                outcome: "already_sent".to_owned(),
                gate_outcome: receipt.fields.get("gate_outcome").cloned(),
                gate_decision_ref: receipt.fields.get("gate_decision_ref").cloned(),
                gate_reason_codes: receipt
                    .fields
                    .get("gate_reason_codes")
                    .map(|codes| {
                        codes
                            .split(',')
                            .filter(|code| !code.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                deduped: true,
            });
        }

        // Pre-validate the channel/verb capability before either the gate or
        // durable enqueue, preserving a clean retry for malformed requests.
        outbound_verb_contract(&draft.channel, &draft.verb).map_err(|capability| {
            MemoryError::bad_request_with(
                format!("unsupported outbound capability: {capability}"),
                &["Use a registered channel/verb pair from the connector manifest."],
            )
        })?;

        let mut intent_draft = OutboundIntentDraft::new(
            self.actor.to_hex(),
            draft.verb.clone(),
            draft.channel.clone(),
            draft.target.clone(),
        );
        if let Some(on_behalf_of) = &draft.on_behalf_of {
            intent_draft = intent_draft.on_behalf_of(on_behalf_of.clone());
        }
        if let Some(content_ref) = &draft.content_ref {
            intent_draft = intent_draft.content_ref(content_ref.clone());
        }
        if let Some(idempotency_key) = &draft.idempotency_key {
            intent_draft = intent_draft.idempotency_key(idempotency_key.clone());
        }
        if let Some(dedupe_key) = &draft.dedupe_key {
            intent_draft = intent_draft.dedupe_key(dedupe_key.clone());
        }
        let intent = OutboundIntent::from_trigger(intent_draft, trigger);

        let queue = AttemptQueue::new(self.vault);
        let task_ref = EntityId::now();
        let payload = connector_send_attempt_payload(task_ref)?;
        // The queue's live-schedule dedupe is scoped by the BOUND EFFECT ACTOR
        // — never `on_behalf_of`, the target, the trigger, the TASK, or any
        // client-controlled content — matching the actor-scoped contract the
        // delivered-send index already keeps. Computed once so the abort-only
        // preflight and the durable enqueue below cannot disagree by a byte.
        let dedupe_actor_ref = self.actor.to_hex();

        // Abort-only enqueue preflight validates queue inputs and recovers an
        // existing live schedule without appending a second Gate decision. A
        // missing key writes only inside this uncommitted transaction and is
        // therefore neither durable nor claimable.
        let mut preflight_txn = self.vault.store.env.write_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(self.vault, &preflight_txn, self.actor, self.actor_class)?;
        let preflight = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
            &mut preflight_txn,
            EnqueueAttempt {
                kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                payload: payload.clone(),
                dedupe_key: draft.idempotency_key.clone(),
                run_id: draft.job_ref.clone(),
                now,
            },
            None,
            Some(dedupe_actor_ref.as_str()),
        )?;
        drop(preflight_txn);
        if let EnqueueOutcome::Existing(attempt) = preflight {
            return Ok(self.already_scheduled_outbound_receipt(attempt.id));
        }

        // CAL-04 (ONE-1786) chokepoint admission, in its fixed order: exact
        // decode (the typed payload is already decoded above), emit/state
        // validation against the live outbound passport, vault-only hygiene
        // hydration, hygiene evaluation. It runs AFTER the dedupe returns
        // above — a coalesced re-schedule must not re-check or re-bump anything
        // — and BEFORE the gate, so a refused invite consumes no gate decision,
        // no budget, and no queue row. The passport head it produces is applied
        // inside the durable transaction below.
        let invite_admission = match calendar_invite {
            Some(payload) => Some(
                crate::calendar::admit_calendar_invite(self.vault, self.actor, payload, now)
                    .map_err(facade_error_from_calendar)?,
            ),
            None => None,
        };

        let gate_intent_ref = format!("intent:task:{}", task_ref.to_hex());
        let actor = OutboundDispatchActor {
            actor_class: self.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            actor_entity_ref: Some(self.actor),
        };
        let mut request = OutboundDispatchRequest::new(
            format!("outbound:{gate_intent_ref}"),
            gate_intent_ref.clone(),
            intent.clone(),
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            now,
            OutboundDeliveryWindowDecision::Hold {
                reason: "bridge_scheduled".to_owned(),
                retry_at: None,
            },
        );
        if let Some(session_ref) = originating_session_ref.as_deref() {
            request = request.originating_session(session_ref);
        }
        if let Some(payload) = calendar_invite {
            request = request.calendar_invite(payload.clone());
        }
        let mut sink = ScheduleOnlySink;
        let result = self
            .vault
            .dispatch_outbound_intent_with_verified_actor(
                request,
                &mut sink,
                self.actor,
                self.actor_class,
            )
            .map_err(facade_error_from_outbound_dispatch)?;

        // A denied schedule is fully audited by its Gate decision but never
        // becomes executable. Under the schedule-only Hold window, Held is the
        // sole outcome admitted to the durable queue.
        if result.outcome != OutboundDispatchOutcome::Held {
            return Ok(OutboundIntentReceipt {
                intent_ref: gate_intent_ref,
                outcome: dispatch_outcome_str(&result.outcome).to_owned(),
                gate_outcome: Some(result.gate_outcome),
                gate_decision_ref: result.gate_decision_id,
                gate_reason_codes: result.gate_reason_codes,
                deduped: false,
            });
        }

        let outcome = self.with_verified_actor_write_txn(|wtxn| {
            let outcome = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
                wtxn,
                EnqueueAttempt {
                    kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                    payload,
                    dedupe_key: draft.idempotency_key.clone(),
                    run_id: draft.job_ref.clone(),
                    now,
                },
                Some(task_ref.to_hex()),
                Some(dedupe_actor_ref.as_str()),
            )?;
            if matches!(&outcome, EnqueueOutcome::Enqueued(_)) {
                put_connector_send_task_in_txn(
                    self.vault,
                    wtxn,
                    task_ref,
                    &intent,
                    self.actor,
                    self.actor_class,
                    originating_session_ref.as_deref(),
                    schedule_context,
                    calendar_invite,
                    now,
                )?;
                // The SEQUENCE bump joins the SAME transaction as the ready
                // attempt and the connector TASK that will replay it. No
                // bumped sequence can survive without its frozen intent,
                // because both commit here or neither does.
                if let Some(admission) = invite_admission.as_ref() {
                    admission
                        .commit_in_txn(self.vault, wtxn, now)
                        .map_err(facade_error_from_calendar)?;
                }
            }
            Ok(outcome)
        })?;
        let attempt = match outcome {
            EnqueueOutcome::Enqueued(attempt) => attempt,
            EnqueueOutcome::Existing(attempt) => {
                return Ok(self.already_scheduled_outbound_receipt(attempt.id));
            }
        };
        let intent_ref = outbound_intent_ref(attempt.id);
        // Persist the gate surface keyed by attempt id so an idempotent replay
        // recovers this decision (best-effort; a missing binding degrades a
        // replay to no gate fields, never a wrong decision) (#484b).
        self.persist_outbound_gate_binding(
            attempt.id,
            &result.gate_outcome,
            result.gate_decision_id.as_deref(),
            &result.gate_reason_codes,
        );
        Ok(OutboundIntentReceipt {
            intent_ref,
            outcome: dispatch_outcome_str(&result.outcome).to_owned(),
            gate_outcome: Some(result.gate_outcome),
            gate_decision_ref: result.gate_decision_id,
            gate_reason_codes: result.gate_reason_codes,
            deduped: false,
        })
    }

    // ── calendar (CAL-09) ───────────────────────────────────────────────
}

/// Schedule-only execution sink: unreachable under the `Hold` window this
/// facade always dispatches with; fails closed if a future path ever
/// reaches it — the bridge carries no channel adapters (OF-327).
struct ScheduleOnlySink;

impl OutboundExecutionSink for ScheduleOnlySink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("bridge schedule-only surface has no channel adapter")
    }
}
