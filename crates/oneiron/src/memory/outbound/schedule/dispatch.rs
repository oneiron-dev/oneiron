//! The single outbound scheduling implementation behind every schedule door.
//! `Memory::schedule_outbound_inner` is its call surface.
//! `memory::outbound::schedule` defines `ScheduleOnlySink` and `BRIDGE_OUTBOUND_ATTEMPT_KIND`.

use super::*;

mod admission;
mod enqueue;
mod gate;
mod replay;

use self::admission::{admit_outbound_schedule, outbound_trigger};
use self::gate::{ScheduledSend, dispatch_receipt};

impl Memory<'_> {
    /// The single scheduling implementation.
    ///
    /// `calendar_invite` is CAL-04's typed payload channel: the invite surface
    /// is the only producer, and it is not reachable from the public draft type
    /// — which is exactly what keeps a hand-rolled `OutboundDraftInput` from
    /// scheduling an invite. Such a draft still resolves the registered
    /// capability, but it carries no five-field body, so the chokepoint's verb
    /// wall refuses it at the last durable boundary.
    ///
    /// `continuation` is what the TASK carries on beside the schedule
    /// context: the caller's deadline and the ambient alternative (FIX 7962,
    /// 8818).
    pub(in crate::memory::outbound) fn schedule_outbound_inner(
        &self,
        draft: &OutboundDraftInput,
        schedule_context: &OutboundScheduleContext,
        continuation: &crate::outbound::OutboundScheduleContinuation,
        calendar_invite: Option<&crate::calendar::CalendarInvitePayload>,
        counterparty_ref: Option<&str>,
    ) -> MemoryResult<(OutboundIntentReceipt, Option<EntityId>)> {
        admit_outbound_schedule(draft, schedule_context, counterparty_ref)?;
        let trigger = outbound_trigger(draft)?;
        let originating_session_ref =
            (draft.trigger == "agent_immediate").then(|| draft.trigger_ref.clone());
        let now = draft
            .occurred_at
            .unwrap_or_else(|| self.vault.store.clock.now_recorded_at());

        // A completed attempt no longer owns the generic queue dedupe row.
        // Consult the additive delivered-only index before any new gate or
        // enqueue work so a client retry cannot charge or send twice.
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if let Some(replayed) = self.replay_delivered_send(draft)? {
            return Ok(replayed);
        }

        // Pre-validate the channel/verb capability before either the gate or
        // durable enqueue, preserving a clean retry for malformed requests.
        outbound_verb_contract(&draft.channel, &draft.verb)
            .map_err(|capability| facade_error_from_unsupported_capability(&capability))?;

        let intent = self.outbound_intent(draft, trigger);

        let task_ref = self.vault.store.clock.entity_id()?;
        let payload = connector_send_attempt_payload(task_ref)?;
        // The queue's live-schedule dedupe is scoped by the BOUND EFFECT ACTOR
        // — never `on_behalf_of`, the target, the trigger, the TASK, or any
        // client-controlled content — matching the actor-scoped contract the
        // delivered-send index already keeps. Computed once so the abort-only
        // preflight and the durable enqueue below cannot disagree by a byte.
        let dedupe_actor_ref = self.actor.to_hex();

        let send = ScheduledSend {
            draft,
            schedule_context,
            continuation,
            calendar_invite,
            counterparty_ref,
            originating_session_ref: originating_session_ref.as_deref(),
            intent: &intent,
            task_ref,
            now,
        };
        // Abort-only enqueue preflight validates queue inputs and recovers an
        // existing live schedule without appending a second Gate decision. A
        // missing key writes only inside this uncommitted transaction and is
        // therefore neither durable nor claimable.
        let preflight = self.preflight_outbound_enqueue(&send, &payload, &dedupe_actor_ref)?;
        if let EnqueueOutcome::Existing(attempt) = preflight {
            return Ok((self.already_scheduled_outbound_receipt(attempt.id), None));
        }

        let gate_intent_ref = format!("intent:task:{}", task_ref.to_hex());
        let result = self.dispatch_outbound_schedule(&send, &gate_intent_ref)?;
        let sender_ref = result
            .receipt
            .fields
            .get("channel_identity_ref")
            .map(|value| EntityId::from_hex(value))
            .transpose()?;

        // A denied schedule is fully audited by its Gate decision but never
        // becomes executable. Under the schedule-only Hold window, Held is the
        // sole outcome admitted to the durable queue.
        if result.outcome != OutboundDispatchOutcome::Held {
            return Ok((dispatch_receipt(gate_intent_ref, result), sender_ref));
        }

        let outcome = self.with_verified_actor_write_txn(|wtxn| {
            self.enqueue_scheduled_send_in_txn(wtxn, &send, payload, &dedupe_actor_ref)
        })?;
        let attempt = match outcome {
            EnqueueOutcome::Enqueued(attempt) => attempt,
            EnqueueOutcome::Existing(attempt) => {
                return Ok((self.already_scheduled_outbound_receipt(attempt.id), None));
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
            result.approval_digest.as_deref(),
        );
        Ok((dispatch_receipt(intent_ref, result), sender_ref))
    }
}
