//! A schedule's intent, its abort-only enqueue preflight, and its one Gate dispatch.

use super::*;

/// A schedule past its replay and capability checks: the door's inputs, its
/// TASK id, its frozen intent and its clock.
pub(super) struct ScheduledSend<'a> {
    pub(super) draft: &'a OutboundDraftInput,
    pub(super) schedule_context: &'a OutboundScheduleContext,
    pub(super) continuation: &'a OutboundScheduleContinuation,
    pub(super) calendar_invite: Option<&'a crate::calendar::CalendarInvitePayload>,
    pub(super) counterparty_ref: Option<&'a str>,
    pub(super) originating_session_ref: Option<&'a str>,
    pub(super) intent: &'a OutboundIntent,
    pub(super) task_ref: EntityId,
    pub(super) now: u64,
}

impl Memory<'_> {
    /// The intent the draft asks for, from the bound actor.
    pub(super) fn outbound_intent(
        &self,
        draft: &OutboundDraftInput,
        trigger: OutboundIntentTrigger,
    ) -> OutboundIntent {
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
        if let Some(mention) = &draft.mention {
            intent_draft = intent_draft.mention(mention.clone());
        }
        OutboundIntent::from_trigger(intent_draft, trigger)
    }

    /// Abort-only enqueue preflight validates queue inputs and recovers an
    /// existing live schedule without appending a second Gate decision. A
    /// missing key writes only inside this uncommitted transaction and is
    /// therefore neither durable nor claimable.
    pub(super) fn preflight_outbound_enqueue(
        &self,
        send: &ScheduledSend<'_>,
        payload: &[u8],
        dedupe_actor_ref: &str,
    ) -> MemoryResult<EnqueueOutcome> {
        let mut preflight_txn = self.vault.store.env.write_txn()?;
        verify_actor_binding_in_txn(self.vault, &preflight_txn, self.actor, self.actor_class)?;
        let preflight = crate::ports::JobQueue::port_job_enqueue_scoped(
            self.vault,
            &mut preflight_txn,
            EnqueueAttempt {
                kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                payload: payload.to_vec(),
                dedupe_key: send.draft.idempotency_key.clone(),
                run_id: send.draft.job_ref.clone(),
                now: send.now,
            },
            crate::ports::JobScope {
                task_ref: None,
                dedupe_actor_ref: Some(dedupe_actor_ref),
            },
        )?;
        drop(preflight_txn);
        Ok(preflight)
    }

    /// The schedule's one Gate decision, under the schedule-only Hold window.
    pub(super) fn dispatch_outbound_schedule(
        &self,
        send: &ScheduledSend<'_>,
        gate_intent_ref: &str,
    ) -> MemoryResult<crate::outbound::OutboundDispatchResult> {
        let actor = OutboundDispatchActor {
            actor_class: self.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            actor_entity_ref: Some(self.actor),
        };
        let mut request = OutboundDispatchRequest::new(
            format!("outbound:{gate_intent_ref}"),
            gate_intent_ref.to_owned(),
            send.intent.clone(),
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            send.now,
            OutboundDeliveryWindowDecision::Hold {
                reason: "bridge_scheduled".to_owned(),
                retry_at: None,
            },
        );
        if let Some(session_ref) = send.originating_session_ref {
            request = request.originating_session(session_ref);
        }
        if let Some(party) = send.counterparty_ref {
            request = request.counterparty_ref(party);
        }
        if let Some(payload) = send.calendar_invite {
            request = request.calendar_invite(payload.clone());
        }
        // FIX 6424: the ask names the logical send the executor will run
        // this TASK under, so a press on it pins the send that spends it.
        request.approval_identity_ref = Some(crate::outbound::connector_logical_send_ref(
            self.actor,
            send.intent.idempotency_key.as_deref(),
            send.task_ref,
        ));
        let mut sink = ScheduleOnlySink;
        self.vault
            .dispatch_outbound_intent_with_verified_actor(
                request,
                &mut sink,
                self.actor,
                self.actor_class,
            )
            .map_err(facade_error_from_outbound_dispatch)
    }
}

/// The receipt a Gate dispatch earns, under the intent ref it names.
pub(super) fn dispatch_receipt(
    intent_ref: String,
    result: crate::outbound::OutboundDispatchResult,
) -> OutboundIntentReceipt {
    OutboundIntentReceipt {
        intent_ref,
        outcome: dispatch_outcome_str(&result.outcome).to_owned(),
        gate_outcome: Some(result.gate_outcome),
        gate_decision_ref: result.gate_decision_id,
        gate_reason_codes: result.gate_reason_codes,
        approval_digest: result.approval_digest,
        deduped: false,
    }
}
