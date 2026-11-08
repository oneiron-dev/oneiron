//! `can({effect: {outbound_schedule}})`: the send a schedule would make,
//! judged read-only as its first executing admission judges it (FIX 22102).

use super::*;
use crate::gate::record_references::{
    ReferenceRefusal, invented_reference, peek_record_references, record_references_at,
};
use crate::memory::CanEffectAnswer;
use crate::verbs::OutboundScheduleRequest;

/// The record-ref slots `connector.outbound.schedule` declares (its row's
/// `refs`), read here as its generated fn reads them.
const OUTBOUND_SCHEDULE_REFS: &[&str] = &["/content_ref"];

impl Memory<'_> {
    /// The dated preflight of the send `connector.outbound.schedule` with
    /// `request` would schedule (C2:207, FIX 22102). It runs the row's
    /// record-ref check and the schedule's own request checks, builds the
    /// Gate input the real dispatch builds, and judges it on one read
    /// snapshot as the send's first executing admission judges it. It writes
    /// nothing: no TASK, queue attempt, Gate decision, receipt or clock
    /// floor, and it allocates no id. A delivered send is not replayed: a
    /// preflight judges a fresh send. The answer is dated, and the act is
    /// judged again when it runs.
    pub(in crate::memory) fn can_outbound_schedule(
        &self,
        request: &OutboundScheduleRequest,
    ) -> MemoryResult<CanEffectAnswer> {
        let (draft, continuation) = crate::verbs::outbound_schedule_parts(request.clone());
        let schedule_context = OutboundScheduleContext::default();
        // The row's record-ref check, read-only: each ref is read as the
        // writer's scoped read reads it, with no grant time persisted, so an
        // unresolved ref gets the same refusal and nothing is written, not
        // even a refusal receipt.
        let value = serde_json::to_value(request).map_err(|_| {
            MemoryError::bad_request("the verb input could not be read for the records it names")
        })?;
        let refs = record_references_at(&value, OUTBOUND_SCHEDULE_REFS);
        match peek_record_references(self, &refs) {
            Ok(()) => {}
            Err(ReferenceRefusal::Read(error)) => return Err(error),
            Err(ReferenceRefusal::Unresolved { pointer }) => {
                return Err(invented_reference(&pointer, false));
            }
        }

        admit_outbound_schedule(&draft, &schedule_context, None)?;
        let trigger = outbound_trigger(&draft)?;
        let originating_session_ref =
            (draft.trigger == "agent_immediate").then(|| draft.trigger_ref.clone());
        // The schedule's own time when it names one; else the recording time,
        // peeked without moving the clock floor.
        let now = match draft.occurred_at {
            Some(occurred_at) => occurred_at,
            None => {
                let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                crate::ports::job_recorded_at_in_txn(&self.vault.store, &txn)?
            }
        };
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        outbound_verb_contract(&draft.channel, &draft.verb)
            .map_err(|capability| facade_error_from_unsupported_capability(&capability))?;
        let intent = self.outbound_intent(&draft, trigger);

        // a send not yet scheduled has no TASK; the zero id, which no
        // allocated id equals, names it, so no one-shot press or override
        // bound to a real send matches it, and a standing grant, override or
        // envelope is judged as for any fresh send
        let task_ref = EntityId::from_bytes_unchecked([0; 16]);
        let gate_intent_ref = format!("intent:task:{}", task_ref.to_hex());
        let send = ScheduledSend {
            draft: &draft,
            schedule_context: &schedule_context,
            continuation: &continuation,
            calendar_invite: None,
            counterparty_ref: None,
            originating_session_ref: originating_session_ref.as_deref(),
            intent: &intent,
            task_ref,
            now,
        };
        let dispatch_request = self.scheduled_dispatch_request(&send, &gate_intent_ref);
        let (effect, payload) = crate::outbound::outbound_preflight_effect(
            self.vault,
            dispatch_request,
            (self.actor, self.actor_class),
        )
        .map_err(facade_error_from_outbound_dispatch)?;

        // One read snapshot for the actor recheck, the final posting check,
        // the policy and the judgment, as the admission writer's.
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        let posted = self
            .vault
            .space_posting_gate_in_txn(&txn, &payload, &effect)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)?;
        let at = crate::ports::job_recorded_at_in_txn(&self.vault.store, &txn)?;
        let judgment = crate::gate::judge_external_effect_in_txn(
            &self.vault.store,
            &txn,
            &posted,
            &policy,
            None,
            None,
            crate::gate::ApprovalContext::FirstAdmission,
            at,
            Some(at),
        )?;
        // The send's admission is the dispatch pipeline's: a Send-class
        // effect, through a transport that waits for a full count-bound
        // window.
        let budget = crate::gate::PreflightBudget {
            send_like: crate::outbound_intent_ledger::BudgetClass::Send.is_send(),
            paces: true,
            priced_tool: None,
        };
        let preflight =
            crate::gate::preflight_answer_in_txn(&self.vault.store, &txn, &judgment, budget, at)?;
        Ok(CanEffectAnswer::judged(preflight, at))
    }
}
