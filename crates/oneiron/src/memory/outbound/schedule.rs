//! Schedule-only dispatch of connector sends through the OF-327 chokepoint.

use super::super::support::{Memory, verify_actor_binding, verify_actor_binding_in_txn};
use super::super::{MemoryError, MemoryResult};
use super::dedupe::outbound_intent_ref;
use super::errors::{
    dispatch_outcome_str, facade_error_from_calendar, facade_error_from_outbound_dispatch,
};
use super::types::{OutboundDraftInput, OutboundIntentReceipt, OutboundScheduleContext};
use crate::attempt_queue::{EnqueueAttempt, EnqueueOutcome};

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

mod dispatch;

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
        self.schedule_outbound_inner(draft, schedule_context, None, None)
            .map(|(receipt, _)| receipt)
    }

    /// Returns the sender recorded by the real outbound admission.
    pub(crate) fn schedule_human_followup(
        &self,
        draft: &OutboundDraftInput,
    ) -> MemoryResult<(OutboundIntentReceipt, Option<EntityId>)> {
        self.schedule_outbound_inner(draft, &OutboundScheduleContext::default(), None, None)
    }

    /// Schedules a communication addressed to an explicit counterparty.
    /// The transport target may be a shared channel or handle; it is never
    /// inferred to be a PERSON. A missing binding on the ordinary schedule
    /// path leaves `comm.last_touch` unchanged after delivery.
    pub fn schedule_outbound_for_counterparty(
        &self,
        draft: &OutboundDraftInput,
        counterparty_ref: &str,
    ) -> MemoryResult<OutboundIntentReceipt> {
        self.schedule_outbound_with_context_for_counterparty(
            draft,
            &OutboundScheduleContext::default(),
            counterparty_ref,
        )
    }

    /// The clock-aware form of [`Self::schedule_outbound_for_counterparty`].
    pub fn schedule_outbound_with_context_for_counterparty(
        &self,
        draft: &OutboundDraftInput,
        schedule_context: &OutboundScheduleContext,
        counterparty_ref: &str,
    ) -> MemoryResult<OutboundIntentReceipt> {
        self.schedule_outbound_inner(draft, schedule_context, None, Some(counterparty_ref))
            .map(|(receipt, _)| receipt)
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
