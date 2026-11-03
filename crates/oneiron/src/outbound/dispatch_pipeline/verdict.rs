//! Typed verdict from either the effect lane or the govern-only parked lane.
use crate::connector_key::EffectorBudgetCharge;
use crate::gate::GateOutcome;
use crate::outbound::dispatch_types::{OutboundDispatchOutcome, OutboundExecutionOutcome};
use crate::outbound_intent_ledger::{
    IntentResolution, IntentState, ProviderRetryDirective, ReservationStatus,
};
use crate::receipt::ReceiptRecord;

pub(in crate::outbound) struct DispatchVerdict {
    pub(in crate::outbound) gate_decision_ref: Option<String>,
    pub(in crate::outbound) gate_outcome: GateOutcome,
    pub(in crate::outbound) gate_reason_codes: Vec<String>,
    pub(in crate::outbound) gate_receipt_reasons: Vec<String>,
    pub(in crate::outbound) effector_charge: Option<EffectorBudgetCharge>,
    pub(in crate::outbound) effect_state: Option<IntentState>,
    pub(in crate::outbound) resolution: Option<IntentResolution>,
    pub(in crate::outbound) outcome: OutboundDispatchOutcome,
    pub(in crate::outbound) execution: Option<OutboundExecutionOutcome>,
    pub(in crate::outbound) suppression_receipt: Option<ReceiptRecord>,
    /// The count a seat ceiling held this send at, read under the admission
    /// writer lock. The pipeline folds it into the seat decision the receipt
    /// carries.
    pub(in crate::outbound) ceiling_count: Option<u32>,
    /// FIX 6424 part 2a: the approve-once digest the holding Gate decision
    /// names, as the chokepoint composed it over the input that decision
    /// evaluated (a co-actor's, when the co-actor held the send).
    pub(in crate::outbound) held_approval_digest: Option<String>,
    /// The actor whose decision named `held_approval_digest`.
    pub(in crate::outbound) held_approval_actor: Option<crate::entity_id::EntityId>,
    /// The provider wait the ledger keeps for this send (FIX 8818).
    pub(in crate::outbound) provider_wait: Option<ProviderRetryDirective>,
    /// The provider's edge, when that wait held this dispatch and nothing
    /// was sent.
    pub(in crate::outbound) provider_wait_held_until: Option<u64>,
    /// The instant a full window paces this unsent send until (FIX 7948,
    /// FIX 8788): it comes back then.
    pub(in crate::outbound) paced_until: Option<u64>,
    /// Where this send's reserved budget stands (FIX 7964).
    pub(in crate::outbound) budget_reservation: Option<ReservationStatus>,
}
