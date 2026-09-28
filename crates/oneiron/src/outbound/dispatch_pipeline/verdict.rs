//! Typed verdict from either the effect lane or the govern-only parked lane.
use crate::connector_key::EffectorBudgetCharge;
use crate::gate::GateOutcome;
use crate::outbound::dispatch_types::{OutboundDispatchOutcome, OutboundExecutionOutcome};
use crate::outbound_intent_ledger::{IntentResolution, IntentState};
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
}
