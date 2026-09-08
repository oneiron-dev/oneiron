//! Pending gate-outcome name and gate-vs-manifest policy-risk resolution.
use crate::gate::ExternalEffectPolicyRisk;
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::{OutboundDispatchGate, OutboundDispatchPolicyRisk};
/// The `gate_outcome` value naming a send parked on a human decision.
pub(crate) const GATE_OUTCOME_PENDING: &str = "pending";
pub(super) fn outbound_dispatch_policy_risk(
    gate: OutboundDispatchGate,
    verb_contract: &OutboundVerbContract,
) -> ExternalEffectPolicyRisk {
    if gate.policy_risk == OutboundDispatchPolicyRisk::HoldToProposal
        || verb_contract.capability_vs_permission.policy_risk
    {
        ExternalEffectPolicyRisk::HoldToProposal
    } else {
        gate.policy_risk.to_gate()
    }
}
