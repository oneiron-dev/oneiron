//! Gate input assembled from the canonical outbound request.
use crate::gate::{ExternalEffectGateInput, ExternalEffectPolicyRisk, GateProvenanceHandles};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::OutboundDispatchRequest;

pub(super) fn gate_input(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    policy_risk: ExternalEffectPolicyRisk,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: request.actor.gate_actor(),
        provenance: GateProvenanceHandles {
            mail_content_ref: request.intent.content_ref.clone(),
            ..request.actor.provenance()
        },
        verb: verb_contract.kind.clone(),
        channel: request.intent.channel.clone(),
        channel_identity_ref: request.channel_identity_ref,
        counterparty: request
            .counterparty_ref
            .clone()
            .or_else(|| Some(request.intent.target.clone())),
        brief_ref: request.intent.job_ref.clone(),
        send_ref: Some(request.intent_ref.clone()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: request.gate.has_opted_in,
        has_permission: request.gate.has_permission,
        policy_risk,
    }
}
