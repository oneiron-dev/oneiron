//! Gate input assembled from the canonical outbound request.
use crate::Vault;
use crate::consent::EffectDigest;
use crate::gate::{
    ApprovalTarget, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateProvenanceHandles,
    OutboundSendFacts,
};
use crate::outbound::capability::{OutboundVerbContract, normalize_key};
use crate::outbound::dispatch_types::{OutboundDispatchError, OutboundDispatchRequest};

pub(super) fn gate_input(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    policy_risk: ExternalEffectPolicyRisk,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: request.actor.gate_actor(),
        provenance: GateProvenanceHandles {
            mail_content_ref: request.intent.content_ref.clone(),
            approval_target: approval_target(request),
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
        send_autonomy: request.send_autonomy.clone(),
    }
}

/// FIX 6424: the one send an owner's approve-once press on `request`
/// approves, read off the canonical request: its original transport target
/// (never the counterparty alias), its intent ref, and its family's facts.
pub(super) fn approval_target(request: &OutboundDispatchRequest) -> Option<ApprovalTarget> {
    ApprovalTarget::for_outbound(&OutboundSendFacts {
        connector: &normalize_key(&request.intent.channel),
        target: &request.intent.target,
        sender: request.channel_identity_ref,
        thread_ref: request.reply_thread_ref.as_deref(),
        content_ref: request.intent.content_ref.as_deref(),
        send_ref: &request.intent_ref,
        calendar_invite: request.calendar_invite.as_ref(),
    })
}

/// FIX 6424 (Engine 10-20 20:4x): the approve-once digest an owner's
/// one-time press must name to release `request` once the Gate holds it,
/// composed by the Gate's own constructor over the request as the dispatch
/// pipeline prepares it: its canonical verb, the sender it resolves, and its
/// family's target and logical send ref. A held dispatch result, e-sign view
/// and schedule receipt carry the same digest as `approval_digest`; pass its
/// `to_hex()` as the press's `effect_digest`. `None` for a send whose family
/// does not pin its target: mail keeps its own canonical digest, and Linear
/// is FIX 6424's second part. A digest composed by hand from
/// [`crate::consent::EffectFacts`] with no target releases none of these
/// families' sends. It reads and records nothing else.
/// # Errors
/// The request's own refusal at preparation (an unknown channel or verb, an
/// off-record session, an unsettled mention, a sender or replay that does
/// not match its admitted binding), or a storage failure.
pub fn outbound_approve_once_digest(
    vault: &Vault,
    request: &OutboundDispatchRequest,
) -> Result<Option<EffectDigest>, OutboundDispatchError> {
    let prepared = super::request_binding::PreparedOutboundDispatch::prepare(
        vault,
        request.clone(),
        None,
        None,
    )?;
    Ok(pinned_approval_digest(&gate_input(
        &prepared.request,
        prepared.verb_contract,
        prepared.policy_risk,
    )))
}

/// FIX 6424: the approve-once digest a held `effect` names, 64 lower-hex,
/// the one the Gate's spend lookup composes; `None` for an effect whose
/// family pins no target.
pub(super) fn approval_digest(effect: &ExternalEffectGateInput) -> Option<String> {
    pinned_approval_digest(effect).map(|digest| digest.to_hex())
}

fn pinned_approval_digest(effect: &ExternalEffectGateInput) -> Option<EffectDigest> {
    effect.provenance.approval_target.as_ref()?;
    crate::gate::external_effect_approval_digest(effect)
}

/// FIX 6424: the send ref `request`'s frozen payload carries, for a family
/// whose admitted press is recomposed from those bytes, so the ledger's
/// proof check, a retry and a delivery's link mint recompose the digest the
/// press approved. `None` for every other send.
pub(super) fn frozen_approval_send_ref(request: &OutboundDispatchRequest) -> Option<&str> {
    approval_target(request)
        .is_some_and(|target| target.freezes_send_ref())
        .then_some(request.intent_ref.as_str())
}
