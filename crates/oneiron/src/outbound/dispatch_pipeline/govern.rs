//! Gate input assembled from the canonical outbound request.
use crate::Vault;
use crate::consent::EffectDigest;
use crate::gate::{
    ApprovalTarget, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateProvenanceHandles,
    LinearMirrorFacts, OutboundSendFacts,
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
            approval_target: approval_target(request, &verb_contract.kind),
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
/// (never the counterparty alias), its logical send ref, and its family's
/// facts. A Linear send (part 2a) pins its canonical `verb`, its target and
/// content ref, its stable logical send ref, and the mirror operation's facts
/// only when the mirror door supplies them.
pub(super) fn approval_target(
    request: &OutboundDispatchRequest,
    verb: &str,
) -> Option<ApprovalTarget> {
    let connector = normalize_key(&request.intent.channel);
    if connector == LINEAR_CONNECTOR {
        return Some(ApprovalTarget::LinearDispatch {
            verb: verb.to_owned(),
            target: request.intent.target.clone(),
            content_ref: request.intent.content_ref.clone(),
            send_ref: stable_send_ref(request).to_owned(),
            mirror: request.linear_mirror.as_ref().map(LinearMirrorFacts::of),
        });
    }
    ApprovalTarget::for_outbound(&OutboundSendFacts {
        connector: &connector,
        target: &request.intent.target,
        sender: request.channel_identity_ref,
        thread_ref: request.reply_thread_ref.as_deref(),
        content_ref: request.intent.content_ref.as_deref(),
        send_ref: approval_send_ref(request, &connector),
        calendar_invite: request.calendar_invite.as_ref(),
    })
}

/// The connector a Linear issue mutation rides (FIX 6424 part 2a).
const LINEAR_CONNECTOR: &str = "linear";

/// FIX 6424 (Engine 10-20 20:4x): the logical send ref a press on `request`
/// pins. A family whose press is recomposed from its frozen ledger bytes
/// (e-sign, failure-signal batches) pins its send's stable identity: the
/// logical send a schedule's ask names, else
/// `ledger_identity_ref.unwrap_or(intent_ref)`, so a retry
/// that keeps its ledger identity under a new caller-facing intent ref
/// still matches its frozen payload and its press, and a scheduled ask pins
/// the send its executor spends. Every other family pins its intent ref,
/// the one a schedule's ask and its executor's spend share.
fn approval_send_ref<'r>(request: &'r OutboundDispatchRequest, connector: &str) -> &'r str {
    if !ApprovalTarget::freezes_send_ref_of(connector) {
        return &request.intent_ref;
    }
    stable_send_ref(request)
}

/// The send's stable logical identity: the logical send a schedule's ask
/// names, else its ledger identity, else its intent ref. A Linear send pins
/// it too (CALLS `FIX 6424 scheduled ask stable identity`), so a scheduled
/// ask and its executor's spend name one logical send.
fn stable_send_ref(request: &OutboundDispatchRequest) -> &str {
    request
        .approval_identity_ref
        .as_deref()
        .or(request.ledger_identity_ref.as_deref())
        .unwrap_or(&request.intent_ref)
}

/// FIX 6424 (Engine 10-20 20:4x): the approve-once digest an owner's
/// one-time press must name to release `request` once the Gate holds it,
/// composed by the Gate's own constructor over the request as the dispatch
/// pipeline prepares it: its canonical verb, the sender it resolves, and its
/// family's target and logical send ref. A held dispatch result, e-sign view
/// and schedule receipt carry the same digest as `approval_digest`; pass its
/// `to_hex()` as the press's `effect_digest`. `None` for a send whose family
/// does not pin its target: mail keeps its own canonical digest. A Linear
/// send's digest pins its stable logical send (FIX 6424 part 2a); the mirror
/// door's names its operation too, through `linear_mirror`, which the door
/// sets. A digest composed by hand from
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
    Ok(pinned_approval_digest(&outbound_gate_effect(
        vault, request,
    )?))
}

/// FIX 6679: `request`'s Gate input as the dispatch pipeline prepares it,
/// the one its approve-once digest and the Gate's decisions on it are
/// composed over, so a caller can tell the Gate's own decisions on exactly
/// this send ([`crate::gate::external_effect_decision_on`]). It reads and
/// records nothing else.
/// # Errors
/// As [`outbound_approve_once_digest`].
pub(crate) fn outbound_gate_effect(
    vault: &Vault,
    request: &OutboundDispatchRequest,
) -> Result<ExternalEffectGateInput, OutboundDispatchError> {
    let prepared = super::request_binding::PreparedOutboundDispatch::prepare(
        vault,
        request.clone(),
        None,
        None,
    )?;
    Ok(gate_input(
        &prepared.request,
        prepared.verb_contract,
        prepared.policy_risk,
    ))
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
/// press approved; a failure-signal batch freezes it whether or not it pins
/// (FIX 6679). `None` for every other send.
pub(super) fn frozen_approval_send_ref(request: &OutboundDispatchRequest) -> Option<&str> {
    let connector = normalize_key(&request.intent.channel);
    ApprovalTarget::freezes_send_ref_of(&connector).then(|| approval_send_ref(request, &connector))
}
