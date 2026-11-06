//! The ordinary dispatch target frozen for its connector slate's one-send approval.

use serde::Deserialize;

use crate::calendar::CalendarInvitePayload;
use crate::consent::approval_proof::PinnedApprovalFamily;
use crate::entity_id::EntityId;
use crate::gate::{
    ApprovalTarget, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles, OutboundSendFacts,
};
use crate::outbound::capability::{normalize_key, outbound_verb_contract};

#[derive(Deserialize)]
struct FrozenDispatch {
    verb: String,
    channel: String,
    target: String,
    content_ref: Option<String>,
    job_ref: Option<String>,
    actor_class: String,
    actor_ref: Option<String>,
    actor_entity_ref: Option<String>,
    channel_identity_ref: Option<String>,
    counterparty_ref: Option<String>,
    /// The producer's native or member mail classification, frozen only
    /// when true (FIX 11869).
    #[serde(default)]
    native_mail_recipient: Option<bool>,
    approval_send_ref: Option<String>,
    linear_approval_send_ref: Option<String>,
    reply_thread_ref: Option<String>,
    calendar_invite: Option<CalendarInvitePayload>,
    has_opted_in: bool,
    has_permission: bool,
    policy_risk: String,
}

/// Rebuilds only the ordinary frozen send's approve-once composition. The
/// current admission still uses its original Gate input, not this snapshot.
/// Other payload formats and target families name no candidate here.
pub(crate) fn connector_slate_effect_from_frozen_payload(
    payload: &[u8],
    server: &str,
    tool: &str,
) -> Option<ExternalEffectGateInput> {
    let frozen: FrozenDispatch = serde_json::from_slice(payload).ok()?;
    if frozen.channel != server {
        return None;
    }
    let contract = outbound_verb_contract(&frozen.channel, &frozen.verb).ok()?;
    if contract.kind != tool {
        return None;
    }
    let entity = |value: Option<String>| -> Option<Option<EntityId>> {
        value
            .map(|hex| EntityId::from_hex(&hex).ok())
            .map_or(Some(None), |id| id.map(Some))
    };
    let actor_entity_ref = entity(frozen.actor_entity_ref)?;
    let sender = entity(frozen.channel_identity_ref)?;
    let connector = normalize_key(&frozen.channel);
    let (target, send_ref) = if connector == "linear" {
        // Only the native non-mirror producer freezes this reference. Its
        // presence proves which Linear target to reconstruct; an absent
        // mirror in an older payload would not prove mirror: None.
        let send_ref = frozen.linear_approval_send_ref?;
        let target = ApprovalTarget::LinearDispatch {
            verb: contract.kind.clone(),
            target: frozen.target.clone(),
            content_ref: frozen.content_ref.clone(),
            send_ref: send_ref.clone(),
            payload_digest: crate::outbound_intent_ledger::hash_frozen_payload(payload),
            mirror: None,
        };
        (target, send_ref)
    } else {
        let send_ref = frozen.approval_send_ref?;
        let target = ApprovalTarget::for_outbound(&OutboundSendFacts {
            connector: &connector,
            target: &frozen.target,
            sender,
            native_mail_recipient: frozen.native_mail_recipient == Some(true),
            thread_ref: frozen.reply_thread_ref.as_deref(),
            content_ref: frozen.content_ref.as_deref(),
            send_ref: &send_ref,
            calendar_invite: frozen.calendar_invite.as_ref(),
        })?;
        if target.pinned_family() != Some(PinnedApprovalFamily::ConnectorSlate) {
            return None;
        }
        (target, send_ref)
    };
    let policy_risk = if frozen.policy_risk == ExternalEffectPolicyRisk::Normal.as_str() {
        ExternalEffectPolicyRisk::Normal
    } else if frozen.policy_risk == ExternalEffectPolicyRisk::HoldToProposal.as_str() {
        ExternalEffectPolicyRisk::HoldToProposal
    } else {
        return None;
    };
    Some(ExternalEffectGateInput {
        actor: GateActor {
            actor_class: frozen.actor_class,
            actor_ref: frozen.actor_ref,
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref,
            mail_content_ref: frozen.content_ref,
            approval_target: Some(target),
            ..GateProvenanceHandles::default()
        },
        verb: contract.kind.clone(),
        channel: frozen.channel,
        channel_identity_ref: sender,
        counterparty: frozen.counterparty_ref.or(Some(frozen.target)),
        brief_ref: frozen.job_ref,
        send_ref: Some(send_ref),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: frozen.has_opted_in,
        has_permission: frozen.has_permission,
        policy_risk,
        send_autonomy: None,
    })
}
