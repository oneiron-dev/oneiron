//! Native identity frozen beside one campaign leg's transport envelope.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::gate::{
    ApprovalTarget, CampaignLegFacts, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles,
};
use crate::outbound_intent_ledger::{IntentLedgerError, IntentLedgerRecord};

/// The facts a ledger row cannot recover from its consequence and call
/// sequence alone. This is native frozen data, not a consent proof.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenCampaignLeg {
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
    epoch: u64,
    program_ref: EntityId,
    step_ref: EntityId,
    payload_digest: [u8; 32],
    sender_ref: EntityId,
}

impl FrozenCampaignLeg {
    pub(super) fn new(target: &CampaignLegFacts, sender_ref: EntityId) -> Self {
        Self {
            query_ref: target.query_ref,
            campaign_ref: target.campaign_ref,
            entity_ref: target.entity_ref,
            epoch: target.epoch,
            program_ref: target.program_ref,
            step_ref: target.step_ref,
            payload_digest: target.payload_digest,
            sender_ref,
        }
    }

    fn facts(&self, record: &IntentLedgerRecord) -> CampaignLegFacts {
        CampaignLegFacts {
            query_ref: self.query_ref,
            campaign_ref: self.campaign_ref,
            entity_ref: self.entity_ref,
            epoch: self.epoch,
            program_ref: self.program_ref,
            step_ref: self.step_ref,
            consequence_id: *record.attempt_id.as_bytes(),
            call_seq: record.call_seq,
            payload_digest: self.payload_digest,
        }
    }
}

/// The live leg and its frozen recomposer use the same native Gate facts.
pub(super) fn gate_input(
    target: CampaignLegFacts,
    sender_ref: EntityId,
    channel: &str,
    verb: &str,
    event_ref: &str,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "agent".to_owned(),
            actor_ref: Some(sender_ref.to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(sender_ref),
            approval_target: Some(ApprovalTarget::Campaign(target.clone())),
            ..GateProvenanceHandles::default()
        },
        verb: verb.to_owned(),
        channel: channel.to_owned(),
        // Campaign email keeps the existing actor assertion and cold-recipient
        // posture; this is not an identity or policy redesign (FIX 11641).
        channel_identity_ref: None,
        counterparty: Some(target.entity_ref.to_hex()),
        brief_ref: Some(target.campaign_ref.to_hex()),
        send_ref: Some(event_ref.to_owned()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
        send_autonomy: None,
    }
}

/// The leg's existing no-send outcomes under the send writer. These outcomes
/// are not errors: in particular, a home-node handoff must keep its lease.
pub(crate) enum CampaignLegReadiness {
    Unsupported,
    Ready,
    NotHomeNode(super::home_node::CampaignHomeNodeDesignation),
    NoHomeNode,
    MembershipNotReady,
    UnresolvableBody,
}

/// Rebuilds the exact native family-2 target. This is data, not consent or
/// send admission: inspecting an ask does not require being the home node.
pub(crate) fn frozen_campaign_effect(
    record: &IntentLedgerRecord,
) -> Result<Option<ExternalEffectGateInput>, IntentLedgerError> {
    Ok(frozen_campaign_input(record)?.map(|(_, gate)| gate))
}

fn frozen_campaign_input(
    record: &IntentLedgerRecord,
) -> Result<
    Option<(
        crate::campaign::sender::CampaignOutboundEnvelope,
        ExternalEffectGateInput,
    )>,
    IntentLedgerError,
> {
    let Ok(envelope) = crate::campaign::sender::decode_campaign_outbound_envelope(record.payload())
    else {
        return Ok(None);
    };
    let frozen = &envelope.campaign_leg;
    if super::runner::consequence_id(
        frozen.query_ref,
        frozen.entity_ref,
        frozen.epoch,
        frozen.campaign_ref,
        frozen.program_ref,
        frozen.step_ref,
    )? != record.attempt_id
    {
        return Ok(None);
    }
    let email_keys_match = match (
        record.server == crate::channel_identity_provider::EMAIL_CHANNEL,
        envelope.subject.as_ref(),
        envelope.composed_at,
        envelope.sender_ref.as_deref(),
    ) {
        (true, Some(_), Some(_), Some(sender)) => {
            EntityId::from_hex(sender).ok() == Some(frozen.sender_ref)
        }
        (false, None, None, None) => true,
        _ => false,
    };
    if !email_keys_match {
        return Ok(None);
    }
    let gate = gate_input(
        frozen.facts(record),
        frozen.sender_ref,
        &record.server,
        &record.tool,
        &envelope.trigger_ref,
    );
    Ok(Some((envelope, gate)))
}

/// Rechecks the existing native leg conditions in the actual send writer.
/// `local_node_id` is the live host's supplied node (or a true hostless
/// caller's actual persisted identity), never a designation or frozen send.
/// No identity is minted, no press is spent and no ask is queued here.
pub(crate) fn admit_frozen_campaign_leg_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &IntentLedgerRecord,
    local_node_id: u64,
) -> Result<CampaignLegReadiness, IntentLedgerError> {
    let Some((envelope, gate)) = frozen_campaign_input(record)? else {
        return Ok(CampaignLegReadiness::Unsupported);
    };
    let frozen = &envelope.campaign_leg;
    match super::home_node::require_campaign_home_node_in_txn(vault, txn, local_node_id)? {
        super::home_node::CampaignHomeNodeAdmission::Designated(_) => {}
        super::home_node::CampaignHomeNodeAdmission::NotHomeNode(designation) => {
            return Ok(CampaignLegReadiness::NotHomeNode(designation));
        }
        super::home_node::CampaignHomeNodeAdmission::NoHomeNode => {
            return Ok(CampaignLegReadiness::NoHomeNode);
        }
    }
    super::program::admit_campaign_leg_in_txn(vault, txn, &gate)?;
    if !super::runner::membership_sends_in_txn(vault, txn, frozen.entity_ref, frozen.campaign_ref) {
        return Ok(CampaignLegReadiness::MembershipNotReady);
    }
    let expected_artifact = crate::campaign::step_body::campaign_step_body_artifact_id(
        frozen.program_ref,
        frozen.step_ref,
        record.call_seq,
    )?;
    let expected_prefix = format!(
        "{}{}@",
        crate::campaign::step_body::CAMPAIGN_STEP_BODY_PREFIX,
        expected_artifact.to_hex(),
    );
    if !envelope.content_ref.starts_with(&expected_prefix) {
        return Ok(CampaignLegReadiness::UnresolvableBody);
    }
    let Some(body) = vault.campaign_step_body_text_in_txn(txn, &envelope.content_ref)? else {
        return Ok(CampaignLegReadiness::UnresolvableBody);
    };
    if super::approval::payload_digest(body.as_bytes(), envelope.subject.as_deref())
        != frozen.payload_digest
    {
        return Ok(CampaignLegReadiness::UnresolvableBody);
    }
    Ok(CampaignLegReadiness::Ready)
}
