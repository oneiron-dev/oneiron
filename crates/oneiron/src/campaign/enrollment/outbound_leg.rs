//! Outward leg bridging persisted refs to the outbound chokepoint and the ledger.

use super::detection::{CampaignEnrollmentEvent, campaign_enrollment_event};
use super::home_node::{
    CampaignHomeNodeAdmission, CampaignHomeNodeDesignation, require_campaign_home_node,
};
use super::program::{CampaignProgramOutbound, CampaignProgramStep};
use super::runner::{
    decode_enrollment_attempt_payload, enrollment_consequence_id, resolve_program_step,
};
use super::storage::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND;
use crate::Vault;
use crate::attempt_queue::AttemptRecord;
use crate::error::Error;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundEffectError, OutboundTransport, PreparedAuthorization,
    PreparedEffect, execute_outbound_effect,
};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{BudgetClass, IntentDispatchResult};

/// What one run of the outward leg did.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentOutboundLeg {
    /// The effect reached the chokepoint; this is what came back.
    Dispatched(IntentDispatchResult),
    /// The program step declares no outward leg.
    NoOutboundStep,
    /// Another node holds the designation; nothing was sent.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No node holds it; nothing was sent.
    NoHomeNode,
}

/// Runs the outward leg for a claimed enrollment attempt.
///
/// A thin bridge, on purpose. It resolves the same persisted refs the
/// membership leg used, derives the call, and hands it to
/// `outbound_chokepoint::execute_outbound_effect` — the one production lane
/// that combines governance, budget, the ONE-1691 ledger, and transport. It
/// never touches a connector, never opens a second ledger, and never mints a
/// second idempotency scheme.
///
/// The leg is SELF-CONTAINED: it takes only the attempt record and the local
/// node, so a process that crashed after the cohort write and before the intent
/// record resumes by calling exactly this, and one that crashed after the send
/// replays the frozen bytes the ledger already holds.
///
/// Being self-contained is exactly why it re-reads the designation itself. A
/// node can apply the cohort row while designated, lose the designation, and
/// come back for the send — no caller sequencing survives a crash and a
/// handoff, so the leg that reaches TRANSPORT enforces the same leader-only
/// authority as the leg that reaches the vault.
///
/// # Errors
///
/// Gate, budget, ledger, and storage failures surface as
/// [`OutboundEffectError`].
// The host driver that pumps this queue is ONE-1778 surface work; until it
// lands the leg has only its oracle. Same posture `gate.rs` takes for the
// crate-visible effect surfaces it exposes ahead of their call sites.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn run_enrollment_outbound_leg<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    local_node_id: u64,
    attempt: &AttemptRecord,
    transport: &mut T,
    now_ms: u64,
) -> std::result::Result<EnrollmentOutboundLeg, OutboundEffectError> {
    if attempt.kind != CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND {
        return Err(OutboundEffectError::InvalidInput(
            "attempt kind is not campaign.enrollment.macro",
        ));
    }
    match require_campaign_home_node(vault, local_node_id)? {
        CampaignHomeNodeAdmission::Designated(_) => {}
        CampaignHomeNodeAdmission::NotHomeNode(designation) => {
            return Ok(EnrollmentOutboundLeg::NotHomeNode(designation));
        }
        CampaignHomeNodeAdmission::NoHomeNode => return Ok(EnrollmentOutboundLeg::NoHomeNode),
    }
    let payload = decode_enrollment_attempt_payload(&attempt.payload)?;
    let event = campaign_enrollment_event(vault, payload.membership_event_ref)?
        .ok_or(Error::EntityNotFound)?;
    let step = resolve_program_step(vault, &payload, &event)?;
    let Some(outbound) = step.outbound.as_ref() else {
        return Ok(EnrollmentOutboundLeg::NoOutboundStep);
    };
    let prepared = PreparedEffect {
        attempt_id: enrollment_consequence_id(&event, &step)?,
        call_seq: outbound.call_seq,
        server: step.channel.clone(),
        tool: outbound.verb.clone(),
        payload: outbound.payload.clone(),
        idempotency_supported: outbound.idempotency_supported,
        resolved_endpoint: None,
        gate: enrollment_gate_input(&step, outbound, &event),
        budget_class: BudgetClass::Send,
        authorization: PreparedAuthorization::None,
        verified_actor: None,
    };
    let result = execute_outbound_effect(
        vault,
        authority,
        OutboundEffectCommand::New(prepared),
        now_ms,
        transport,
    )?;
    Ok(EnrollmentOutboundLeg::Dispatched(result.dispatch))
}

/// Gate facts assembled from persisted rows only.
///
/// `has_opted_in`/`has_permission` report the program step's own consent basis
/// and sticky sender — a step cannot exist without both. They are ASSERTIONS
/// about persisted state, not a decision: the gate is still the authority, and
/// CA-06 owns tightening this posture.
#[cfg_attr(not(test), allow(dead_code))]
fn enrollment_gate_input(
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
    event: &CampaignEnrollmentEvent,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "agent".to_owned(),
            actor_ref: Some(step.sender_ref.to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(step.sender_ref),
            ..GateProvenanceHandles::default()
        },
        verb: outbound.verb.clone(),
        channel: step.channel.clone(),
        channel_identity_ref: None,
        counterparty: Some(event.entity_ref.to_hex()),
        brief_ref: Some(event.campaign_ref.to_hex()),
        send_ref: Some(event.event_ref.to_hex()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}
