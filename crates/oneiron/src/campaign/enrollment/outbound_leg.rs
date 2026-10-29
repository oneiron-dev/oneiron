//! Outward leg bridging persisted refs to the outbound chokepoint and the ledger.

use super::detection::{CampaignEnrollmentEvent, campaign_enrollment_event};
use super::home_node::{
    CampaignHomeNodeAdmission, CampaignHomeNodeDesignation, require_campaign_home_node,
};
use super::program::{CampaignProgramOutbound, CampaignProgramStep};
use super::runner::CampaignEnrollmentAttemptPayload;
use super::runner::{
    decode_enrollment_attempt_payload, enrollment_consequence_id, membership_sends,
    resolve_program_step,
};
use super::storage::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND;
use crate::Vault;
use crate::attempt_queue::AttemptRecord;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{
    ApprovalTarget, CampaignLegFacts, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles,
};
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundEffectError, OutboundEffectResult, OutboundTransport,
    PreparedAuthorization, PreparedEffect, execute_outbound_effect,
};
use crate::outbound_consent::{OutboundBindingAuthority, OutboundResultSender};
use crate::outbound_intent_ledger::{
    BudgetClass, FrozenOutboundCall, IntentLedgerError, OutboundSendOutcome, RemoteTaskHandle,
};

/// What one run of the outward leg did.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EnrollmentOutboundLeg {
    /// The effect reached the chokepoint; this is what came back, its Gate
    /// evidence and the approve-once digest a hold names included (FIX 6424
    /// part 2a).
    Dispatched(EnrollmentLegDispatch),
    /// The program step declares no outward leg.
    NoOutboundStep,
    /// Another node holds the designation; nothing was sent.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No node holds it; nothing was sent.
    NoHomeNode,
    /// The member's effective state is paused, suppressed or exited
    /// (FIX 9662), on a first run or a replay alike; nothing was sent.
    MembershipNotReady,
    /// The member does not resolve to a sendable target on the step's
    /// pinned channel and sender (FIX 11513 K12: a non-PERSON, a PERSON
    /// with no comm address, a sender that is not Active on this channel
    /// or may not send, or no live contact); nothing was sent.
    UnresolvableTarget,
    /// The step's filed body does not pin to the program row (FIX 11513
    /// K11: no filed body, or the blob's latest version runs ahead of the
    /// accepted row); nothing was sent.
    BodyUnpinned,
}

/// One outward leg's chokepoint result (FIX 6424 part 2a).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EnrollmentLegDispatch {
    /// The chokepoint's result: the dispatch, the Gate decision, its reasons
    /// and, while the Gate holds the call for a press, its `approval_digest`.
    pub(super) effect: OutboundEffectResult,
    /// The event row this call's prepared request was first asked under,
    /// retained before the chokepoint first took it; `None` when its
    /// retained request did not read or keep.
    pub(super) first_asked_event_ref: Option<EntityId>,
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
// The host drives it through [`drive_enrollment_outbound_leg`] (FIX 2636).
pub(super) fn run_enrollment_outbound_leg<T: OutboundTransport>(
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
    // The send waits on the member's own state, read now (FIX 9662): an
    // applied or replayed consequence never reaches a paused, suppressed or
    // exited member.
    if !membership_sends(vault, &event) {
        return Ok(EnrollmentOutboundLeg::MembershipNotReady);
    }
    // The send waits on a resolvable target (FIX 11513 K12): without one
    // there is no address to freeze, so the leg ends before the chokepoint
    // rather than minting an intent that can never send. Ids only: the
    // target address never reaches the log.
    let Some(target) =
        super::target::resolve_campaign_member_target(vault, event.entity_ref, &step)?
    else {
        tracing::warn!(
            event_ref = %event.event_ref.to_hex(),
            program_ref = %step.program_ref.to_hex(),
            step_ref = %step.step_ref.to_hex(),
            "a campaign enrollment's member does not resolve to a sendable target on the step's pinned channel; nothing is sent (FIX 11513 K12)"
        );
        return Ok(EnrollmentOutboundLeg::UnresolvableTarget);
    };
    // The send waits on the filed body pinning to the program row
    // (FIX 11513 K11): the blob's latest version can run ahead of the
    // accepted row, and then the send waits rather than carrying words the
    // program never accepted.
    let Some(content_ref) = vault.campaign_step_body_latest_ref_if_matches(
        step.program_ref,
        step.step_ref,
        outbound.call_seq,
        &outbound.payload,
    )?
    else {
        tracing::warn!(
            event_ref = %event.event_ref.to_hex(),
            program_ref = %step.program_ref.to_hex(),
            step_ref = %step.step_ref.to_hex(),
            "a campaign enrollment's filed body does not pin to its program row; nothing is sent (FIX 11513 K11)"
        );
        return Ok(EnrollmentOutboundLeg::BodyUnpinned);
    };
    // The wire payload is the v1 envelope the channel sender decodes with
    // `deny_unknown_fields`, never the raw body: exactly these five keys,
    // none of the chokepoint-sniffed ones (FIX 11513).
    let envelope = serde_json::json!({
        "target": target.target,
        "content_ref": content_ref,
        "counterparty_ref": target.party_key,
        "actor": event.owner_actor.to_hex(),
        "trigger_ref": event.event_ref.to_hex(),
    });
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        OutboundEffectError::InvalidInput("a campaign envelope is not JSON-encodable")
    })?;
    let consequence_id = enrollment_consequence_id(&event, &step)?;
    // FIX 6424 part 2a (Engine ruling 7): the request retained for this call
    // is read before its gate input is built; a new one is retained before
    // the chokepoint asks for it.
    let ask = super::approval::leg_ask(vault, &event, &step, outbound, consequence_id, true);
    let prepared = PreparedEffect {
        attempt_id: consequence_id,
        call_seq: outbound.call_seq,
        server: step.channel.clone(),
        tool: outbound.verb.clone(),
        payload: envelope_bytes,
        idempotency_supported: outbound.idempotency_supported,
        resolved_endpoint: None,
        gate: enrollment_gate_input(&step, outbound, &event, ask.target),
        budget_class: BudgetClass::Send,
        authorization: PreparedAuthorization::None,
        verified_actor: None,
        owner_proof: None,
        dedupe_key: None,
        suppression_receipt: None,
        admission_ceiling: None,
        co_actor: None,
    };
    let result = execute_outbound_effect(
        vault,
        authority,
        OutboundEffectCommand::New(prepared),
        now_ms,
        transport,
    )?;
    Ok(EnrollmentOutboundLeg::Dispatched(EnrollmentLegDispatch {
        effect: result,
        first_asked_event_ref: ask.first_event_ref,
    }))
}

/// What the host's drive of one attempt's outward leg came to (ONE-1778,
/// FIX 2636).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentLegDrive {
    /// The chokepoint took the call: it sent it, replayed the frozen bytes
    /// the ledger already holds, or settled it.
    Dispatched,
    /// The Gate holds the call for the owner's approve-once press on this
    /// digest (FIX 6424 part 2a); nothing went out.
    AwaitingApproval {
        /// The digest the press names, 64 lower-hex.
        approval_digest: String,
    },
    /// Nothing is owed outward: the step declares no outward leg, the
    /// member's own state holds the send, or the send does not resolve
    /// (an unresolvable member or an unpinned body, FIX 11513 K11/K12).
    NothingOwed,
    /// Another node holds the designation; nothing was sent.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No node holds it; nothing was sent.
    NoHomeNode,
}

/// Drives the outward leg of the claimed enrollment `attempt` through the
/// host's `sender` (ONE-1778, FIX 2636), after its membership leg applied.
/// The leg is the same self-contained bridge a crash resumes: the call's
/// identity is the consequence and the step's durable `call_seq`, so a
/// re-drive after a crash takes the stored intent and replays its frozen
/// bytes instead of freezing a second send. Consent and sender inputs are
/// the leg's own, unchanged.
///
/// # Errors
///
/// Gate, budget, ledger and storage failures, as the leg returns them.
pub fn drive_enrollment_outbound_leg<S: OutboundResultSender>(
    vault: &Vault,
    local_node_id: u64,
    attempt: &AttemptRecord,
    sender: &mut S,
    now_ms: u64,
) -> std::result::Result<EnrollmentLegDrive, IntentLedgerError> {
    let authority = OutboundBindingAuthority::for_vault(vault)?;
    let mut transport = SenderTransport(sender);
    Ok(
        match run_enrollment_outbound_leg(
            vault,
            &authority,
            local_node_id,
            attempt,
            &mut transport,
            now_ms,
        )? {
            EnrollmentOutboundLeg::Dispatched(dispatch) => match dispatch.effect.approval_digest {
                Some(approval_digest) => EnrollmentLegDrive::AwaitingApproval { approval_digest },
                None => EnrollmentLegDrive::Dispatched,
            },
            EnrollmentOutboundLeg::NoOutboundStep
            | EnrollmentOutboundLeg::MembershipNotReady
            | EnrollmentOutboundLeg::UnresolvableTarget
            | EnrollmentOutboundLeg::BodyUnpinned => EnrollmentLegDrive::NothingOwed,
            EnrollmentOutboundLeg::NotHomeNode(designation) => {
                EnrollmentLegDrive::NotHomeNode(designation)
            }
            EnrollmentOutboundLeg::NoHomeNode => EnrollmentLegDrive::NoHomeNode,
        },
    )
}

/// The host's result sender as the chokepoint's transport. The leg keeps no
/// result body, so only the send's outcome and its remote task pass through.
struct SenderTransport<'a, S>(&'a mut S);

impl<S: OutboundResultSender> OutboundTransport for SenderTransport<'_, S> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.0.send(call).outcome
    }

    fn remote_task(&self) -> Option<RemoteTaskHandle> {
        self.0.remote_task()
    }
}

/// FIX 6424 part 2a (Engine 10-20 21:0x ruling 1): the approve-once digest
/// an owner's press on `payload`'s outbound leg names, composed by the
/// Gate's own constructor over the gate input the leg builds from the same
/// persisted rows (the logical event, the program step, the consequence and
/// its call sequence, the frozen body), read against the request retained
/// for that call as the leg reads it. `None` when the step declares no
/// outward call. It reads and records nothing else.
///
/// # Errors
/// As the leg's own resolution of the refs: [`Error::EntityNotFound`] when
/// they do not resolve, [`Error::InvalidConfig`] when they do not cross-bind.
pub fn enrollment_outbound_approval_digest(
    vault: &Vault,
    payload: &CampaignEnrollmentAttemptPayload,
) -> crate::error::Result<Option<crate::consent::EffectDigest>> {
    let event = campaign_enrollment_event(vault, payload.membership_event_ref)?
        .ok_or(Error::EntityNotFound)?;
    let step = resolve_program_step(vault, payload, &event)?;
    let Some(outbound) = step.outbound.as_ref() else {
        return Ok(None);
    };
    let consequence_id = enrollment_consequence_id(&event, &step)?;
    let ask = super::approval::leg_ask(vault, &event, &step, outbound, consequence_id, false);
    let gate = enrollment_gate_input(&step, outbound, &event, ask.target);
    Ok(crate::gate::external_effect_approval_digest(&gate))
}

/// Gate facts assembled from persisted rows only.
///
/// `has_opted_in`/`has_permission` report the program step's own consent basis
/// and sticky sender — a step cannot exist without both. They are ASSERTIONS
/// about persisted state, not a decision: the gate is still the authority, and
/// CA-06 owns tightening this posture.
fn enrollment_gate_input(
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
    event: &CampaignEnrollmentEvent,
    target: CampaignLegFacts,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "agent".to_owned(),
            actor_ref: Some(step.sender_ref.to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(step.sender_ref),
            // FIX 6424 part 2a: a press pins this consequence's call.
            approval_target: Some(ApprovalTarget::Campaign(target)),
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
        send_autonomy: None,
    }
}
