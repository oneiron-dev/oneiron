//! Coded-reply ingress: ladder routing-table dispatch to promote, snooze, refer, exit, or suppress.

use super::ladder::{
    PromotionMode, ReplyCode, ReplyDisposition, StageLadderDefinition, transition_rule,
    validate_ladder,
};
use super::projector::{
    StageProjectResult, StageProjectorInput, StageRoute, project_stage_transition, stage_position,
};
use super::reentry::{
    MemberStateChange, ReentryPlan, WakeCondition, replace_member_state, snooze_with_wake,
};
use crate::campaign::claims::{CampaignMemberState, CrmStageValue, EvidenceBasis, StageKey};
use crate::{EntityId, Result, Vault};

/// An already-projected comm reply, coded.
///
/// CA-04 CONSUMES comm projection output. It adds no comm predicate and does not
/// touch the comm projector — `comm.rs` is SPINE-COMM's hot zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedCommReply {
    /// PERSON who replied.
    pub party_ref: EntityId,
    /// Campaign the reply belongs to.
    pub campaign_ref: EntityId,
    /// The live `campaign.member` head this reply acts on.
    pub membership_claim_ref: EntityId,
    /// The projected reply message; the evidence every promotion cites.
    pub message_ref: EntityId,
    /// Thread the reply sits in, preserved for copy/rendering consumers.
    pub thread_ref: Option<String>,
    /// The coded disposition.
    pub code: ReplyCode,
    /// When the reply arrived.
    pub occurred_at: u64,
}

// ---------------------------------------------------------------------------
// Coded replies
// ---------------------------------------------------------------------------

/// Applies one coded reply through the ladder's routing table.
///
/// The LADDER decides the disposition. A code with no row changes nothing, which
/// is a configuration statement rather than an error. Every promotion builds
/// CA-01's canonical [`CrmStageValue`] and routes it through
/// `project_stage_transition`; nothing here writes a `crm.stage` claim
/// directly.
///
/// # Errors
///
/// Propagates [`validate_ladder`], the projector, and the membership-state
/// door.
pub fn apply_coded_reply(
    vault: &Vault,
    definition: &StageLadderDefinition,
    reply: &CodedCommReply,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    validate_ladder(definition)?;
    let Some(route) = definition
        .reply_routes
        .iter()
        .find(|route| route.code == reply.code)
    else {
        return Ok(StageProjectResult::NoChange);
    };
    match &route.disposition {
        ReplyDisposition::Promote { stage } => {
            promote_from_reply(vault, definition, reply, stage, mode)
        }
        ReplyDisposition::Snooze => snooze_from_reply(vault, reply),
        ReplyDisposition::RouteReferral => Ok(StageProjectResult::Routed(StageRoute::Referral)),
        ReplyDisposition::RecordOnly => Ok(StageProjectResult::NoChange),
        ReplyDisposition::Exit => {
            set_member_state(vault, reply, CampaignMemberState::Exited)?;
            Ok(StageProjectResult::Routed(StageRoute::Exited))
        }
        ReplyDisposition::Suppress => {
            set_member_state(vault, reply, CampaignMemberState::Suppressed)?;
            Ok(StageProjectResult::Routed(StageRoute::Suppressed))
        }
    }
}

fn promote_from_reply(
    vault: &Vault,
    definition: &StageLadderDefinition,
    reply: &CodedCommReply,
    stage: &StageKey,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    let (previous_stage_claim_ref, from) =
        stage_position(vault, &reply.party_ref, &reply.campaign_ref)?;
    let Some(rule) = transition_rule(definition, from.as_ref(), stage) else {
        return Ok(StageProjectResult::NoChange);
    };
    project_stage_transition(
        vault,
        &StageProjectorInput {
            party_ref: reply.party_ref,
            previous_stage_claim_ref,
            value: CrmStageValue {
                campaign_ref: reply.campaign_ref,
                stage: stage.clone(),
                evidence_class: rule.evidence_class,
                evidence_refs: vec![reply.message_ref],
                basis: EvidenceBasis::Machine,
                recorded_at: reply.occurred_at,
            },
        },
        mode,
    )
}

/// A coded reply carries no clock, so the wake it can honestly write is the
/// trigger it can observe. A dated snooze enters through [`snooze_with_wake`].
fn snooze_from_reply(vault: &Vault, reply: &CodedCommReply) -> Result<StageProjectResult> {
    let plan = ReentryPlan {
        party_ref: reply.party_ref,
        campaign_ref: reply.campaign_ref,
        wake: WakeCondition::NewTrigger,
        restart_touch_index: 0,
        reason_evidence_ref: reply.message_ref,
        reentry_attempt: None,
    };
    snooze_with_wake(vault, &reply.membership_claim_ref, &plan, reply.occurred_at)?;
    Ok(StageProjectResult::Routed(StageRoute::Snoozed(plan)))
}

fn set_member_state(
    vault: &Vault,
    reply: &CodedCommReply,
    state: CampaignMemberState,
) -> Result<EntityId> {
    replace_member_state(
        vault,
        &MemberStateChange {
            membership_claim_ref: &reply.membership_claim_ref,
            party_ref: reply.party_ref,
            campaign_ref: reply.campaign_ref,
            state,
            evidence_ref: reply.message_ref,
            now: reply.occurred_at,
        },
    )
}
