//! Membership-side writes: lane selection, snooze-with-wake pause, and the shared member-replacement helper.

use super::projector::{at, elapsed, evidence_value, invalid};
use crate::campaign::claims::{
    CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value, encode_campaign_member_value,
};
use crate::campaign::enrollment::{
    CampaignEnrollmentAttemptPayload, CampaignEnrollmentRunner, enrollment_dedupe_key,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::{EntityId, Result, Vault};

// ---------------------------------------------------------------------------
// Outreach lane selection
// ---------------------------------------------------------------------------

/// Why a membership exists, and what prior relationship it can honestly claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipProvenance {
    /// The `campaign.member` head this provenance describes.
    pub membership_claim_ref: EntityId,
    /// Evidence the enrolling trigger was derived from.
    pub trigger_evidence_refs: Vec<EntityId>,
    /// When the trigger was observed.
    pub trigger_observed_at: u64,
    /// A REAL prior thread, if one exists.
    pub prior_thread_ref: Option<String>,
    /// A REAL prior relationship evidence entity, if one exists.
    pub prior_relationship_evidence_ref: Option<EntityId>,
    /// When the last prior touch happened.
    pub prior_touch_at: Option<u64>,
}

/// Freshness horizons, supplied as policy data.
///
/// No universal business threshold is hard-coded: a consultancy's warm window
/// and a marketplace's are not the same number, and picking one here would make
/// the engine assert a market fact it has no evidence for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneClockPolicy {
    /// How long an enrolling trigger stays a live reason to reach out.
    pub trigger_fresh_for_secs: u64,
    /// How long a prior touch keeps a relationship warm.
    pub prior_touch_warm_for_secs: u64,
}

/// Which outreach lane a membership earns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutreachLane {
    /// No prior relationship this touch may claim.
    Cold,
    /// A real prior relationship, with the reference that proves it preserved
    /// for copy and rendering consumers.
    WarmReconnect {
        /// The prior thread, when one exists.
        thread_ref: Option<String>,
        /// The prior relationship evidence, when one exists.
        relationship_evidence_ref: Option<EntityId>,
    },
}

/// Chooses the outreach lane for one membership. Writes nothing.
///
/// This is where "member (cold)" stops. A match plus provenance picks a LANE; it
/// does not create a pipeline head, because nothing here is transition evidence.
///
/// [`OutreachLane::WarmReconnect`] requires a REAL prior reference — a non-blank
/// thread or a relationship evidence entity. An assertion with no reference
/// behind it falls back to [`OutreachLane::Cold`], and the surviving reference
/// rides the lane so copy and rendering consume the same evidence the decision
/// was made on.
///
/// Both policy horizons are load-bearing: a warm reconnect needs a live reason
/// to reconnect (a stale trigger is cold prospecting again) and a prior touch
/// that is still inside the warm window. An untimestamped prior touch is carried
/// by the reference alone rather than being guessed stale.
#[must_use]
pub fn route_membership_lane(
    provenance: &MembershipProvenance,
    policy: LaneClockPolicy,
    now: u64,
) -> OutreachLane {
    let thread_ref = provenance
        .prior_thread_ref
        .as_deref()
        .map(str::trim)
        .filter(|thread| !thread.is_empty());
    let relationship_evidence_ref = provenance.prior_relationship_evidence_ref;
    if thread_ref.is_none() && relationship_evidence_ref.is_none() {
        return OutreachLane::Cold;
    }
    if elapsed(now, provenance.trigger_observed_at) > policy.trigger_fresh_for_secs {
        return OutreachLane::Cold;
    }
    if provenance
        .prior_touch_at
        .is_some_and(|at| elapsed(now, at) > policy.prior_touch_warm_for_secs)
    {
        return OutreachLane::Cold;
    }
    OutreachLane::WarmReconnect {
        thread_ref: thread_ref.map(str::to_owned),
        relationship_evidence_ref,
    }
}

// ---------------------------------------------------------------------------
// Re-entry
// ---------------------------------------------------------------------------

/// When a paused membership wakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeCondition {
    /// At a deadline.
    At(u64),
    /// When a new trigger arrives.
    NewTrigger,
    /// At the deadline OR on a new trigger, whichever comes first.
    AtOrNewTrigger {
        /// The deadline half.
        at: u64,
    },
}

/// One snooze-with-wake re-entry directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReentryPlan {
    /// PERSON being paused.
    pub party_ref: EntityId,
    /// Campaign the pause is scoped to.
    pub campaign_ref: EntityId,
    /// The wake condition written onto the `campaign.member` head.
    pub wake: WakeCondition,
    /// Always 0: restart at touch 1.
    pub restart_touch_index: u32,
    /// The NEW reason this re-entry exists. Retained, never inferred.
    pub reason_evidence_ref: EntityId,
    /// The CA-03 attempt this re-entry re-runs at touch 1, when the caller holds
    /// the program refs.
    ///
    /// `None` pauses without queueing: the wake condition still lands on the
    /// membership head, and a caller that later resolves the program enqueues
    /// through this same door. The three refs cannot be derived here — CA-03's
    /// enqueue takes `{membership_event_ref, campaign_program_ref,
    /// program_step_ref}` and no campaign-to-program index exists — so they ride
    /// the plan rather than being invented.
    pub reentry_attempt: Option<CampaignEnrollmentAttemptPayload>,
}

// ---------------------------------------------------------------------------
// Snooze with wake
// ---------------------------------------------------------------------------

/// Pauses one membership with a wake condition, and requests re-entry.
///
/// The membership head is superseded with CA-01's exact `campaign.member` value
/// carrying `paused { until?, new_trigger? }` — at least one field always set,
/// and [`WakeCondition::AtOrNewTrigger`] setting both. The existing channel rows
/// (each with its consent basis and sticky sender) and any derivation are
/// carried across: a pause changes state, it does not erase how the membership
/// got there or what authorized the contact.
///
/// Re-entry rides CA-03's EXISTING `campaign.enrollment.macro` enqueue surface.
/// No timer, recurrence primitive, or attempt kind is minted here. The attempt
/// is vetted through CA-03's own dedupe door BEFORE the pause is written, so an
/// unresolvable membership event is refused with nothing half-applied.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the plan does not restart at touch 1, when
/// the named claim is not a live `campaign.member` head, or when its subject or
/// campaign disagrees with the plan. [`Error::EntityNotFound`] from CA-03 for an
/// unresolvable re-entry attempt. Claim-validation, queue, and storage errors
/// propagate.
pub fn snooze_with_wake(
    vault: &Vault,
    membership_claim_ref: &EntityId,
    plan: &ReentryPlan,
    now: u64,
) -> Result<EntityId> {
    if plan.restart_touch_index != 0 {
        return Err(invalid("campaign re-entry restarts at touch 1"));
    }
    if let Some(attempt) = &plan.reentry_attempt {
        enrollment_dedupe_key(vault, attempt)?;
    }
    let new_id = replace_member_state(
        vault,
        &MemberStateChange {
            membership_claim_ref,
            party_ref: plan.party_ref,
            campaign_ref: plan.campaign_ref,
            state: paused_state(&plan.wake),
            evidence_ref: plan.reason_evidence_ref,
            now,
        },
    )?;
    if let Some(attempt) = &plan.reentry_attempt {
        CampaignEnrollmentRunner::new(vault).enqueue(attempt, None, now)?;
    }
    Ok(new_id)
}

fn paused_state(wake: &WakeCondition) -> CampaignMemberState {
    match *wake {
        WakeCondition::At(until) => CampaignMemberState::Paused {
            until: Some(until),
            new_trigger: None,
        },
        WakeCondition::NewTrigger => CampaignMemberState::Paused {
            until: None,
            new_trigger: Some(true),
        },
        WakeCondition::AtOrNewTrigger { at } => CampaignMemberState::Paused {
            until: Some(at),
            new_trigger: Some(true),
        },
    }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// One replacement of a live `campaign.member` head.
pub(super) struct MemberStateChange<'a> {
    pub(super) membership_claim_ref: &'a EntityId,
    pub(super) party_ref: EntityId,
    pub(super) campaign_ref: EntityId,
    pub(super) state: CampaignMemberState,
    pub(super) evidence_ref: EntityId,
    pub(super) now: u64,
}

/// Writes a replacement `campaign.member` head carrying a new STATE and
/// supersedes the head it replaces, in one transaction.
///
/// The replacement is built from the head it replaces, so channels and any
/// derivation survive. The identity checks run inside the same txn as the write:
/// a claim that is not this party's live membership in this campaign is rejected
/// before anything lands.
pub(super) fn replace_member_state(
    vault: &Vault,
    change: &MemberStateChange<'_>,
) -> Result<EntityId> {
    let new_id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        let value = require_member_head(vault, wtxn, change)?;
        let replacement = CampaignMemberValue {
            state: change.state,
            ..value
        };
        let mut body = ClaimBody::new(
            PREDICATE_CAMPAIGN_MEMBER,
            ClaimSubject::Entity(change.party_ref),
            encode_campaign_member_value(&replacement),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(evidence_value(&[change.evidence_ref]));
        vault.put_claim_in_txn(wtxn, &new_id, &body, at(change.now), change.now)?;
        vault.supersede_claim_in_txn(wtxn, &new_id, change.membership_claim_ref, change.now)
    })?;
    Ok(new_id)
}

pub(super) fn require_member_head(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    change: &MemberStateChange<'_>,
) -> Result<CampaignMemberValue> {
    let body = vault
        .get_claim_in_txn(wtxn, change.membership_claim_ref)?
        .ok_or(invalid("campaign.member head is missing"))?;
    if body.predicate != PREDICATE_CAMPAIGN_MEMBER || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(invalid("claim is not a live campaign.member head"));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid("campaign.member subject must be an entity"));
    };
    if subject != change.party_ref {
        return Err(invalid("campaign.member subject mismatch"));
    }
    let value = decode_campaign_member_value(&body.value)?;
    if value.campaign != change.campaign_ref {
        return Err(invalid("campaign.member campaign mismatch"));
    }
    Ok(value)
}
