//! CA-04 stage-ladder machinery: the mechanism, never the content.
//!
//! This module owns the pure ladder schema, coded-reply routing, evidence
//! validation, the AUTO/propose dial, the ordered `crm.stage` projector,
//! warm/cold lane selection, calendar-outcome consumption, no-show recovery
//! directives, and snooze-with-wake re-entry. It owns nothing else: send
//! execution, calendar ingestion, payment truth, delivery truth, and preset
//! content all stay with their existing owners.
//!
//! Four laws shape every function here.
//!
//! 1. **`member (cold)` is not a `crm.stage`.** A query match plus
//!    `campaign.member` provenance may choose a cold or warm-reconnect outreach
//!    lane ([`route_membership_lane`]), but it never creates a pipeline head.
//!    The first stage head is earned only when a configured transition's
//!    evidence lands.
//! 2. **Default promotion is AUTO.** [`PromotionMode::Propose`] is an optional
//!    dial a caller may pass, not an approval wall this layer inserts. Every
//!    accepted transition carries non-empty evidence references and a named
//!    evidence class.
//! 3. **`crm.stage` is projector-only.** [`project_stage_transition`] is the
//!    single writer; [`apply_coded_reply`], [`apply_event_outcome`], and
//!    [`apply_external_stage_evidence`] build CA-01's canonical
//!    [`CrmStageValue`] and route it through that door. None of them puts or
//!    supersedes a `crm.stage` claim directly, and the replacement write plus
//!    the prior head's supersession share ONE transaction via CA-01's
//!    [`supersede_crm_stage_in_txn`].
//! 4. **Silence is never `held`.** Calendar outcomes are a READ-side
//!    dependency: CAL-07's `read_event_outcome` answers `None` for silence,
//!    which projects to Unknown and can never become `Held`.
//!
//! Ownership is deliberately thin. `CrmStageValue`, `StageKey`,
//! `StageEvidenceClass`, `EvidenceBasis`, the `campaign.member` value, their
//! codecs, and the in-transaction supersession helper all belong to
//! [`crate::campaign::claims`] (CA-01) and are IMPORTED, never re-spelled.
//! `EventOutcome` and `EventOutcomeClaimValue` belong to
//! [`crate::calendar::outcome`] (CAL-07). The `campaign.enrollment.macro`
//! attempt kind and its enqueue surface belong to
//! [`crate::campaign::enrollment`] (CA-03). This module mints no entity byte, no
//! registry row, no timer, no recurrence primitive, and no attempt kind.
//!
//! Stage KEYS are data. ONE-1779 supplies the consultancy preset that
//! instantiates [`StageLadderDefinition`]; no consultancy stage name is spelled
//! in this file, including at the owner-attestation boundary (see
//! [`require_owner_attestable`]).

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::calendar::claims::decode_event_outcome_value;
use crate::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME,
    read_event_outcome,
};
use crate::campaign::claims::{
    CampaignMemberState, CampaignMemberValue, CrmStageValue, EvidenceBasis,
    PREDICATE_CAMPAIGN_MEMBER, PREDICATE_CRM_STAGE, StageEvidenceClass, StageKey,
    decode_campaign_member_value, decode_crm_stage_value, encode_campaign_member_value,
    encode_crm_stage_value, supersede_crm_stage_in_txn,
};
use crate::campaign::enrollment::{
    CampaignEnrollmentAttemptPayload, CampaignEnrollmentRunner, enrollment_dedupe_key,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    claim_surfaceable,
};
use crate::error::Error;
use crate::temporal::TimeRange;
use crate::{EntityId, Result, Vault};

/// CA-03's attempt kind, re-exported so a re-entry caller never spells a second
/// one. This module adds no attempt kind of its own.
pub use crate::campaign::enrollment::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND;

/// The ratified D+3 bump delay for no-show recovery, offered as preset data.
///
/// A default a ladder may adopt, never a threshold this module applies behind a
/// caller's back: [`NoShowRecoveryRule::bump_after_secs`] is what the recovery
/// plan actually reads.
pub const NO_SHOW_BUMP_AFTER_SECS: u64 = 3 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Ladder schema
// ---------------------------------------------------------------------------

/// Whether an earned transition writes the head or proposes it.
///
/// [`Self::Auto`] is the default posture: evidence that satisfies a configured
/// transition advances the stage. [`Self::Propose`] is a per-call dial for a
/// host that wants a human between evidence and pipeline movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionMode {
    /// Earned evidence writes the stage head.
    Auto,
    /// Earned evidence writes a PROPOSED head for the existing claim-approval
    /// machinery to rule on. No CA-04 approval mechanism is minted.
    Propose,
}

/// Transition-request helper only; this is not the `crm.stage` wire value.
///
/// Deliberately not serde-derived: [`EntityId`] carries no serde impl and
/// `entity_id.rs` is a CA non-claim, so evidence references cross a wire through
/// CA-01's [`encode_crm_stage_value`] rather than a second serialization of the
/// same refs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageEvidence {
    /// Which class of evidence this request cites.
    pub class: StageEvidenceClass,
    /// Machine derivation or owner attestation.
    pub basis: EvidenceBasis,
    /// Non-empty evidence references. An empty list is rejected at every door.
    pub evidence_refs: Vec<EntityId>,
    /// When the evidence was recorded.
    pub recorded_at: u64,
}

/// One declared stage. Position in [`StageLadderDefinition::stages`] IS the
/// ladder order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageDefinition {
    /// Opaque stage token, owned by CA-01's [`StageKey`].
    pub key: StageKey,
    /// Host-facing label. Content, not mechanism.
    pub label: String,
}

/// One configured way to earn a stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageTransitionRule {
    /// `None` means no live `crm.stage` head yet; `campaign.member` is not a stage.
    pub from: Option<StageKey>,
    /// Stage entered when this rule's evidence lands.
    pub to: StageKey,
    /// The one evidence class this transition accepts.
    pub evidence_class: StageEvidenceClass,
    /// Whether an owner attestation may stand in for machine evidence. Read
    /// together with the ladder's proposal boundary — see
    /// [`require_owner_attestable`].
    pub owner_attested_allowed: bool,
}

/// The six ratified reply codes. Consultancy-neutral by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyCode {
    /// Wants to move now.
    PositiveNow,
    /// Interested, but not yet.
    PositiveLater,
    /// Points at someone else.
    Referral,
    /// Pushes back on a specific point.
    Objection,
    /// Declines.
    NotInterested,
    /// Objects to being contacted at all.
    Complaint,
}

/// What a coded reply does. The LADDER decides which code lands on which
/// disposition; no code-to-action mapping is hidden in this module's code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplyDisposition {
    /// Earn a stage, subject to a configured transition.
    Promote {
        /// Stage the reply earns.
        stage: StageKey,
    },
    /// Pause the membership with a wake condition.
    Snooze,
    /// Hand off to referral routing; no CA-04 write.
    RouteReferral,
    /// Keep the reply as history and change nothing.
    RecordOnly,
    /// Leave the cohort.
    Exit,
    /// Hold out of the cohort. Reuses CA-01 membership state; mints no second
    /// suppression primitive.
    Suppress,
}

/// One code-to-disposition row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRouteRule {
    /// The coded reply this row routes.
    pub code: ReplyCode,
    /// What it does.
    pub disposition: ReplyDisposition,
}

/// The ratified no-show recovery shape: same-day reschedule, then a bump, then
/// snooze. Each leg is a dial; the ORDER is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoShowRecoveryRule {
    /// Offer a same-day reschedule first.
    pub same_day_reschedule: bool,
    /// Delay before the bump. [`NO_SHOW_BUMP_AFTER_SECS`] is the ratified D+3.
    pub bump_after_secs: u64,
    /// Snooze when the bump does not land.
    pub snooze_after_failed_bump: bool,
}

/// A whole stage ladder, as pure data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLadderDefinition {
    /// Ladder identity, host-assigned.
    pub key: String,
    /// Declared stages, in ladder order.
    pub stages: Vec<StageDefinition>,
    /// Every configured way to earn a stage.
    pub transitions: Vec<StageTransitionRule>,
    /// Reply routing table.
    pub reply_routes: Vec<ReplyRouteRule>,
    /// No-show recovery dials.
    pub no_show_recovery: NoShowRecoveryRule,
}

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

/// One leg of the ratified no-show recovery order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoShowRecoveryStep {
    /// Offer a same-day reschedule.
    SameDayReschedule,
    /// Bump after a delay.
    BumpAfter {
        /// The configured delay.
        delay_secs: u64,
    },
    /// Snooze the membership.
    Snooze,
}

/// The recovery plan a `no_show` outcome produces. It never writes `call_held`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoShowRecoveryPlan {
    /// The EVENT that did not happen.
    pub event_ref: EntityId,
    /// The `calendar.event_outcome` claim that says so.
    pub outcome_claim_ref: EntityId,
    /// Recovery legs, in the ratified order.
    pub steps: Vec<NoShowRecoveryStep>,
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// A non-promoting route the ladder took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageRoute {
    /// The membership is paused with a wake condition.
    Snoozed(ReentryPlan),
    /// A no-show earned a recovery plan.
    Reengage(NoShowRecoveryPlan),
    /// Referral routing owns the next step.
    Referral,
    /// The membership left the cohort.
    Exited,
    /// The membership is held out of the cohort.
    Suppressed,
}

/// What one ladder call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageProjectResult {
    /// The stage head moved.
    Advanced {
        /// The new live `crm.stage` head.
        new_claim_ref: EntityId,
    },
    /// A proposed head landed for the existing approval machinery to rule on.
    Proposed {
        /// The proposed `crm.stage` claim.
        proposed_claim_ref: EntityId,
    },
    /// Something happened that is not a stage move.
    Routed(StageRoute),
    /// Nothing to do. Silence, an unrouted code, and an unconfigured transition
    /// all land here — none of them is an error.
    NoChange,
}

/// A typed request from an evidence source CA-04 does not own.
///
/// Deposit, audit/delivery, desk, and renewal inputs enter ONLY through this
/// hook. Their source truth stays with the counterparty ledger (ONE-1542),
/// commitments, or TASK_LIST machinery; CA-04 stores the stage and the evidence
/// reference and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalStageEvidenceHook {
    /// PERSON the stage is about.
    pub party_ref: EntityId,
    /// Campaign the stage is scoped to.
    pub campaign_ref: EntityId,
    /// Stage the evidence claims to earn.
    pub target_stage: StageKey,
    /// The evidence itself.
    pub evidence: StageEvidence,
}

/// The only CA-04 ingress permitted to write a `crm.stage` head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageProjectorInput {
    /// PERSON the head is written on.
    pub party_ref: EntityId,
    /// The head being replaced, or `None` for the FIRST head.
    pub previous_stage_claim_ref: Option<EntityId>,
    /// CA-01's canonical value. This module defines no second stage wire shape.
    pub value: CrmStageValue,
}

// ---------------------------------------------------------------------------
// Ladder validation
// ---------------------------------------------------------------------------

/// Rejects a ladder that contradicts itself.
///
/// Every check answers "can this definition be read deterministically?", not
/// "is this a good sales process". Two uniqueness rules carry the weight:
/// `(from, to)` must be unique so a promotion names one rule, and
/// `(from, evidence_class)` must be unique so evidence-class-driven selection
/// (the calendar-outcome path) resolves from the current stage alone.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] with a distinct static reason per rejection:
/// empty ladder or stage key, duplicate stage, transition touching an undeclared
/// stage, duplicate or ambiguous transition, a reply code routed twice, or a
/// reply route promoting into an undeclared stage.
pub fn validate_ladder(definition: &StageLadderDefinition) -> Result<()> {
    if definition.key.trim().is_empty() {
        return Err(invalid("stage ladder key must not be empty"));
    }
    if definition.stages.is_empty() {
        return Err(invalid("stage ladder must declare at least one stage"));
    }
    let mut seen: Vec<&StageKey> = Vec::with_capacity(definition.stages.len());
    for stage in &definition.stages {
        if stage.key.0.trim().is_empty() {
            return Err(invalid("stage key must not be empty"));
        }
        if seen.contains(&&stage.key) {
            return Err(invalid("stage ladder declares a duplicate stage"));
        }
        seen.push(&stage.key);
    }
    validate_transitions(definition)?;
    validate_reply_routes(definition)
}

fn validate_transitions(definition: &StageLadderDefinition) -> Result<()> {
    let mut pairs = Vec::with_capacity(definition.transitions.len());
    let mut classes = Vec::with_capacity(definition.transitions.len());
    for rule in &definition.transitions {
        if rule
            .from
            .as_ref()
            .is_some_and(|from| !declares(definition, from))
        {
            return Err(invalid("stage transition leaves an undeclared stage"));
        }
        if !declares(definition, &rule.to) {
            return Err(invalid("stage transition enters an undeclared stage"));
        }
        let pair = (rule.from.clone(), rule.to.clone());
        if pairs.contains(&pair) {
            return Err(invalid("stage ladder declares a duplicate transition"));
        }
        pairs.push(pair);
        let class = (rule.from.clone(), rule.evidence_class);
        if classes.contains(&class) {
            return Err(invalid("stage ladder declares an ambiguous evidence class"));
        }
        classes.push(class);
    }
    Ok(())
}

fn validate_reply_routes(definition: &StageLadderDefinition) -> Result<()> {
    let mut codes = Vec::with_capacity(definition.reply_routes.len());
    for route in &definition.reply_routes {
        if codes.contains(&route.code) {
            return Err(invalid("stage ladder routes one reply code twice"));
        }
        codes.push(route.code);
        if let ReplyDisposition::Promote { stage } = &route.disposition
            && !declares(definition, stage)
        {
            return Err(invalid("reply route promotes into an undeclared stage"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outreach lane selection
// ---------------------------------------------------------------------------

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
// The projector — the ONE `crm.stage` writer
// ---------------------------------------------------------------------------

/// Writes one `crm.stage` head through CA-01's transition door.
///
/// Crate-visible on purpose: every CA-04 ingress routes here, and there is no
/// public back door that could put or supersede a `crm.stage` claim without the
/// head compare-and-swap.
///
/// Under [`PromotionMode::Auto`] the replacement head and the prior head's
/// supersession share ONE write transaction through
/// [`supersede_crm_stage_in_txn`], which verifies predicate, subject, campaign
/// scope, and current head before superseding — so a stale
/// `previous_stage_claim_ref` rolls the replacement back instead of leaving two
/// live heads.
///
/// Under [`PromotionMode::Propose`] the same canonical value lands as a
/// PROPOSED head and nothing is superseded, because nothing has been decided
/// yet. Resolving it belongs to the crate's existing claim-approval machinery;
/// this module mints no second approval mechanism. The COMPARE half of the CAS
/// still runs, in the same write transaction as the proposal: a proposal planned
/// against a head that has since been superseded is refused rather than landed
/// beside the head that replaced it, because a torn pair of live heads wedges
/// every later transition on this `(party, campaign)` — the dial changes who
/// decides, never whether the head check holds.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the value carries no evidence references, or
/// when the head the transition was planned against is no longer the current
/// one. Claim-validation, supersession, and storage errors propagate.
pub(crate) fn project_stage_transition(
    vault: &Vault,
    input: &StageProjectorInput,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    // Defence in depth against the ONE law a stage cannot be written without:
    // CA-01's decoder rejects an empty list at the write door too, but this door
    // names the caller rather than the wire.
    if input.value.evidence_refs.is_empty() {
        return Err(invalid("crm.stage transition requires evidence"));
    }
    let body = stage_claim_body(input, mode);
    let new_id = EntityId::now();
    let recorded_at = input.value.recorded_at;
    match mode {
        PromotionMode::Propose => {
            vault.with_write_txn(|wtxn| {
                require_current_stage_head(vault, wtxn, input)?;
                vault.put_claim_in_txn(wtxn, &new_id, &body, at(recorded_at), recorded_at)?;
                Ok(())
            })?;
            Ok(StageProjectResult::Proposed {
                proposed_claim_ref: new_id,
            })
        }
        PromotionMode::Auto => {
            vault.with_write_txn(|wtxn| {
                vault.put_claim_in_txn(wtxn, &new_id, &body, at(recorded_at), recorded_at)?;
                supersede_crm_stage_in_txn(
                    vault,
                    wtxn,
                    &new_id,
                    input.previous_stage_claim_ref.as_ref(),
                    recorded_at,
                )
            })?;
            Ok(StageProjectResult::Advanced {
                new_claim_ref: new_id,
            })
        }
    }
}

fn stage_claim_body(input: &StageProjectorInput, mode: PromotionMode) -> ClaimBody {
    let mut body = ClaimBody::new(
        PREDICATE_CRM_STAGE,
        ClaimSubject::Entity(input.party_ref),
        encode_crm_stage_value(&input.value),
        1.0,
        match mode {
            PromotionMode::Auto => ClaimApprovalStatus::Approved,
            PromotionMode::Propose => ClaimApprovalStatus::Proposed,
        },
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(match input.value.basis {
        EvidenceBasis::Machine => ClaimSource::Observed,
        EvidenceBasis::OwnerAttested => ClaimSource::UserStated,
    });
    body.evidence = Some(evidence_value(&input.value.evidence_refs));
    body
}

/// The compare half of the head CAS, without the swap.
///
/// [`supersede_crm_stage_in_txn`] carries this check for a promotion, as the
/// first half of replacing the head. A proposal replaces nothing, so it has no
/// supersession to hang the check on — but it still lands a live head, and a
/// second live head is exactly what the check exists to prevent. Reading through
/// the caller's write txn is what makes it a compare-and-swap rather than a
/// suggestion.
fn require_current_stage_head(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    input: &StageProjectorInput,
) -> Result<()> {
    let current = live_stage_head_in(vault, wtxn, &input.party_ref, &input.value.campaign_ref)?
        .map(|(id, _)| id);
    if current != input.previous_stage_claim_ref {
        return Err(invalid("crm.stage expected head is not current"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Coded replies
// ---------------------------------------------------------------------------

/// Applies one coded reply through the ladder's routing table.
///
/// The LADDER decides the disposition. A code with no row changes nothing, which
/// is a configuration statement rather than an error. Every promotion builds
/// CA-01's canonical [`CrmStageValue`] and routes it through
/// [`project_stage_transition`]; nothing here writes a `crm.stage` claim
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

// ---------------------------------------------------------------------------
// Calendar outcomes — read side only
// ---------------------------------------------------------------------------

/// Consumes CAL-07's recorded outcome for one EVENT.
///
/// The whole point of this function is what it REFUSES to do. CAL-07's
/// `read_event_outcome` answers `None` for silence, and `None` projects to
/// Unknown — never to `Held`, whatever else the calendar, the thread, or the
/// elapsed clock might suggest. Only `Some(EventOutcome::Held)` can advance, and
/// only with the live outcome claim itself as evidence.
///
/// `no_show` returns the ratified recovery plan and never writes a held stage.
/// `cancelled_pre_start`, an explicit `unknown`, and silence all return
/// [`StageProjectResult::NoChange`].
///
/// The outcome VALUE and the outcome CLAIM the stage cites are bound to each
/// other by [`live_event_outcome_claim`], so an outcome that changes between the
/// two reads cannot be decided on under one value and cited under another.
///
/// # Errors
///
/// Propagates [`validate_ladder`], CAL-07's reader, and the projector.
pub fn apply_event_outcome(
    vault: &Vault,
    definition: &StageLadderDefinition,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
    event_ref: &EntityId,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    validate_ladder(definition)?;
    let Some(outcome) = read_event_outcome(vault, *event_ref)? else {
        return Ok(StageProjectResult::NoChange);
    };
    let Some(outcome_claim_ref) = live_event_outcome_claim(vault, event_ref, &outcome)? else {
        return Ok(StageProjectResult::NoChange);
    };
    match outcome.outcome {
        EventOutcome::Held => promote_on_held(
            vault,
            definition,
            party_ref,
            campaign_ref,
            &HeldOutcome {
                value: outcome,
                claim_ref: outcome_claim_ref,
            },
            mode,
        ),
        EventOutcome::NoShow => Ok(StageProjectResult::Routed(StageRoute::Reengage(
            NoShowRecoveryPlan {
                event_ref: *event_ref,
                outcome_claim_ref,
                steps: recovery_steps(&definition.no_show_recovery),
            },
        ))),
        EventOutcome::CancelledPreStart | EventOutcome::Unknown => Ok(StageProjectResult::NoChange),
    }
}

/// One `held` outcome as a promotion needs it: the value that was read and the
/// claim that carries it, resolved as ONE generation.
struct HeldOutcome {
    value: EventOutcomeClaimValue,
    claim_ref: EntityId,
}

fn promote_on_held(
    vault: &Vault,
    definition: &StageLadderDefinition,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
    outcome: &HeldOutcome,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    let (previous_stage_claim_ref, from) = stage_position(vault, party_ref, campaign_ref)?;
    let Some(rule) = evidence_class_rule(
        definition,
        from.as_ref(),
        StageEvidenceClass::CalendarEventOutcome,
    ) else {
        return Ok(StageProjectResult::NoChange);
    };
    let Some(basis) = admissible_basis(outcome.value.basis, rule) else {
        return Ok(StageProjectResult::NoChange);
    };
    project_stage_transition(
        vault,
        &StageProjectorInput {
            party_ref: *party_ref,
            previous_stage_claim_ref,
            value: CrmStageValue {
                campaign_ref: *campaign_ref,
                stage: rule.to.clone(),
                evidence_class: rule.evidence_class,
                evidence_refs: vec![outcome.claim_ref],
                basis,
                recorded_at: outcome.value.recorded_at,
            },
        },
        mode,
    )
}

/// Carries CAL-07's basis onto the stage head, or refuses it.
///
/// An owner who answered the check-in is not a machine observation, and writing
/// one as the other would launder the attestation past the ladder's own dial and
/// out of the head a reader inspects. So the basis rides through, and a
/// transition that does not admit attestation declines the promotion instead of
/// relabelling it — a configuration statement, not an error.
///
/// The proposal-stage boundary [`require_owner_attestable`] applies is
/// deliberately NOT applied here: it governs the downstream evidence HOOKS,
/// whose truth lives in the counterparty ledger, whereas a calendar outcome is
/// CAL-07's own recorded fact and the owner check-in is its ratified
/// owner-attested producer. The per-transition dial is the whole gate on this
/// path.
fn admissible_basis(basis: EventOutcomeBasis, rule: &StageTransitionRule) -> Option<EvidenceBasis> {
    match basis {
        EventOutcomeBasis::Machine => Some(EvidenceBasis::Machine),
        EventOutcomeBasis::OwnerAttested => rule
            .owner_attested_allowed
            .then_some(EvidenceBasis::OwnerAttested),
    }
}

/// The ratified order: same-day reschedule, then the bump, then snooze. Each leg
/// is a dial the ladder can drop; their relative order is not.
fn recovery_steps(rule: &NoShowRecoveryRule) -> Vec<NoShowRecoveryStep> {
    let mut steps = Vec::with_capacity(3);
    if rule.same_day_reschedule {
        steps.push(NoShowRecoveryStep::SameDayReschedule);
    }
    steps.push(NoShowRecoveryStep::BumpAfter {
        delay_secs: rule.bump_after_secs,
    });
    if rule.snooze_after_failed_bump {
        steps.push(NoShowRecoveryStep::Snooze);
    }
    steps
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
// External evidence hooks
// ---------------------------------------------------------------------------

/// Accepts evidence from a source CA-04 does not own, then routes a canonical
/// value through the stage projector.
///
/// Deposit, audit/delivery, desk, and renewal stages are EVIDENCE HOOKS only:
/// this writes the stage and its evidence reference, and never a payment,
/// commitment, renewal, or TASK_LIST record. Source truth stays with the
/// counterparty ledger (ONE-1542) and the other existing owners.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the hook carries no evidence references,
/// when its class disagrees with the configured transition, or when an
/// owner-attested basis is not admissible (see [`require_owner_attestable`]).
/// Projector and storage errors propagate.
pub fn apply_external_stage_evidence(
    vault: &Vault,
    definition: &StageLadderDefinition,
    hook: &ExternalStageEvidenceHook,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    validate_ladder(definition)?;
    if hook.evidence.evidence_refs.is_empty() {
        return Err(invalid("external stage evidence requires evidence refs"));
    }
    let (previous_stage_claim_ref, from) =
        stage_position(vault, &hook.party_ref, &hook.campaign_ref)?;
    let Some(rule) = transition_rule(definition, from.as_ref(), &hook.target_stage) else {
        return Ok(StageProjectResult::NoChange);
    };
    if hook.evidence.class != rule.evidence_class {
        return Err(invalid(
            "external stage evidence class does not match the transition",
        ));
    }
    if hook.evidence.basis == EvidenceBasis::OwnerAttested {
        require_owner_attestable(definition, rule)?;
    }
    project_stage_transition(
        vault,
        &StageProjectorInput {
            party_ref: hook.party_ref,
            previous_stage_claim_ref,
            value: CrmStageValue {
                campaign_ref: hook.campaign_ref,
                stage: hook.target_stage.clone(),
                evidence_class: hook.evidence.class,
                evidence_refs: hook.evidence.evidence_refs.clone(),
                basis: hook.evidence.basis,
                recorded_at: hook.evidence.recorded_at,
            },
        },
        mode,
    )
}

/// Enforces "stages past `proposal_sent` accept owner-attested basis" WITHOUT
/// spelling `proposal_sent`.
///
/// The boundary is read from the ladder itself: `proposal_sent` is definitionally
/// the stage a document artifact plus its send receipt earns, so the earliest
/// stage entered by a [`StageEvidenceClass::DocumentArtifactAndSendReceipt`]
/// transition IS the boundary, and "strictly after" is a position comparison in
/// the declared stage order. Consultancy stage names therefore stay in ONE-1779's
/// preset data, and a ladder that declares no such stage has nothing to attest
/// past.
///
/// The rule's own `owner_attested_allowed` flag is the second half: the ladder
/// may withhold attestation from a late stage, but it cannot grant it to an early
/// one.
fn require_owner_attestable(
    definition: &StageLadderDefinition,
    rule: &StageTransitionRule,
) -> Result<()> {
    if !rule.owner_attested_allowed {
        return Err(invalid("transition does not admit owner-attested evidence"));
    }
    let Some(boundary) = proposal_boundary_index(definition) else {
        return Err(invalid("ladder declares no proposal stage to attest past"));
    };
    let Some(target) = stage_index(definition, &rule.to) else {
        return Err(invalid("stage transition enters an undeclared stage"));
    };
    if target <= boundary {
        return Err(invalid(
            "owner-attested evidence is admissible only past the proposal stage",
        ));
    }
    Ok(())
}

fn proposal_boundary_index(definition: &StageLadderDefinition) -> Option<usize> {
    definition
        .transitions
        .iter()
        .filter(|rule| rule.evidence_class == StageEvidenceClass::DocumentArtifactAndSendReceipt)
        .filter_map(|rule| stage_index(definition, &rule.to))
        .min()
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// One replacement of a live `campaign.member` head.
struct MemberStateChange<'a> {
    membership_claim_ref: &'a EntityId,
    party_ref: EntityId,
    campaign_ref: EntityId,
    state: CampaignMemberState,
    evidence_ref: EntityId,
    now: u64,
}

/// Writes a replacement `campaign.member` head carrying a new STATE and
/// supersedes the head it replaces, in one transaction.
///
/// The replacement is built from the head it replaces, so channels and any
/// derivation survive. The identity checks run inside the same txn as the write:
/// a claim that is not this party's live membership in this campaign is rejected
/// before anything lands.
fn replace_member_state(vault: &Vault, change: &MemberStateChange<'_>) -> Result<EntityId> {
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

fn require_member_head(
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

/// The live `crm.stage` head for one `(party, campaign)`, read through the
/// caller's transaction.
///
/// Two live heads is a TORN pipeline, not a merge problem — the rows can
/// disagree about stage, evidence, and basis — so it is rejected here for the
/// same reason CA-01's transition door rejects it. Decoding runs through CA-01's
/// decoder; this module defines no second stage wire shape.
fn live_stage_head_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
) -> Result<Option<(EntityId, CrmStageValue)>> {
    let mut head = None;
    for id in vault.claims_for_subject_in_txn(rtxn, party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CRM_STAGE || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let value = decode_crm_stage_value(&body.value)?;
        if value.campaign_ref != *campaign_ref {
            continue;
        }
        if head.is_some() {
            return Err(invalid("crm.stage has more than one live head"));
        }
        head = Some((id, value));
    }
    Ok(head)
}

/// The live `calendar.event_outcome` claim that CARRIES `outcome`.
///
/// CAL-07 answers the outcome VALUE and a stage head has to cite a CLAIM, so the
/// two reads are bound by the value itself rather than by a second guess at which
/// head is current: the claim returned here still says exactly what the decision
/// was made on. A supersession landing between the reads — the `no_show` that
/// replaced the `held` this call read — leaves nothing carrying that value, so
/// the caller changes nothing instead of writing `call_held` citing a claim that
/// says the call never happened.
///
/// Reader-visibility is CAL-07's rule too: a gate-pending head the read path
/// cannot see is not evidence a stage may cite. Ties are broken on the claim id
/// so the choice among identical values stays total.
fn live_event_outcome_claim(
    vault: &Vault,
    event_ref: &EntityId,
    outcome: &EventOutcomeClaimValue,
) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut carrying: Vec<EntityId> = Vec::new();
    for id in vault.claims_for_subject_in_txn(&rtxn, event_ref)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_EVENT_OUTCOME || !claim_surfaceable(&body) {
            continue;
        }
        if decode_event_outcome_value(&body.value)? == *outcome {
            carrying.push(id);
        }
    }
    Ok(carrying.into_iter().max())
}

/// The live head as a transition needs it: the claim the projector will
/// supersede, and the stage the transition leaves. `(None, None)` means no live
/// head yet — `campaign.member` is not a stage.
fn stage_position(
    vault: &Vault,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
) -> Result<(Option<EntityId>, Option<StageKey>)> {
    let rtxn = vault.store.env.read_txn()?;
    let Some((id, value)) = live_stage_head_in(vault, &rtxn, party_ref, campaign_ref)? else {
        return Ok((None, None));
    };
    Ok((Some(id), Some(value.stage)))
}

fn declares(definition: &StageLadderDefinition, key: &StageKey) -> bool {
    stage_index(definition, key).is_some()
}

fn stage_index(definition: &StageLadderDefinition, key: &StageKey) -> Option<usize> {
    definition.stages.iter().position(|stage| stage.key == *key)
}

fn transition_rule<'a>(
    definition: &'a StageLadderDefinition,
    from: Option<&StageKey>,
    to: &StageKey,
) -> Option<&'a StageTransitionRule> {
    definition
        .transitions
        .iter()
        .find(|rule| rule.from.as_ref() == from && rule.to == *to)
}

fn evidence_class_rule<'a>(
    definition: &'a StageLadderDefinition,
    from: Option<&StageKey>,
    class: StageEvidenceClass,
) -> Option<&'a StageTransitionRule> {
    definition
        .transitions
        .iter()
        .find(|rule| rule.from.as_ref() == from && rule.evidence_class == class)
}

/// Evidence is a reference list, matching the crate's claim-evidence shape.
fn evidence_value(evidence_refs: &[EntityId]) -> Value {
    Value::Array(
        evidence_refs
            .iter()
            .map(|id| Value::from(id.to_hex()))
            .collect(),
    )
}

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

fn elapsed(now: u64, then: u64) -> u64 {
    now.saturating_sub(then)
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VaultConfig;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::test_util::{entity, open_test_vault_with};

    // Seeds, all outside `PINNED_ID_BYTES`.
    const PARTY_SEED: u8 = 0x71;
    const CAMPAIGN_SEED: u8 = 0x72;
    const EVIDENCE_SEED: u8 = 0x73;
    const RECORDED_AT: u64 = 1_754_400_000;

    /// The projector's own door is crate-visible, so the stale-head plan a
    /// concurrent pair of requests produces is only expressible from inside the
    /// crate. The cross-module laws stay in
    /// `tests/campaign_stage_ladder_oracle.rs`.
    fn stage_vault() -> (tempfile::TempDir, Vault) {
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let (dir, vault) = open_test_vault_with(config);
        vault
            .put_entity(
                &entity(PARTY_SEED),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"stage projector party",
            )
            .expect("put person");
        (dir, vault)
    }

    fn transition_to(stage: &str, previous: Option<EntityId>) -> StageProjectorInput {
        StageProjectorInput {
            party_ref: entity(PARTY_SEED),
            previous_stage_claim_ref: previous,
            value: CrmStageValue {
                campaign_ref: entity(CAMPAIGN_SEED),
                stage: StageKey(stage.to_owned()),
                evidence_class: StageEvidenceClass::MeaningfulReply,
                evidence_refs: vec![entity(EVIDENCE_SEED)],
                basis: EvidenceBasis::Machine,
                recorded_at: RECORDED_AT,
            },
        }
    }

    fn advance(vault: &Vault, input: &StageProjectorInput) -> EntityId {
        match project_stage_transition(vault, input, PromotionMode::Auto) {
            Ok(StageProjectResult::Advanced { new_claim_ref }) => new_claim_ref,
            other => panic!("expected an advanced stage, got {other:?}"),
        }
    }

    /// Every live `crm.stage` claim on the party, counted WITHOUT the one-head
    /// rule — the point of the test is whether a second head can exist at all.
    fn live_heads(vault: &Vault) -> Vec<EntityId> {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .claims_for_subject_in_txn(&rtxn, &entity(PARTY_SEED))
            .expect("claims for subject")
            .into_iter()
            .filter(|id| {
                vault
                    .get_claim_in_txn(&rtxn, id)
                    .expect("claim body")
                    .is_some_and(|body| {
                        body.predicate == PREDICATE_CRM_STAGE
                            && body.lifecycle == ClaimLifecycleStatus::Active
                    })
            })
            .collect()
    }

    #[test]
    fn a_proposal_against_a_stale_head_is_refused() {
        let (_dir, vault) = stage_vault();

        // Two requests plan from the same head. One of them advances first.
        let planned_from = advance(&vault, &transition_to("replied", None));
        let current = advance(&vault, &transition_to("call_booked", Some(planned_from)));

        // The other now lands its PROPOSAL against a head that no longer exists.
        // Beside the head that replaced it, it would be a second live head, and
        // a torn pair wedges every later transition on this (party, campaign).
        let stale = transition_to("call_held", Some(planned_from));
        let proposed = project_stage_transition(&vault, &stale, PromotionMode::Propose);
        assert!(
            matches!(proposed, Err(Error::InvalidClaimBody(_))),
            "{proposed:?}"
        );
        assert_eq!(
            live_heads(&vault),
            vec![current],
            "a refused proposal leaves the current head alone",
        );

        // The dial decides WHO rules on the transition, never whether the head
        // check holds: AUTO refuses the same stale plan.
        let advanced = project_stage_transition(&vault, &stale, PromotionMode::Auto);
        assert!(
            matches!(advanced, Err(Error::InvalidClaimBody(_))),
            "{advanced:?}"
        );
        assert_eq!(live_heads(&vault), vec![current]);
    }

    #[test]
    fn a_proposal_against_the_current_head_lands_proposed() {
        let (_dir, vault) = stage_vault();
        let current = advance(&vault, &transition_to("replied", None));

        let result = project_stage_transition(
            &vault,
            &transition_to("call_booked", Some(current)),
            PromotionMode::Propose,
        );
        let Ok(StageProjectResult::Proposed { proposed_claim_ref }) = result else {
            panic!("propose mode must return a proposed head, got {result:?}");
        };

        // Nothing was superseded: the proposal is a question, not a decision.
        let body = vault
            .get_claim(&proposed_claim_ref)
            .expect("read proposal")
            .expect("proposal exists");
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(
            vault
                .get_claim(&current)
                .expect("read head")
                .expect("head exists")
                .lifecycle,
            ClaimLifecycleStatus::Active,
        );
    }
}
