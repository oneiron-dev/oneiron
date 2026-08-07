//! CA-08 consultancy preset: the CONTRACT, never the copy.
//!
//! ONE-1775 owns the stage-ladder mechanism and deliberately spells no stage
//! name. This module is the other half of that split: it declares the typed
//! shape a consultancy preset has to arrive in, and validates one host-supplied
//! pack config against the ratified content invariants. It instantiates
//! [`StageLadderDefinition`] rather than restating it — no schema is copied
//! across the seam.
//!
//! Three laws shape the whole file.
//!
//! 1. **[`load_campaign_preset`] is the only production function.** It parses
//!    caller-supplied JSON, validates it, and returns owned data. It reads no
//!    path, writes no storage, queues no work, sends nothing, registers no
//!    kind, and allocates no entity byte.
//! 2. **No consultancy CONTENT lives in this crate.** Headings, SOW and
//!    one-pager bodies, and Mom-Test interview text are host-supplied pack
//!    config. The engine ships section KEYS, evidence SLOT names, and the
//!    validation that a config declares them — never a sentence a counterparty
//!    would read. The parse-plus-validate shape mirrors
//!    [`crate::channel_identity_manifest::parse_channel_identity_capability_matrix`];
//!    its compiled-in asset and `OnceLock` cache are deliberately NOT mirrored,
//!    because a built-in catalog is exactly the embedded content this module
//!    exists to keep out.
//! 3. **The preset is data for other owners' machinery.** The snooze dials feed
//!    CA-01's `campaign.member` paused form through CA-04's re-entry door; the
//!    no-show legs feed CA-04's recovery plan; deposit, audit, desk, and
//!    renewal fields are evidence HOOK declarations whose truth stays with the
//!    counterparty ledger, TASK_LIST, and commitment owners. Nothing here adds
//!    a scheduler, recurrence primitive, commitment type, or delivery action.
//!
//! The validated content invariants are the ratified ones: id
//! [`CONSULTANCY_PRESET_ID`] at version [`CONSULTANCY_PRESET_VERSION`], the
//! eight-stage pipeline with `member (cold)` absent because membership is not
//! pipeline, `call_held` earned only by a calendar event OUTCOME, all six reply
//! codes routed exactly once, a 60–90 day positive-later snooze that restarts at
//! touch 1 and also wakes on a fresh trigger, same-day-reschedule → D+3 bump →
//! snooze no-show recovery, a 14-day audit, and a `P1M` desk month.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::campaign::claims::{StageEvidenceClass, StageKey};
use crate::campaign::stage::{
    NO_SHOW_BUMP_AFTER_SECS, NoShowRecoveryRule, ReplyCode, ReplyDisposition,
    StageLadderDefinition, validate_ladder,
};
use crate::error::Error;

// ---------------------------------------------------------------------------
// Ratified identity
// ---------------------------------------------------------------------------

/// The host-supplied consultancy preset this module validates.
pub const CONSULTANCY_PRESET_ID: &str = "crm.consultancy.v1";

/// The preset schema version that pairs with [`CONSULTANCY_PRESET_ID`].
pub const CONSULTANCY_PRESET_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Preset shape
// ---------------------------------------------------------------------------

/// One whole campaign preset, as host-supplied data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPresetData {
    /// Preset identity. Must be [`CONSULTANCY_PRESET_ID`].
    pub id: String,
    /// Schema version. Must be [`CONSULTANCY_PRESET_VERSION`].
    pub version: u32,
    /// Host-facing label. Content, not mechanism.
    pub display_name: String,
    /// The pipeline this preset instantiates. CA-04 owns the schema.
    pub stage_ladder: StageLadderDefinition,
    /// Warm/cold outreach clocks, as data rather than engine constants.
    pub lane_policy: LanePolicyData,
    /// Positive-later snooze dials.
    pub snooze_policy: SnoozePolicyData,
    /// Brief SHAPES for the SOW and the one-pager. Bodies are host-supplied.
    pub templates: BriefTemplateSet,
    /// The desk month's declarative rhythm.
    pub desk_month: CommitmentRhythmData,
    /// Research/interview templates, including the Mom-Test one.
    pub campaign_templates: Vec<CampaignTemplateData>,
    /// The audit window this preset runs, in days. Declarative: it names the
    /// duration the TASK_LIST owner executes, and starts no timer here.
    pub audit_window_days: u32,
}

/// Freshness horizons for outreach-lane selection, supplied per preset.
///
/// A consultancy's warm window and a marketplace's are not the same number, so
/// CA-04 takes them as [`crate::campaign::stage::LaneClockPolicy`] data rather
/// than asserting a market fact the engine has no evidence for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanePolicyData {
    /// How long an enrolling trigger stays a live reason to reach out.
    pub trigger_fresh_for_secs: u64,
    /// How long a prior touch keeps a relationship warm.
    pub prior_touch_warm_for_secs: u64,
    /// Whether warm-reconnect rendering demands a real prior-thread or
    /// relationship reference. Always true here: cold outreach never fabricates
    /// familiarity.
    pub warm_requires_evidence: bool,
}

/// The positive-later snooze, expressed as dials rather than scheduling code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnoozePolicyData {
    /// Shortest admissible pause.
    pub min_secs: u64,
    /// Pause taken when the reply names no date.
    pub default_secs: u64,
    /// Longest admissible pause.
    pub max_secs: u64,
    /// Whether a fresh trigger also wakes the membership. Combined with a timed
    /// wake this drives CA-01's paused form with BOTH fields set.
    pub wake_on_new_trigger: bool,
    /// Always 0: re-entry restarts at touch 1.
    pub restart_touch_index: u32,
}

/// Which ARCH-0032b brief a template describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BriefTemplateKind {
    /// The statement of work.
    Sow,
    /// The pre-proposal one-pager.
    OnePager,
}

/// The two brief shapes a consultancy preset carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefTemplateSet {
    /// Statement-of-work shape.
    pub sow: BriefTemplateData,
    /// One-pager shape.
    pub one_pager: BriefTemplateData,
}

/// One brief shape: identity, ordering, and its sections.
///
/// There is no send, e-sign, payment, or delivery field, and adding one would
/// be a different ticket: composing a brief is not shipping it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefTemplateData {
    /// Host-assigned template key.
    pub key: String,
    /// Which brief this is.
    pub kind: BriefTemplateKind,
    /// Host-supplied title template.
    pub title_template: String,
    /// Sections, in the order the host renders them.
    pub sections: Vec<BriefSectionData>,
}

/// One brief section: a stable key, host-supplied presentation, and the
/// evidence slots the section may not be rendered without.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefSectionData {
    /// Stable section key the engine validates against the ARCH-0032b shape.
    pub key: String,
    /// Host-supplied heading text.
    pub heading: String,
    /// Evidence slots this section must be filled from.
    pub required_evidence_slots: Vec<String>,
    /// Host-supplied body template.
    pub body_template: String,
}

/// Where in a commitment period a checkpoint sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RhythmAnchor {
    /// At the period's start.
    PeriodStart,
    /// Repeating inside the period.
    Weekly,
    /// A review before the period ends.
    BeforePeriodEnd,
    /// At the period's end.
    PeriodEnd,
}

/// The desk month's rhythm, as declarative data.
///
/// It names WHEN evidence is expected and WHICH hooks carry it. It starts no
/// timer, mints no commitment or invoice type, and asserts no renewal truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentRhythmData {
    /// ISO-8601 period token, `P1M`; data only, not a new `Schedule` variant.
    pub period: String,
    /// The checkpoints inside one period.
    pub checkpoints: Vec<RhythmCheckpointData>,
    /// Evidence classes a renewal review may rest on. External hooks only.
    pub renewal_evidence: Vec<StageEvidenceClass>,
}

/// One checkpoint inside a commitment period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RhythmCheckpointData {
    /// Host-assigned checkpoint key.
    pub key: String,
    /// Which end of the period the offset is measured from.
    pub anchor: RhythmAnchor,
    /// Offset in days from the anchor; negative reaches backwards.
    pub offset_days: i32,
    /// Evidence hooks this checkpoint collects.
    pub evidence_slots: Vec<String>,
}

/// A research/interview campaign template.
///
/// There is no pitch, offer, or call-to-action field: a research interview that
/// can carry sales copy is a prospecting sequence wearing a research label, and
/// the shape refuses to express one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignTemplateData {
    /// Host-assigned template key.
    pub key: String,
    /// What the template is for.
    pub purpose: String,
    /// The role a participant occupies in this template.
    pub participant_role: String,
    /// Roles a participant in this template may not simultaneously occupy.
    pub cross_campaign_exclusions: Vec<String>,
    /// Host-supplied opening text.
    pub opening_template: String,
    /// The question blocks, in asking order.
    pub question_blocks: Vec<QuestionBlockData>,
    /// Host-declared rules for leaving the template.
    pub exit_rules: Vec<String>,
}

/// One block of interview questions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionBlockData {
    /// Stable block key the engine validates against the Mom-Test shape.
    pub key: String,
    /// What the block is trying to learn.
    pub intent: String,
    /// Host-supplied questions.
    pub questions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Ratified content
// ---------------------------------------------------------------------------

const SECS_PER_DAY: u64 = 24 * 60 * 60;

const STAGE_REPLIED: &str = "replied";
const STAGE_CALL_BOOKED: &str = "call_booked";
const STAGE_CALL_HELD: &str = "call_held";
const STAGE_PROPOSAL_SENT: &str = "proposal_sent";
const STAGE_DEPOSIT_PAID: &str = "deposit_paid";
const STAGE_AUDIT_ACTIVE: &str = "audit_active";
const STAGE_AUDIT_COMPLETE: &str = "audit_complete";
const STAGE_DESK_CLIENT: &str = "desk_client";

/// The ratified pipeline: stage order AND the one evidence class each stage is
/// earned by. `member (cold)` is deliberately absent — membership is not
/// pipeline, and a query match earns an outreach lane rather than a head.
const CONSULTANCY_STAGE_EVIDENCE: [(&str, StageEvidenceClass); 8] = [
    (STAGE_REPLIED, StageEvidenceClass::MeaningfulReply),
    (STAGE_CALL_BOOKED, StageEvidenceClass::CalendarEvent),
    (STAGE_CALL_HELD, StageEvidenceClass::CalendarEventOutcome),
    (
        STAGE_PROPOSAL_SENT,
        StageEvidenceClass::DocumentArtifactAndSendReceipt,
    ),
    (STAGE_DEPOSIT_PAID, StageEvidenceClass::CounterpartyLedger),
    (STAGE_AUDIT_ACTIVE, StageEvidenceClass::TaskListProgress),
    (STAGE_AUDIT_COMPLETE, StageEvidenceClass::TaskListProgress),
    (STAGE_DESK_CLIENT, StageEvidenceClass::RecurringCommitment),
];

/// Every reply code the preset must route, exactly once.
const RATIFIED_REPLY_CODES: [ReplyCode; 6] = [
    ReplyCode::PositiveNow,
    ReplyCode::PositiveLater,
    ReplyCode::Referral,
    ReplyCode::Objection,
    ReplyCode::NotInterested,
    ReplyCode::Complaint,
];

const CONSULTANCY_SNOOZE_MIN_SECS: u64 = 60 * SECS_PER_DAY;
const CONSULTANCY_SNOOZE_MAX_SECS: u64 = 90 * SECS_PER_DAY;
const CONSULTANCY_AUDIT_WINDOW_DAYS: u32 = 14;
const CONSULTANCY_DESK_PERIOD: &str = "P1M";

const SOW_SECTION_KEYS: [&str; 8] = [
    "context_and_evidence",
    "outcomes",
    "scope",
    "out_of_scope",
    "timeline",
    "fees_and_deposit",
    "acceptance",
    "next_step",
];
const SOW_EVIDENCE_SECTION: &str = "context_and_evidence";

const ONE_PAGER_SECTION_KEYS: [&str; 6] = [
    "situation",
    "observed_evidence",
    "proposed_engagement",
    "timeline",
    "commercial_shape",
    "next_step",
];
const ONE_PAGER_EVIDENCE_SECTION: &str = "observed_evidence";

const REQUIRED_RHYTHM_ANCHORS: [RhythmAnchor; 4] = [
    RhythmAnchor::PeriodStart,
    RhythmAnchor::Weekly,
    RhythmAnchor::BeforePeriodEnd,
    RhythmAnchor::PeriodEnd,
];

const MOM_TEST_TEMPLATE_KEY: &str = "mom_test";
const MOM_TEST_PARTICIPANT_ROLE: &str = "interviewee";
const PROSPECT_PARTICIPANT_ROLE: &str = "prospect";
const MOM_TEST_QUESTION_BLOCK_KEYS: [&str; 6] = [
    "past_behavior",
    "most_recent_occurrence",
    "current_workflow",
    "cost_and_time",
    "prior_attempts",
    "decision_process",
];

// ---------------------------------------------------------------------------
// The loader
// ---------------------------------------------------------------------------

/// Parses and validates JSON supplied by the host pack/config layer.
///
/// The returned value is owned data: nothing is cached, installed, registered,
/// or written. A caller hands this to CA-04's ladder functions, which own every
/// consequence.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the first defect found: malformed JSON, an
/// unknown or missing field, an id or version that is not the ratified pair, a
/// ladder CA-04 itself rejects, or any violated content invariant.
pub fn load_campaign_preset(json: &str) -> Result<CampaignPresetData> {
    let preset: CampaignPresetData = serde_json::from_str(json)
        .map_err(|err| preset_error(format!("host config is not a valid preset: {err}")))?;
    validate_preset(&preset)?;
    Ok(preset)
}

fn validate_preset(preset: &CampaignPresetData) -> Result<()> {
    if preset.id != CONSULTANCY_PRESET_ID {
        return Err(preset_error(format!(
            "id must be {CONSULTANCY_PRESET_ID:?}, found {:?}",
            preset.id
        )));
    }
    if preset.version != CONSULTANCY_PRESET_VERSION {
        return Err(preset_error(format!(
            "version must be {CONSULTANCY_PRESET_VERSION}, found {}",
            preset.version
        )));
    }
    require_text("display_name", &preset.display_name)?;
    // CA-04 owns ladder self-consistency: unique stages, unambiguous
    // transitions, one row per reply code. Its rejections are re-raised in this
    // module's error family rather than re-implemented.
    validate_ladder(&preset.stage_ladder)
        .map_err(|err| preset_error(format!("stage ladder: {err}")))?;
    validate_pipeline(&preset.stage_ladder)?;
    validate_reply_routes(&preset.stage_ladder)?;
    validate_no_show_recovery(&preset.stage_ladder.no_show_recovery)?;
    validate_lane_policy(&preset.lane_policy)?;
    validate_snooze_policy(&preset.snooze_policy)?;
    if preset.audit_window_days != CONSULTANCY_AUDIT_WINDOW_DAYS {
        return Err(preset_error(format!(
            "audit window must be {CONSULTANCY_AUDIT_WINDOW_DAYS} days, found {}",
            preset.audit_window_days
        )));
    }
    validate_templates(&preset.templates)?;
    validate_desk_month(&preset.desk_month)?;
    validate_campaign_templates(&preset.campaign_templates)
}

/// The eight stages, in order, each earned by its one ratified evidence class.
///
/// Exact-order equality is what keeps `member` and `cold` out: they are not
/// pipeline heads, so a ladder that declares one is not this preset.
fn validate_pipeline(ladder: &StageLadderDefinition) -> Result<()> {
    let declared: Vec<&str> = ladder
        .stages
        .iter()
        .map(|stage| stage.key.0.as_str())
        .collect();
    let ratified = CONSULTANCY_STAGE_EVIDENCE.map(|(stage, _)| stage);
    if declared != ratified {
        return Err(preset_error(format!(
            "stage order must be {ratified:?}, found {declared:?}"
        )));
    }
    for (stage, class) in CONSULTANCY_STAGE_EVIDENCE {
        let mut earned = false;
        for rule in &ladder.transitions {
            if rule.to.0 != stage {
                continue;
            }
            earned = true;
            if rule.evidence_class != class {
                return Err(preset_error(format!(
                    "stage {stage} is earned by {} evidence, not {}",
                    class.as_str(),
                    rule.evidence_class.as_str()
                )));
            }
        }
        if !earned {
            return Err(preset_error(format!("no transition earns stage {stage}")));
        }
    }
    Ok(())
}

/// All six coded replies, each on its ratified disposition.
///
/// CA-04 already rejects a code routed twice, so presence plus agreement is the
/// whole check.
fn validate_reply_routes(ladder: &StageLadderDefinition) -> Result<()> {
    for code in RATIFIED_REPLY_CODES {
        let Some(route) = ladder.reply_routes.iter().find(|route| route.code == code) else {
            return Err(preset_error(format!("reply code {code:?} is not routed")));
        };
        let ratified = ratified_disposition(code);
        if route.disposition != ratified {
            return Err(preset_error(format!(
                "reply code {code:?} must route to {ratified:?}, found {:?}",
                route.disposition
            )));
        }
    }
    Ok(())
}

fn ratified_disposition(code: ReplyCode) -> ReplyDisposition {
    match code {
        ReplyCode::PositiveNow => ReplyDisposition::Promote {
            stage: StageKey(STAGE_REPLIED.to_owned()),
        },
        ReplyCode::PositiveLater => ReplyDisposition::Snooze,
        ReplyCode::Referral => ReplyDisposition::RouteReferral,
        ReplyCode::Objection => ReplyDisposition::RecordOnly,
        ReplyCode::NotInterested => ReplyDisposition::Exit,
        ReplyCode::Complaint => ReplyDisposition::Suppress,
    }
}

/// Same-day reschedule, then the D+3 bump, then snooze.
///
/// The delay is compared against CA-04's own [`NO_SHOW_BUMP_AFTER_SECS`] so the
/// ratified 259200 seconds is stated once, in the module that applies it.
fn validate_no_show_recovery(rule: &NoShowRecoveryRule) -> Result<()> {
    if !rule.same_day_reschedule {
        return Err(preset_error(
            "no-show recovery must offer a same-day reschedule",
        ));
    }
    if rule.bump_after_secs != NO_SHOW_BUMP_AFTER_SECS {
        return Err(preset_error(format!(
            "no-show bump must be {NO_SHOW_BUMP_AFTER_SECS} seconds, found {}",
            rule.bump_after_secs
        )));
    }
    if !rule.snooze_after_failed_bump {
        return Err(preset_error(
            "no-show recovery must snooze after a failed bump",
        ));
    }
    Ok(())
}

fn validate_lane_policy(policy: &LanePolicyData) -> Result<()> {
    if !policy.warm_requires_evidence {
        return Err(preset_error(
            "warm reconnect must require prior-thread or relationship evidence",
        ));
    }
    if policy.trigger_fresh_for_secs == 0 || policy.prior_touch_warm_for_secs == 0 {
        return Err(preset_error("lane clocks must be non-zero"));
    }
    Ok(())
}

fn validate_snooze_policy(policy: &SnoozePolicyData) -> Result<()> {
    if policy.min_secs != CONSULTANCY_SNOOZE_MIN_SECS
        || policy.max_secs != CONSULTANCY_SNOOZE_MAX_SECS
    {
        return Err(preset_error(format!(
            "positive-later snooze must span {CONSULTANCY_SNOOZE_MIN_SECS}..={CONSULTANCY_SNOOZE_MAX_SECS} seconds, found {}..={}",
            policy.min_secs, policy.max_secs
        )));
    }
    if !(policy.min_secs..=policy.max_secs).contains(&policy.default_secs) {
        return Err(preset_error(format!(
            "default snooze {} is outside the ratified range",
            policy.default_secs
        )));
    }
    if !policy.wake_on_new_trigger {
        return Err(preset_error(
            "positive-later snooze must wake on a new trigger",
        ));
    }
    if policy.restart_touch_index != 0 {
        return Err(preset_error("campaign re-entry restarts at touch 1"));
    }
    Ok(())
}

fn validate_templates(templates: &BriefTemplateSet) -> Result<()> {
    validate_brief(
        &templates.sow,
        BriefTemplateKind::Sow,
        &SOW_SECTION_KEYS,
        SOW_EVIDENCE_SECTION,
    )?;
    validate_brief(
        &templates.one_pager,
        BriefTemplateKind::OnePager,
        &ONE_PAGER_SECTION_KEYS,
        ONE_PAGER_EVIDENCE_SECTION,
    )
}

/// One ARCH-0032b brief shape.
///
/// Section ORDER is host presentation, so only presence, uniqueness, and the
/// evidence anchor are enforced. Body text is validated for existence and never
/// for content: what a brief says is the host's, and reading it here would make
/// the engine an editor.
fn validate_brief(
    template: &BriefTemplateData,
    kind: BriefTemplateKind,
    required_keys: &[&str],
    evidence_section: &str,
) -> Result<()> {
    if template.kind != kind {
        return Err(preset_error(format!(
            "brief template {:?} must be {kind:?}, found {:?}",
            template.key, template.kind
        )));
    }
    require_text("brief template key", &template.key)?;
    require_text("brief title template", &template.title_template)?;
    let mut seen: Vec<&str> = Vec::with_capacity(template.sections.len());
    let mut evidence_slots = 0;
    for section in &template.sections {
        require_text("brief section key", &section.key)?;
        if seen.contains(&section.key.as_str()) {
            return Err(preset_error(format!(
                "brief declares section {:?} twice",
                section.key
            )));
        }
        seen.push(section.key.as_str());
        require_text("brief section heading", &section.heading)?;
        require_text("brief section body template", &section.body_template)?;
        if section.key == evidence_section {
            evidence_slots = section.required_evidence_slots.len();
        }
    }
    for required in required_keys {
        if !seen.contains(required) {
            return Err(preset_error(format!(
                "brief {:?} is missing section {required}",
                template.key
            )));
        }
    }
    if evidence_slots == 0 {
        return Err(preset_error(format!(
            "section {evidence_section} must declare at least one evidence slot"
        )));
    }
    Ok(())
}

/// The desk month, checked as data.
///
/// Every rejection answers "can this rhythm be read deterministically?": one
/// checkpoint per anchor so a reader knows which row it is looking at, an
/// evidence hook on each so a checkpoint has something to collect, and offsets
/// that point the direction their anchor names.
fn validate_desk_month(rhythm: &CommitmentRhythmData) -> Result<()> {
    if rhythm.period != CONSULTANCY_DESK_PERIOD {
        return Err(preset_error(format!(
            "desk period must be {CONSULTANCY_DESK_PERIOD:?}, found {:?}",
            rhythm.period
        )));
    }
    let mut anchors: Vec<RhythmAnchor> = Vec::with_capacity(rhythm.checkpoints.len());
    let mut keys: Vec<&str> = Vec::with_capacity(rhythm.checkpoints.len());
    for checkpoint in &rhythm.checkpoints {
        require_text("desk checkpoint key", &checkpoint.key)?;
        if keys.contains(&checkpoint.key.as_str()) {
            return Err(preset_error(format!(
                "desk rhythm declares checkpoint {:?} twice",
                checkpoint.key
            )));
        }
        keys.push(checkpoint.key.as_str());
        if anchors.contains(&checkpoint.anchor) {
            return Err(preset_error(format!(
                "desk rhythm declares anchor {:?} twice",
                checkpoint.anchor
            )));
        }
        anchors.push(checkpoint.anchor);
        if checkpoint.evidence_slots.is_empty() {
            return Err(preset_error(format!(
                "desk checkpoint {:?} names no evidence hook",
                checkpoint.key
            )));
        }
        validate_checkpoint_offset(checkpoint)?;
    }
    for anchor in REQUIRED_RHYTHM_ANCHORS {
        if !anchors.contains(&anchor) {
            return Err(preset_error(format!(
                "desk rhythm declares no {anchor:?} checkpoint"
            )));
        }
    }
    if rhythm.renewal_evidence.is_empty() {
        return Err(preset_error("desk renewal declares no evidence hook"));
    }
    for class in &rhythm.renewal_evidence {
        if !is_external_hook(*class) {
            return Err(preset_error(format!(
                "renewal evidence {} is not an external hook; renewal truth stays with the counterparty ledger",
                class.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_checkpoint_offset(checkpoint: &RhythmCheckpointData) -> Result<()> {
    let consistent = match checkpoint.anchor {
        RhythmAnchor::Weekly => checkpoint.offset_days > 0,
        RhythmAnchor::BeforePeriodEnd => checkpoint.offset_days < 0,
        RhythmAnchor::PeriodStart | RhythmAnchor::PeriodEnd => true,
    };
    if !consistent {
        return Err(preset_error(format!(
            "checkpoint {:?} offset {} contradicts its {:?} anchor",
            checkpoint.key, checkpoint.offset_days, checkpoint.anchor
        )));
    }
    Ok(())
}

/// Whether a class is evidence some OTHER owner records.
///
/// Deposit, audit, desk, and renewal rest on these and only these: a reply or a
/// calendar entry is not a payment, a deliverable, or a renewal.
const fn is_external_hook(class: StageEvidenceClass) -> bool {
    matches!(
        class,
        StageEvidenceClass::CounterpartyLedger
            | StageEvidenceClass::TaskListProgress
            | StageEvidenceClass::RecurringCommitment
    )
}

fn validate_campaign_templates(templates: &[CampaignTemplateData]) -> Result<()> {
    let mut keys: Vec<&str> = Vec::with_capacity(templates.len());
    let mut mom_test = None;
    for template in templates {
        require_text("campaign template key", &template.key)?;
        if keys.contains(&template.key.as_str()) {
            return Err(preset_error(format!(
                "campaign template {:?} is declared twice",
                template.key
            )));
        }
        keys.push(template.key.as_str());
        require_text("campaign template purpose", &template.purpose)?;
        require_text(
            "campaign template participant role",
            &template.participant_role,
        )?;
        if template
            .cross_campaign_exclusions
            .contains(&template.participant_role)
        {
            return Err(preset_error(format!(
                "campaign template {:?} excludes its own participant role",
                template.key
            )));
        }
        if template.key == MOM_TEST_TEMPLATE_KEY {
            mom_test = Some(template);
        }
    }
    let Some(mom_test) = mom_test else {
        return Err(preset_error(format!(
            "preset declares no {MOM_TEST_TEMPLATE_KEY} template"
        )));
    };
    validate_mom_test(mom_test)
}

/// The Mom-Test template is research, not prospecting.
///
/// Two things carry that. The SHAPE has no pitch, offer, or call-to-action
/// field, so an interview cannot express one. The DATA has to declare the
/// cross-campaign exclusion, so one person cannot be interviewed about their
/// problem and sold to about it in the same breath — a conflict of interest that
/// corrupts the research and the relationship at once.
fn validate_mom_test(template: &CampaignTemplateData) -> Result<()> {
    if template.participant_role != MOM_TEST_PARTICIPANT_ROLE {
        return Err(preset_error(format!(
            "mom test participant role must be {MOM_TEST_PARTICIPANT_ROLE:?}, found {:?}",
            template.participant_role
        )));
    }
    if !template
        .cross_campaign_exclusions
        .iter()
        .any(|role| role == PROSPECT_PARTICIPANT_ROLE)
    {
        return Err(preset_error(format!(
            "mom test must exclude the {PROSPECT_PARTICIPANT_ROLE} role"
        )));
    }
    require_text("mom test opening template", &template.opening_template)?;
    let mut blocks: Vec<&str> = Vec::with_capacity(template.question_blocks.len());
    for block in &template.question_blocks {
        require_text("question block key", &block.key)?;
        if blocks.contains(&block.key.as_str()) {
            return Err(preset_error(format!(
                "mom test declares question block {:?} twice",
                block.key
            )));
        }
        blocks.push(block.key.as_str());
        require_text("question block intent", &block.intent)?;
        if block.questions.is_empty() {
            return Err(preset_error(format!(
                "question block {:?} asks nothing",
                block.key
            )));
        }
        for question in &block.questions {
            require_text("interview question", question)?;
        }
    }
    for required in MOM_TEST_QUESTION_BLOCK_KEYS {
        if !blocks.contains(&required) {
            return Err(preset_error(format!(
                "mom test is missing the {required} question block"
            )));
        }
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(preset_error(format!("{field} must not be empty")));
    }
    Ok(())
}

fn preset_error(message: impl Into<String>) -> Error {
    let message = message.into();
    Error::InvalidConfig(format!("campaign preset: {message}"))
}

#[cfg(test)]
mod tests;
