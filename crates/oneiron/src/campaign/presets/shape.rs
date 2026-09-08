//! Typed consultancy-preset shape: identity consts plus every pub struct and enum.

use serde::{Deserialize, Serialize};

use crate::campaign::claims::StageEvidenceClass;
use crate::campaign::stage::StageLadderDefinition;

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
