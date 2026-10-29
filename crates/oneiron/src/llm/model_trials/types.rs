//! The held-out selection and sufficiency card are supplied by eval authoring.

use crate::llm::decision::TypedDecision;
use crate::llm::registry::{ModelBackendPin, ModelCostReceipt, PricedModelBackend};
use crate::{EntityId, llm::LlmUsage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrialSetPin {
    pub id: String,
    pub version: u32,
    pub rubric_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeldOutSelection {
    pub answer: EntityId,
    pub fact: EntityId,
    /// Assigned by the derivation ledger before the split, never by the model.
    pub source_family: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialPolicy {
    /// Remaining monetary exploration allowance on the goal record. Ordinary
    /// inference leases still admit and settle every call independently.
    pub exploration_remaining: f64,
    /// Maximum cost per thousand future units, in catalog monetary units.
    pub vault_cost_cap: Option<f64>,
    pub project_cost_cap: Option<f64>,
    #[serde(default)]
    pub auto_approve: bool,
    pub candidate_needs_download: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialRequest {
    pub principal: EntityId,
    pub question: EntityId,
    pub question_version: u32,
    pub goal: EntityId,
    pub incumbent: ModelBackendPin,
    pub candidate: ModelBackendPin,
    pub source: String,
    pub benchmark: String,
    pub set: TrialSetPin,
    pub held_out: Vec<HeldOutSelection>,
    /// Per-unit upper usage bounds for both arms; cost is computed before work.
    pub incumbent_usage_bound: LlmUsage,
    pub candidate_usage_bound: LlmUsage,
    pub future_units: u64,
    pub policy: ModelTrialPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrialAdmission {
    Ready,
    AskExploration,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenTrialCase {
    pub selection: HeldOutSelection,
    pub unit: EntityId,
    pub source_frontier: [u8; 32],
    pub fact_value_hash: [u8; 32],
    pub label: bool,
    pub noise_weight: f64,
    pub derived_from: Vec<EntityId>,
}

/// The replay input deliberately omits the held-out label and outcome fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialCaseInput {
    pub answer: EntityId,
    pub unit: EntityId,
    pub source_frontier: [u8; 32],
}

/// Provider work uses decide(), with this exact backend and source frontier.
/// A cut or failed reply still reports billed usage, but has no typed answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialReading {
    pub backend: ModelBackendPin,
    pub decision: Option<TypedDecision>,
    pub usage: LlmUsage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialObservation {
    pub answer: EntityId,
    pub incumbent: TrialReading,
    pub candidate: TrialReading,
}

/// A held-out case's measured reads. A cost is `None` only for an arm whose
/// provider outcome is unknown (FIX 9920): its spend is not known, never zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialMeasurement {
    pub answer: EntityId,
    pub incumbent: Option<TypedDecision>,
    pub candidate: Option<TypedDecision>,
    pub incumbent_cost: Option<ModelCostReceipt>,
    pub candidate_cost: Option<ModelCostReceipt>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialEvidence {
    pub measurements: Vec<TrialMeasurement>,
    pub measurements_hash: [u8; 32],
    /// Family-grouped, noise-weighted Brier loss; lower is better. A missing
    /// or abstained answer makes the comparison unknown, never a zero loss.
    pub incumbent_loss: Option<f64>,
    pub candidate_loss: Option<f64>,
    pub independent_families: usize,
    pub incumbent_cost_per_thousand: f64,
    pub candidate_cost_per_thousand: f64,
    pub trial_cost: f64,
    /// Arms sent with no reading back (FIX 9920). While nonzero, the costs
    /// above are the known billed spend only, and the losses are unknown.
    #[serde(default)]
    pub unknown_arms: usize,
    /// Earlier attempts of arms the owner resent (FIX 10464): their spend is
    /// unknown, so while nonzero the costs above are the known billed spend
    /// only, while the losses are read on the resent arms.
    #[serde(default)]
    pub resent_unknown_arms: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairedQualityInterval {
    /// Positive gain means the candidate has lower loss than the incumbent.
    pub low: f64,
    pub high: f64,
}

/// The OF-578 sufficiency result is bound to the exact set and measured reads.
/// Interval construction, family derivations and exposure retirement belong there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrialAssessment {
    pub set: TrialSetPin,
    pub measurements_hash: [u8; 32],
    pub paired_gain: Option<PairedQualityInterval>,
    pub retest_noise: f64,
    pub stricter_margin: Option<f64>,
    pub required_families: usize,
    pub rare_slices_sufficient: bool,
    pub versions_match: bool,
    pub canary_diverged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrialQuality {
    Better,
    NotWorse,
    Worse,
    Unknown,
}

/// These are offers/approvals for the activation owner, not routing mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelTrialAction {
    Stay,
    Offer,
    AutoApprove,
    AskTradeoff,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialReceipt {
    pub assessment: TrialAssessment,
    pub quality: TrialQuality,
    pub action: ModelTrialAction,
    pub candidate_cost_per_unit: f64,
    pub added_cost_per_thousand: f64,
    pub added_future_cost: f64,
    pub completed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTrial {
    pub id: EntityId,
    pub request: ModelTrialRequest,
    pub nominated_score: f64,
    pub score_fetched_at: u64,
    pub incumbent: PricedModelBackend,
    pub candidate: PricedModelBackend,
    pub cases: Vec<FrozenTrialCase>,
    pub estimated_cost: f64,
    pub admission: TrialAdmission,
    pub prepared_at: u64,
    pub execution_started: bool,
    /// Where its paid reads stand (FIX 9920); see
    /// [`ModelTrial::progress_counts`].
    #[serde(default)]
    pub execution: ModelTrialExecutionState,
    /// The run that last claimed it: each claim takes the next.
    #[serde(default)]
    pub run: u32,
    /// Every arm sent, each kept before the next send.
    #[serde(default)]
    pub arms: Vec<TrialArmProgress>,
    /// Arms of unknown outcome the owner chose to send again (FIX 10464),
    /// each as it stood when resent: its spend stays unknown, never zero.
    #[serde(default)]
    pub resent_arms: Vec<TrialArmProgress>,
    pub evidence: Option<TrialEvidence>,
    pub receipt: Option<ModelTrialReceipt>,
}

/// Which of a held-out case's two reads an arm is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TrialArm {
    Incumbent,
    Candidate,
}

/// Where a trial's paid reads stand, inside its own row (FIX 9920).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ModelTrialExecutionState {
    /// No run has claimed it.
    #[default]
    NotStarted,
    /// A run holds it and sends the arms not yet sent.
    Running,
    /// A run stopped on an arm whose provider outcome it does not know. A
    /// later run sends only the arms never sent; the trial then measures
    /// with that arm unknown.
    Interrupted,
    /// Every arm is read or unknown, and the evidence is recorded.
    Measured,
}

/// Why an arm's provider outcome is unknown. Content-free: never the
/// executor's error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrialArmFailure {
    /// The executor returned an error after the arm was handed to it.
    ExecutorError,
    /// The run that sent it stopped, or a later run claimed the trial, while
    /// the send was in flight.
    Interrupted,
}

/// One sent arm's outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialArmOutcome {
    /// Handed to the executor; no result is kept yet.
    Sending,
    /// Billed, and kept before the next send.
    Completed { reading: TrialReading },
    /// Sent with no reading back: its spend is unknown, never zero, and it
    /// is never sent again unless its owner resends it (FIX 10464).
    Unknown { failure: TrialArmFailure },
}

/// One arm of a trial: a held-out case's answer and which of its two reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrialArmKey {
    pub answer: EntityId,
    pub arm: TrialArm,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialArmProgress {
    pub answer: EntityId,
    pub arm: TrialArm,
    /// The run that sent it.
    pub run: u32,
    pub outcome: TrialArmOutcome,
}

/// A picker reads the measured pin beside the current backend price. A pin
/// for one router, serving revision or question cannot qualify another.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendQualityPin {
    pub backend: PricedModelBackend,
    pub question: EntityId,
    pub question_version: u32,
    pub trial: EntityId,
    pub set: TrialSetPin,
    pub brier_loss: f64,
    pub cost_per_thousand: f64,
    pub measured_at: u64,
}
