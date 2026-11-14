//! Moved from `crates/oneiron/src/autoreason_campaign/config.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::extraction_eval::Of360DerivationEnvelope;
use serde::Deserialize;
use serde::Serialize;

/// Every declared campaign arm, including the design-only one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignArmId {
    /// Incumbent single-pass claim authoring.
    SinglePass,
    /// OF-366 tournament claim authoring.
    Tournament,
    /// Design-only arm: same author, stronger critic. Never invoked.
    StrongCritic,
}

/// Arms the campaign can actually invoke.
///
/// The strong-critic arm has no variant here, so the compiler — not a runtime
/// check — is what stops an invocation path from selecting a stronger model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignExecutableArm {
    /// Incumbent single-pass claim authoring.
    SinglePass,
    /// OF-366 tournament claim authoring.
    Tournament,
}

impl From<CampaignExecutableArm> for CampaignArmId {
    fn from(arm: CampaignExecutableArm) -> Self {
        match arm {
            CampaignExecutableArm::SinglePass => Self::SinglePass,
            CampaignExecutableArm::Tournament => Self::Tournament,
        }
    }
}

/// Whether a declared arm is invoked or documented only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignArmExecution {
    /// The arm runs.
    Executable,
    /// The arm is declared for the record and never runs.
    DesignOnly,
}

/// Critic strength declared for an arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignCriticTier {
    /// Critic tier equals the authoring tier.
    SameAsAuthor,
    /// Stronger critic tier. Only legal on a design-only arm.
    Stronger,
}

/// One declared campaign arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignArmConfig {
    /// Arm identity.
    pub arm: CampaignArmId,
    /// Whether the arm is invoked.
    pub execution: CampaignArmExecution,
    /// Critic strength for the arm.
    pub critic_tier: CampaignCriticTier,
}

/// Corpus restriction applied before an incumbent claim enters the campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignCorpusFilter {
    /// Claim-predicate prefix the corpus is restricted to.
    pub predicate_prefix: String,
    /// Minimum incumbent sample count.
    pub min_sample_count: u32,
}

/// Identity of one evaluation dataset revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignDatasetRef {
    /// Dataset id.
    pub dataset_id: String,
    /// Dataset revision.
    pub revision: String,
}

/// The three campaign splits.
///
/// The sealed split is pinned here so it can be reserved, never evaluated:
/// [`CampaignEvaluationSplit`] has no sealed variant and no report constructor
/// can select this ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignSplits {
    /// Split used while searching for a configuration.
    pub search: CampaignDatasetRef,
    /// Split the verdict is decided on.
    pub held_out: CampaignDatasetRef,
    /// Reserved split. Never evaluated by this module.
    pub sealed: CampaignDatasetRef,
}

/// Tournament axes handed to the landed OF-366 admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignTournamentConfig {
    /// Candidate fan-out per round.
    pub fanout_m: u16,
    /// Refinement round cap.
    pub max_rounds_k: u16,
    /// Incumbent-confidence threshold below which the tournament is admitted.
    pub uncertainty_tau: f32,
}

/// The single budget lease line the campaign reserves against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignBudgetLine {
    /// Budget line id.
    pub budget_id: String,
    /// Units reserved per tournament step.
    pub reserve_units_per_step: u64,
}

/// The OF-360 metric definitions the campaign is pinned to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignMetricPin {
    /// Metric definition set id.
    pub set_id: String,
    /// Metric definition set revision.
    pub revision: String,
    /// Derivation envelope of the pinned set, carried verbatim.
    pub derivation_envelope: Of360DerivationEnvelope,
}

pub fn is_unit_interval_f32(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
