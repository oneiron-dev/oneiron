//! Engine-side AR-3 autoreason campaign configuration and report join.
//!
//! The campaign compares the incumbent single-pass claim-authoring arm against
//! the tournament arm over a pinned corpus. This module is a validated serde
//! config plus a report join over two already-landed surfaces: the OF-366
//! claim-authoring admission machinery (`dreamer_runner::claim_authoring`,
//! `dreamer_tournament`) and the OF-360 AR-3 metric tier
//! (`extraction_eval::of360_ar3_metric_tier`).
//!
//! It owns no storage, mints no entity, and performs no writes. Every metric
//! number is produced by the landed OF-360 evaluator and carried verbatim;
//! every admission decision is produced by the landed OF-366 gate. The only
//! numbers this module derives are the held-out comparison scalars, and each
//! of them is recomputed from the reports rather than trusted on input, so a
//! deserialized report cannot smuggle a fabricated verdict past
//! [`CampaignComparisonReport::validate`].
//!
//! A third arm (`strong critic`) is declared but design-only: the executable
//! boundary is a separate type ([`CampaignExecutableArm`]) that has no
//! strong-critic variant, so no invocation path can select a stronger model.

use crate::extraction_eval::Of360EvalError;

mod config;
mod judge;
mod report;
mod verdict;

pub use config::{
    CampaignArmConfig, CampaignArmExecution, CampaignArmId, CampaignBudgetLine, CampaignConfig,
    CampaignCorpusFilter, CampaignCriticTier, CampaignDatasetRef, CampaignExecutableArm,
    CampaignMetricPin, CampaignSplits, CampaignTournamentConfig,
};
pub use judge::{BlindCampaignJudgeInput, CampaignGoldAnchor, CampaignTasteJudgment};
pub use report::{
    CampaignArmReport, CampaignCost, CampaignEvaluationSplit, CampaignSmokeOutcome,
    CampaignSplitReport, build_campaign_split_report, merge_campaign_arm_report,
};
pub use verdict::{
    CampaignComparisonReport, CampaignHeldOutDecision, CampaignVerdict, CampaignVerdictReason,
    ExperimentVerdict, build_campaign_held_out_decision, compare_campaign,
};

/// Schema version of the campaign config and of the reports joined here.
pub const AUTOREASON_CAMPAIGN_SCHEMA_VERSION: u32 = 1;
/// Stable id of the claim-authoring autoreason campaign.
pub const AUTOREASON_CAMPAIGN_ID: &str = "autoreason-claim-authoring";
/// Predicate emitted when the campaign keeps the experiment.
pub const EXPERIMENT_VERDICT_KEEP: &str = "experiment.verdict.keep";
/// Predicate emitted when the campaign discards the experiment.
pub const EXPERIMENT_VERDICT_DISCARD: &str = "experiment.verdict.discard";

/// Incumbent-confidence threshold handed to the landed OF-366 gate.
const OF366_UNCERTAINTY_TAU: f32 = 0.5;
/// Minimum net held-out gain that still counts as a win.
const OF366_VERDICT_EPSILON: f64 = 0.05;
/// Minimum incumbent sample count admitted into the campaign corpus.
const OF366_MIN_SAMPLE_COUNT: u32 = 3;
/// Claim-predicate prefix the campaign corpus is restricted to.
const OF366_PATTERN_PREDICATE_PREFIX: &str = "pattern.";

/// Campaign-local failure modes. Deliberately module-local: nothing here
/// widens the crate error enum.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CampaignError {
    /// A config field is outside the pinned campaign shape.
    #[error("invalid campaign config field `{field}`: {reason}")]
    InvalidConfig {
        /// Offending config field.
        field: &'static str,
        /// Why the value is refused.
        reason: &'static str,
    },
    /// Two joined reports do not describe the same arm/split pair.
    #[error("campaign split report mismatch: {reason}")]
    ReportMismatch {
        /// Why the join is refused.
        reason: &'static str,
    },
    /// The evaluated metric definitions differ from the config pin.
    #[error("campaign metric pin does not match the landed OF-360 definitions")]
    MetricPinMismatch,
    /// The supplied gold anchor is not the configured held-out dataset.
    #[error("campaign held-out anchor does not match the configured held-out dataset")]
    HeldOutAnchorMismatch,
    /// A decision field does not match the value recomputed from the reports.
    #[error("invalid campaign decision field `{field}`: {reason}")]
    InvalidDecision {
        /// Offending decision field.
        field: &'static str,
        /// Why the value is refused.
        reason: &'static str,
    },
    /// The landed OF-360 evaluator refused the dataset or run.
    #[error(transparent)]
    Of360(#[from] Of360EvalError),
}

/// Result alias for campaign operations.
pub type CampaignResult<T> = std::result::Result<T, CampaignError>;

#[cfg(test)]
mod tests;
