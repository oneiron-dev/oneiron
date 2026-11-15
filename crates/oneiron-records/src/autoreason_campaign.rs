//! Moved from `crates/oneiron/src/autoreason_campaign.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::autoreason_campaign::judge::CampaignTaste;
pub use crate::autoreason_campaign::verdict::CampaignHeldOutDecision;
pub use crate::autoreason_campaign::verdict::CampaignVerdict;
pub use crate::autoreason_campaign::verdict::CampaignVerdictReason;
pub use crate::autoreason_campaign::verdict::ExperimentVerdict;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignArmConfig;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignArmExecution;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignArmId;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignBudgetLine;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignCorpusFilter;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignCriticTier;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignDatasetRef;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignExecutableArm;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignMetricPin;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignSplits;
pub use oneiron_verb_wire::autoreason_campaign::config::CampaignTournamentConfig;
pub use oneiron_verb_wire::autoreason_campaign::judge::BlindCampaignJudgeInput;
pub use oneiron_verb_wire::autoreason_campaign::judge::CampaignGoldAnchor;
pub use oneiron_verb_wire::autoreason_campaign::report::CampaignCost;
pub use oneiron_verb_wire::autoreason_campaign::report::CampaignEvaluationSplit;
pub use oneiron_verb_wire::autoreason_campaign::report::CampaignSmokeOutcome;

/// Predicate emitted when the campaign keeps the experiment.
pub const EXPERIMENT_VERDICT_KEEP: &str = "experiment.verdict.keep";

/// Predicate emitted when the campaign discards the experiment.
pub const EXPERIMENT_VERDICT_DISCARD: &str = "experiment.verdict.discard";
pub mod authoring;
pub mod beam_promotion;
pub mod judge;
pub mod report;
pub mod research;
pub mod verdict;
