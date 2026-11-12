//! Moved from `crates/oneiron/src/autoreason_campaign/report.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::config::CampaignDatasetRef;
use crate::autoreason_campaign::config::CampaignExecutableArm;
use crate::autoreason_campaign::judge::BlindCampaignJudgeInput;
use oneiron_base::extraction_eval::Of360Ar3MetricTier;
use oneiron_base::extraction_eval::Of360ExtractionRun;
use oneiron_base::extraction_eval::Of360GoldDataset;
use oneiron_base::extraction_eval::of360_ar3_metric_tier;
use serde::Deserialize;
use serde::Serialize;

/// Splits an AR-3 report may be produced for.
///
/// There is deliberately no sealed variant: the sealed split is reserved by
/// the config and unreachable from every report constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignEvaluationSplit {
    /// Configuration-search split.
    Search,
    /// Verdict-deciding split.
    HeldOut,
}

/// Smoke-gate outcome for one arm on one split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignSmokeOutcome {
    /// The arm survived the smoke gate.
    Passed,
    /// The arm was killed by the smoke gate.
    Killed {
        /// Why the arm was killed.
        reason: String,
    },
}

/// Observed cost row for one arm on one split.
///
/// The module records what the run reported and never recalculates a provider
/// price table.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignCost {
    /// Input tokens observed.
    pub input_tokens: u64,
    /// Output tokens observed.
    pub output_tokens: u64,
    /// Cache-read tokens observed.
    pub cache_read_tokens: u64,
    /// Cache-write tokens observed.
    pub cache_write_tokens: u64,
    /// Observed cost in USD.
    pub cost_usd: f64,
    /// Observed wall-clock duration.
    pub elapsed_ms: u64,
}
