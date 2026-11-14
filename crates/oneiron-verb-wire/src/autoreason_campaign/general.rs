//! Moved from `crates/oneiron/src/autoreason_campaign/general.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::config::CampaignDatasetRef;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// A bounded, tunable search dimension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SearchAxis {
    pub name: String,
    pub values: Vec<String>,
}

/// Which way a measured axis improves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricDirection {
    Higher,
    Lower,
}

/// Primary axes seek improvement; floors cannot regress; costs count as tradeoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricRole {
    Primary,
    Floor,
    Cost,
}

/// One named axis in a pinned metric set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MetricAxis {
    pub name: String,
    pub direction: MetricDirection,
    pub role: MetricRole,
}

/// Evaluator-owned metric set identity and the axes used by the decision rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MetricSet {
    pub set_id: String,
    pub revision: String,
    pub axes: Vec<MetricAxis>,
}

/// A bounded share of an externally enforced, reserve-then-spend lease.
/// This row cannot mint authority or spend the vault's lease by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BudgetLease {
    pub budget_id: String,
    pub max_units: u64,
    pub exploration_units: u64,
}

/// How a held-out measurement is decided. OF-366 uses its own validated
/// comparison report: its net taste gain, external cost penalty and smoke
/// precedence cannot be reduced to OF-360 metric deltas.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecideRules {
    /// Strict dominance: better on any axis and worse on none.
    Dominance,
    /// Delegate the fixed claim-authoring verdict to its validated report.
    Of366 { verdict_epsilon: f64 },
}

/// Requested merge crossover. It is never effective merely because this is true.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MergeCrossover {
    #[serde(default)]
    pub requested: bool,
    /// Minimum overlap required by the executor's common-ancestor validation.
    pub min_validation_overlap: f64,
}

impl Default for MergeCrossover {
    fn default() -> Self {
        Self {
            requested: false,
            min_validation_overlap: 0.5,
        }
    }
}

/// Optional search policy; crossover stays disabled by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignKnobs {
    #[serde(default)]
    pub merge_crossover: MergeCrossover,
}

/// Scores must come from a pinned dataset revision; a search split is never
/// eligible to supply decision evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Measurement {
    pub dataset: CampaignDatasetRef,
    pub metric_set_id: String,
    pub metric_set_revision: String,
    pub scores: BTreeMap<String, f64>,
}

/// Decisions do not deserialize or expose mutable evidence. Consumers must
/// request a new decision from the config's held-out measurement door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Promote,
    Reject,
    EscalateTradeoff,
}
