//! Moved from `crates/oneiron/src/verbs/engine_controls.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::free_time::policy::FreeTimeSchedule;
use serde::Deserialize;
use serde::Serialize;

/// `vault.consolidation.selection_timing.set`'s input: how long a claim
/// soaks before consolidation selects it, and the recency window, in
/// milliseconds. Every other selection field stays as it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationSelectionTimingSetRequest {
    pub soak_ms: u64,
    pub recency_window_ms: u64,
}

/// `vault.consolidation.strength.set`'s input: the strength under which a
/// quiet claim is archived (0 to 1), and how long a claim stays quiet before
/// it may be, in milliseconds (above 0).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStrengthSetRequest {
    pub archive_below: f64,
    pub quiet_ms: u64,
}

/// `vault.curator.cadence.set`'s input: the minimum age of what the curator
/// reviews and the period between its passes, in seconds. The factors and
/// the questions stay as the owner set them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CuratorCadenceSetRequest {
    pub minimum_age_secs: u64,
    pub cadence_secs: u64,
}

/// `vault.evaluation.retune_thresholds.set`'s input: the score regression
/// (0 to 1) past which each tuned artifact is retuned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetuneThresholdsSetRequest {
    pub prompts_score_regression: f64,
    pub weights_score_regression: f64,
    pub manifest_thresholds_score_regression: f64,
}

/// `vault.stewardship.rules.period.set`'s input: how often the standing
/// rule `rule` falls due, in seconds. The rule's person, draft route and
/// `since` stay as the owner set them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StewardshipRulePeriodSetRequest {
    /// The rule's id, as the rule set names it.
    pub rule: String,
    pub every_secs: u64,
}

/// `vault.free_time.schedule.set`'s input: the agent (32 hex) whose standing
/// free-time policy moves, the revision the caller read, and the new
/// schedule. The policy's units, split and shown cap stay the owner's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeScheduleSetRequest {
    pub agent: String,
    pub expected_revision: u64,
    pub schedule: FreeTimeSchedule,
}
