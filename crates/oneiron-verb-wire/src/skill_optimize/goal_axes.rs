//! Moved from `crates/oneiron/src/skill_optimize/goal_axes.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_record::record::SkillRecord;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AxisScores {
    pub before: f64,
    pub after: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnlineAxisOutcome {
    CandidateBetter,
    IncumbentBetter,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OnlineAxisMeasurement {
    pub axis: String,
    pub before_pulls: u32,
    pub after_pulls: u32,
    pub before: ConfidenceInterval,
    pub after: ConfidenceInterval,
    /// Person-time recorded on the slice's runs, by arm, in minutes.
    pub human_minutes: AxisScores,
    /// The pulls of each arm whose run carried recorded person-time.
    pub before_timed: u32,
    pub after_timed: u32,
    pub outcome: OnlineAxisOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GoalAxisReport {
    pub held_out_receipts: Vec<String>,
    pub offline: Vec<(String, AxisScores)>,
    pub online: Vec<OnlineAxisMeasurement>,
    /// Mandatory cost axis: the mean person-time of one timed live run, by
    /// arm, in minutes. `None` while either arm has no timed run. Never
    /// included in an online success rate.
    pub human_minutes: Option<AxisScores>,
}
