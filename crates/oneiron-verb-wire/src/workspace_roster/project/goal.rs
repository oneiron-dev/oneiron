//! Moved from `crates/oneiron/src/workspace_roster/project/goal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::workspace_roster::project::goal::interview::GoalInterviewTurns;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalBase;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalImprovement;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalReasons;
pub(crate) use oneiron_policy_vocabulary::policy_model::goal_limits::GoalLimits;
use oneiron_run_budget::run_budget::LeaseUnit;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A named observation that can be checked against receipts or a held-out trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoalAxis {
    pub name: String,
    pub measure: String,
    pub bound: String,
}

/// One tradeoff the human actually chose; the loop may propose, not invent, these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoalPreference {
    pub prefer: String,
    pub over: String,
    pub reason: String,
}

/// A goal's soft exploration share, not a grant or a vault budget lease.
/// Spend and the slice are counted in `unit`; a skill trial is charged
/// against the slice only when its run's launch estimate is in that unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoalExplorationBudget {
    pub max_spend: u64,
    pub exploration_slice: u64,
    pub unit: LeaseUnit,
    pub human_minutes: u64,
}
pub mod interview;
pub mod proposals;
