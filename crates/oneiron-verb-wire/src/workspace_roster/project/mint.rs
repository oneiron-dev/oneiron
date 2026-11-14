//! Moved from `crates/oneiron/src/workspace_roster/project/mint.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The goal is data for the leader, not instructions in its prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalRecord {
    pub project_id: String,
    pub goal: String,
    pub why: String,
    pub axes: Vec<String>,
}

/// The share is expressed against the root project's budget, never a grant
/// to spend more than the parent has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectBudgetShare {
    pub project_id: String,
    pub parent_id: String,
    pub share_bps: u16,
}
