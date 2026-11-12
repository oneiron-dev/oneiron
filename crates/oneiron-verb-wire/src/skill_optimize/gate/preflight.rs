//! Moved from `crates/oneiron/src/skill_optimize/gate/preflight.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::*;
use crate::skill_optimize::goal_axes::AxisScores;
use crate::workspace_roster::project::goal::GoalExplorationBudget;
use serde::Deserialize;
use serde::Serialize;

/// A proposal's offline preflight on its current basis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillEditPreflight {
    /// No floor regressed, the honesty floor included.
    pub passed: bool,
    /// The goal revision the floors were judged under.
    pub goal_revision: String,
    /// Each offline floor and cost axis, scored on the held-out set.
    pub offline: Vec<(String, AxisScores)>,
    /// The honesty floor, from the same held-out replays.
    pub honesty: AxisScores,
}
