//! What a full goal proposal changes against the goal it revises, computed
//! by the engine when the proposal is stored. The interview shows it to the
//! human; a floor the proposal drops or relaxes is named here, never left to
//! the proposal's prose.

use serde::{Deserialize, Serialize};

use super::super::GoalRecord;

#[doc(hidden)]
pub use oneiron_records::workspace_roster::project::goal::proposals::diff::{
    GoalAxisChange, GoalAxisChanges, GoalBudgetChange, GoalPreferenceChange, GoalPreferenceChanges,
    GoalTextChange,
};
#[doc(hidden)]
use oneiron_records::workspace_roster::project::goal::proposals::diff::{
    axis_changes, preference_changes, text_change,
};

/// Every field of a goal record a proposal changes against its base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalRecordDiff {
    pub goal: Option<GoalTextChange>,
    pub why: Option<GoalTextChange>,
    pub primary_axes: GoalAxisChanges,
    /// Floor axes never regress (ARCH-0053): a proposal that drops or
    /// relaxes one shows it here by name, with its bound before and after.
    pub floor_axes: GoalAxisChanges,
    pub cost_axes: GoalAxisChanges,
    pub preferences: GoalPreferenceChanges,
    pub exploration_budget: Option<GoalBudgetChange>,
}

impl GoalRecordDiff {
    /// What `proposed` changes against `base`.
    pub(crate) fn between(base: &GoalRecord, proposed: &GoalRecord) -> Self {
        Self {
            goal: text_change(&base.goal, &proposed.goal),
            why: text_change(&base.why, &proposed.why),
            primary_axes: axis_changes(&base.primary_axes, &proposed.primary_axes),
            floor_axes: axis_changes(&base.floor_axes, &proposed.floor_axes),
            cost_axes: axis_changes(&base.cost_axes, &proposed.cost_axes),
            preferences: preference_changes(&base.preferences, &proposed.preferences),
            exploration_budget: (base.exploration_budget != proposed.exploration_budget).then(
                || GoalBudgetChange {
                    before: base.exploration_budget.clone(),
                    after: proposed.exploration_budget.clone(),
                },
            ),
        }
    }
}
