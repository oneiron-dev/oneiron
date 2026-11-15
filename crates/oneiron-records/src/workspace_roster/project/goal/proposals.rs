//! Moved from `crates/oneiron/src/workspace_roster/project/goal/proposals.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::workspace_roster::project::goal::proposals::diff::GoalAxisChange;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalAxisChanges;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalBudgetChange;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalPreferenceChange;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalPreferenceChanges;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalTextChange;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::workspace_roster::project::goal::proposals::ProjectGoalBase;
pub use oneiron_verb_wire::workspace_roster::project::goal::proposals::ProjectGoalProposalImprovement;
pub use oneiron_verb_wire::workspace_roster::project::goal::proposals::ProjectGoalProposalReasons;
use serde::Deserialize;
use serde::Serialize;

/// The rate a proposal was admitted under: at most `open_per_base` open
/// proposals of one proposer on one goal base, and at most `per_window` of
/// its proposals for one project in any `window_secs` (the vault clock's
/// seconds), dismissed ones counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalRate {
    pub open_per_base: u32,
    pub per_window: u32,
    pub window_secs: u64,
}

/// A vault owner's outcome for a proposal: dismissed, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalDismissal {
    pub person: EntityId,
    pub reason: String,
    pub at: u64,
}

/// Where a proposal stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectGoalProposalStatus {
    /// On the goal in force and not dismissed: the interview shows it.
    Open,
    /// A vault owner dismissed it.
    Dismissed,
    /// The goal moved since; history only.
    Superseded,
}
pub mod diff;
