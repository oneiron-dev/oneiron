//! Moved from `crates/oneiron/src/workspace_roster/project/history_policy.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::workspace_roster::project::revision::ProjectRevisionHash;
use serde::Deserialize;
use serde::Serialize;

pub const DEFAULT_PROJECT_HISTORY_MAX_REVISIONS: u64 = 10_000;

/// How many worlds one member of a parent cycle has before the solver raises
/// its scan check (`joint`).
pub const DEFAULT_PROJECT_CYCLE_WORLDS_MAX: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectHistoryPolicy {
    pub max_revisions: u64,
    /// Past this many distinct views of one cycle member (or this many per
    /// undecided revision of assignments), the cycle's decision raises its
    /// scan check and reads on: every world is still decided and served.
    #[serde(default = "default_cycle_worlds_max")]
    pub cycle_worlds_max: u64,
}

pub fn default_cycle_worlds_max() -> u64 {
    DEFAULT_PROJECT_CYCLE_WORLDS_MAX
}

impl Default for ProjectHistoryPolicy {
    fn default() -> Self {
        Self {
            max_revisions: DEFAULT_PROJECT_HISTORY_MAX_REVISIONS,
            cycle_worlds_max: DEFAULT_PROJECT_CYCLE_WORLDS_MAX,
        }
    }
}

/// The owner's question about a parent cycle past its world bound (OF-520):
/// node-local, kept by the batch-end refresh for a component whose decision
/// came back as `super::fold::reason::CYCLE_BOUND`. The joint solver now
/// decides every component in full and counts its worlds and work as
/// EngineScan observations, so no decision carries that reason and the
/// refresh raises none; a row is only ever removed (FIX 11050).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCycleQuestion {
    /// The cycle's projects, in id order; each keys a copy of the row.
    pub members: Vec<EntityId>,
    pub raised_at: u64,
}

/// The owner's question about a project past its history budget (OF-520):
/// raised once, when a batch end first freezes the project, while every
/// authenticated revision past it is held; a seal or a raised policy that
/// brings the project back within budget clears it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectHistoryQuestion {
    pub project: EntityId,
    /// The revisions counted when the project crossed its budget.
    pub counted_at_crossing: u64,
    pub raised_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectHistoryOverBudget {
    pub project: EntityId,
    pub held: u64,
    pub max_revisions: u64,
    /// `None` when no record exists or it no longer re-checks.
    pub frozen_head: Option<ProjectRevisionHash>,
    /// Whether descendants of the frozen head narrowed it since the freeze.
    pub narrowed: bool,
}
