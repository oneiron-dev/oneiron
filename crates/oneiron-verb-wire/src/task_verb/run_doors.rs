//! Moved from `crates/oneiron/src/task_verb/run_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_run_budget::run_budget::LeaseUnit;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// The owner's force: every live branch of `task_ref` stops, for `reason`
/// when one is given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelForceRequest {
    pub task_ref: EntityId,
    /// Kept on each terminal cancellation receipt the force writes.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The owner's read of every branch of one TASK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunBranchesRequest {
    pub task_ref: EntityId,
}

/// The owner's read of one consult TASK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsultReadRequest {
    pub task_ref: EntityId,
}

/// How a consult ended. `expired` (its deadline passed) and `abandoned` (its
/// executor went away) stay distinct causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsultDisposition {
    Completed,
    Rejected,
    Failed,
    Expired,
    Abandoned,
    Cancelled,
}

/// What one consult cost its peer, measured, in one unit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsultLandSpend {
    /// A budget line's unit: `tokens`, or one a pack row names.
    pub unit: LeaseUnit,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub units: u64,
}
