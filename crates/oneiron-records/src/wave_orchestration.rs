//! Moved from `crates/oneiron/src/wave_orchestration.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::dreamer_attempt_kind::WAVE_PLAN_ATTEMPT_KIND;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// One task a planner proposes, addressed by a plan-local key.
///
/// `blocked_by` is expressed in LOCAL keys because the plan is validated
/// before any TASK row exists: entity ids only appear once the
/// [`WaveTaskPort`] has landed the rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedTask {
    /// Plan-local identity, unique within one [`WavePlan`].
    pub local_key: String,
    /// Short label for the minted TASK row.
    pub label: String,
    /// Engine-opaque task specification handed to the executor.
    pub spec: Value,
    /// Optional assignee for the minted TASK row.
    pub assignee_ref: Option<EntityId>,
    /// Local keys this task is blocked by; the edge runs dependent → blocker.
    pub blocked_by: Vec<String>,
}

/// The typed task cut a [`WavePlanner`] returns, before validation. A cut
/// held for a launch approval is frozen in this form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WavePlan {
    /// Must equal [`WAVE_PLAN_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Stable identity of this cut, reused across idempotent applies.
    pub plan_ref: String,
    /// The EPIC-level TASK the cut hangs under.
    pub epic_task_ref: EntityId,
    /// The proposed tasks, in planner order.
    pub tasks: Vec<PlannedTask>,
}
