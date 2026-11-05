//! Core half of `store::dreamer_wake_policy`: its store-layer items live in `oneiron_store::dreamer_wake_policy` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::dreamer_wake_policy::*;

use serde::{Deserialize, Serialize};

/// Per-vault recipe dials. An owner may write a different v1 row; these are
/// data, not compiled thresholds. `new_records` excludes Generated claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerWakePolicy {
    pub wake_grain_turns: u64,
    /// Resident trigger table, missing-role rule and nested rate precedence.
    pub agent_cadence: AgentWakePolicy,
    /// New explicit CLAIMs plus user TURNs since the last weave.
    pub new_records: u64,
    pub longest_wait_secs: u64,
    pub nightly_secs: u64,
    /// Minimum inbound silence for any idle recipe to run.
    pub idle_secs: u64,
    /// Independent quiet-window trigger for Weave, even below accumulation.
    pub quiet_weave_secs: u64,
    /// Where the per-vault workflow skill competes with connector events.
    /// Cleanup and maintenance retain their protected priority; consolidation
    /// stays after these two lanes so its home-node stop cannot starve them.
    pub weave_recipe_priority: WeaveRecipePriority,
    /// The surprise floor, in thousandths (OF-138, ARCH-0036): a turn whose
    /// re-tag moved at least this far beside the set it replaced is a
    /// surprise signal for a resident's wake. The tagger measures the delta;
    /// a role's trigger table decides whether surprise may wake it.
    pub surprise_permille: u16,
}

/// Role table on the owner-editable wake-policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWakePolicy {
    pub absent_role: AgentWakeRole,
    pub precedence: CadencePrecedence,
    pub companion: AgentWakeTriggers,
    pub leader: AgentWakeTriggers,
    pub worker: AgentWakeTriggers,
}
