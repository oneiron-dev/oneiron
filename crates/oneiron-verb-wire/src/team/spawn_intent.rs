//! Moved from `crates/oneiron/src/team/spawn_intent.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Where the owner's spawn stands: a planned intent before or at its
/// launch, or a spawned agent the queue holds, which the spawn observation
/// reads as launched. In flight or in doubt is no stand: the owner is
/// refused and asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpawnPhase {
    /// Placed and planned: the stamp and the plan are frozen, and nothing
    /// launched yet.
    Planned,
    /// Queued: the leader and each member, bound as one team, or a solo's
    /// one agent.
    Launched,
    /// Placement, the planner or the launch refused; the refusal is kept.
    Refused,
    /// An erase of its asker or of the AGENT_DEF its plan seats took its
    /// text: it keeps its receipt, its ids and times, and never launches.
    Erased,
}

/// Whose erase left a planned spawn erased (Engine 10-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpawnErasure {
    /// The asker's.
    AskerErased,
    /// The AGENT_DEF its plan seats: a launch on it records this and
    /// launches nothing.
    TargetErased,
}
