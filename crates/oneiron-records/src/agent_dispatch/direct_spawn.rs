//! Moved from `crates/oneiron/src/agent_dispatch/direct_spawn.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A field of a spawn's ask that a direct spawn may leave unapplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnAskField {
    Need,
    Care,
    Notes,
    Model,
    Width,
    Pattern,
}

/// Why a direct spawn left an asked field unapplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnUnappliedReason {
    /// The host binds no planner, so nothing read the field.
    PlannerUnbound,
    /// The spawning agent holds no acquired lease, so the host neither
    /// planned the spawn nor placed it on its need.
    AgentLeaseUnbound,
}

/// One asked field a direct spawn did not apply, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnUnapplied {
    pub field: SpawnAskField,
    pub reason: SpawnUnappliedReason,
}
