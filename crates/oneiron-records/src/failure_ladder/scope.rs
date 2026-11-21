//! Moved from `crates/oneiron/src/failure_ladder/scope.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What the Nth consecutive transient failure selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureEscalationMode {
    /// Route to the healer slot; the default slot wakes the Coach.
    Auto,
    Human,
}

/// The agent-side scope a policy binds to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureScope {
    /// Lowercase-hex EntityId spelling.
    pub agent_ref: String,
    #[serde(default)]
    pub skill_ref: Option<String>,
}
