//! Moved from `crates/oneiron/src/failure_ladder/healer_dispatch.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which healer a failure scope routes its cases to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealerSlot {
    /// No healer: the case goes only to the human surface. It is an explicit
    /// typed outcome, never a silently dropped case.
    Reserved,
    /// The Coach, the second base agent (ARCH-0066 #coach): the default slot.
    /// The case also wakes one Coach heal attempt on the Dreamer's runner.
    Coach,
    /// Lowercase-hex EntityId spelling.
    AgentDef { agent_def_ref: String },
}
