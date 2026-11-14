//! Moved from `crates/oneiron/src/agent_dispatch/launch.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One agent the launch starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LaunchRole {
    Agent,
    /// A saved workflow's leaf. The inert workflow wrapper is not an agent.
    WorkflowLeaf {
        ordinal: usize,
    },
}
