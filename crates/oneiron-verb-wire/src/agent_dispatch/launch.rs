//! Moved from `crates/oneiron/src/agent_dispatch/launch.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::spend_scope::SpendState;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_run_budget::run_budget::LeaseUnit;
use oneiron_store::attempt_id::AttemptId;
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
