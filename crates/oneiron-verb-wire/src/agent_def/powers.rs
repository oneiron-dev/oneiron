//! Moved from `crates/oneiron/src/agent_def/powers.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The kind of holder `vault.agents.powers.set` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPowerHolderKind {
    /// An agent definition: its root grant.
    Agent,
    /// One dispatched attempt of an agent.
    Attempt,
    /// One reader child, by its task id.
    ReaderTask,
}
