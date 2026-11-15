//! Moved from `crates/oneiron/src/settings/board_layout.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::layout::BoardLayout;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The most agents the owner may override one by one.
pub const BOARD_LAYOUT_AGENT_OVERRIDES_MAX: usize = 256;

/// The owner's override of one agent's board layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentBoardLayoutOverride {
    /// The agent whose board this override lays out.
    pub agent: EntityId,
    /// The sections the owner sets for this agent.
    pub layout: BoardLayout,
}
