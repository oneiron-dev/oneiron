//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/action_mode.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::agent_record::AgentCeiling;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

/// One band: an index in `[min_index, max_index)` selects `mode`; a band
/// whose upper bound is 1 includes 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionModeRule {
    pub mode: String,
    pub min_index: f32,
    pub max_index: f32,
    /// The explicit agent-ceiling patch an approved mode applies (FIX
    /// 1786). `None` keeps the mode advice only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<ActionModeEffect>,
}

/// One band's explicit patch (FIX 1786): the agent whose definition ceiling
/// the mode sets, and that ceiling. It names no grant, scope or connector;
/// the ceiling still meets the preset and the owner's manifest at every gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionModeEffect {
    pub agent: EntityId,
    pub ceiling: ActionModeCeiling,
}

/// An agent definition's ceiling as a patch names it: ask first, or eligible
/// to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionModeCeiling {
    Proposed,
    Auto,
}

impl ActionModeCeiling {
    const fn agent_ceiling(self) -> AgentCeiling {
        match self {
            Self::Proposed => AgentCeiling::Proposed,
            Self::Auto => AgentCeiling::Auto,
        }
    }

    const fn of(ceiling: AgentCeiling) -> Self {
        match ceiling {
            AgentCeiling::Proposed => Self::Proposed,
            AgentCeiling::Auto => Self::Auto,
        }
    }
}
