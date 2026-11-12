//! Moved from `crates/oneiron/src/share_travel/agent_pack.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::num::NonZeroU64;

/// The run scope, with a world named rather than referenced. The destination
/// binds a local world by that name or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackScope {
    All,
    Base,
    World { name: String },
}

/// A code-mode MCP the agent asks for, by key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackMcp {
    pub key: String,
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackBudgetSplit {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackOutputDecay {
    pub overview_after_turns: u64,
    pub stub_after_turns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackWakeCadence {
    Companion { every_turns: Option<u64> },
    Leader { every_turns: Option<u64> },
    Worker,
}

/// One selected piece of knowledge about the agent, as text. The destination
/// mints it as a local claim with this agent as the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackKnowledge {
    pub predicate: String,
    pub text: String,
}
