//! Moved from `crates/oneiron/src/verbs/standing.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One configured standing block: its durable handle and floor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StandingBlockView {
    pub handle: String,
    pub agent_ref: EntityId,
    pub world_ref: EntityId,
    pub name: String,
    pub token_floor: usize,
}

/// `vault.standing_blocks.configure` and `.reconfigure` input: the pair,
/// its name and the token floor no session may spend below.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StandingBlockConfigureRequest {
    pub agent_ref: EntityId,
    pub world_ref: EntityId,
    pub name: String,
    pub token_floor: usize,
}

/// `vault.standing_blocks.get` input: one configured pair.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StandingBlockRequest {
    pub agent_ref: EntityId,
    pub world_ref: EntityId,
}

/// `vault.standing_blocks.list` input: every world configured for an agent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StandingBlocksRequest {
    pub agent_ref: EntityId,
}

/// `self.standing.get` input: the caller's own block in one world.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnStandingBlockRequest {
    pub world_ref: EntityId,
}

/// `self.standing.edit` input: one persona field's new text, proposed
/// under the caller's run with the claims that evidence it. Compiled text
/// is never edited; the proposal waits for its gate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StandingBlockEditRequest {
    pub world_ref: EntityId,
    pub field: String,
    pub value: String,
    pub run_ref: String,
    #[serde(default)]
    pub evidence_refs: Vec<EntityId>,
}

/// `self.standing.edit`'s answer: the Proposed claim the edit landed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StandingBlockEditReceipt {
    pub handle: String,
    pub claim_ref: EntityId,
    pub field: String,
}

/// How a resident's own dreaming chooses its model and window: its own
/// model, the vault weaver's (`inherit`), or `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DreamingModeInput {
    Own,
    Inherit,
    Off,
}

/// `vault.agents.dreaming.get` input: one agent definition.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDreamingRequest {
    pub agent_def_ref: EntityId,
}

/// `vault.agents.dreaming.set` input: the complete dreaming choice for
/// the revision the owner read. An absent model clears the slot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDreamingSetRequest {
    pub agent_def_ref: EntityId,
    pub expected_version: String,
    pub new_version: String,
    pub mode: DreamingModeInput,
    #[serde(default)]
    pub dreaming_model: Option<String>,
}

/// One agent's dreaming choice: what its definition stores, the mode in
/// force, and its own dreaming model slot when it names one. Sharing a
/// model never shares the agent's diary or scratchpad.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDreamingView {
    pub agent_def_ref: EntityId,
    pub version: String,
    pub mode: Option<DreamingModeInput>,
    pub effective_mode: DreamingModeInput,
    pub dreaming_model: Option<String>,
}
