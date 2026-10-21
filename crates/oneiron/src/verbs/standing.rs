//! Standing-block configuration, gated self-edits and per-agent dreaming
//! choice (BOARD-04). Configuration and the dreaming dial are the owner's;
//! a self-edit lands as a Proposed persona claim for the gate to settle.
use serde::{Deserialize, Serialize};

use crate::agent_def::{AgentDefinition, DreamingMode};
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::llm::ModelTierRef;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
use crate::persona_snapshot::standing::{StandingBlockEdit, StandingBlockHandle};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// One configured standing block: its durable handle and floor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StandingBlockView {
    pub handle: String,
    pub agent_ref: EntityId,
    pub world_ref: EntityId,
    pub name: String,
    pub token_floor: usize,
}

fn block_view(handle: &StandingBlockHandle) -> StandingBlockView {
    StandingBlockView {
        handle: handle.handle().to_owned(),
        agent_ref: handle.agent(),
        world_ref: handle.world(),
        name: handle.name().to_owned(),
        token_floor: handle.token_floor(),
    }
}

fn block_not_found() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "standing block not configured",
        &["Configure the agent's standing block for that world first."],
    )
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

pub fn configure_standing_block_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: StandingBlockConfigureRequest,
) -> MemoryResult<StandingBlockView> {
    let handle = vault.open_standing_block(
        owner,
        input.agent_ref,
        input.world_ref,
        &input.name,
        input.token_floor,
    )?;
    Ok(block_view(&handle))
}

pub fn reconfigure_standing_block_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: StandingBlockConfigureRequest,
) -> MemoryResult<StandingBlockView> {
    let handle = vault.reconfigure_standing_block(
        owner,
        input.agent_ref,
        input.world_ref,
        &input.name,
        input.token_floor,
    )?;
    Ok(block_view(&handle))
}

pub fn read_standing_block_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: StandingBlockRequest,
) -> MemoryResult<StandingBlockView> {
    owner.revalidate(vault)?;
    let handle = vault
        .standing_block(input.agent_ref, input.world_ref)?
        .ok_or_else(block_not_found)?;
    Ok(block_view(&handle))
}

pub fn list_standing_blocks_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: StandingBlocksRequest,
) -> MemoryResult<Vec<StandingBlockView>> {
    owner.revalidate(vault)?;
    Ok(vault
        .standing_blocks(input.agent_ref)?
        .iter()
        .map(block_view)
        .collect())
}

pub fn read_own_standing_block(
    memory: &Memory<'_>,
    input: OwnStandingBlockRequest,
) -> MemoryResult<StandingBlockView> {
    let handle = memory
        .vault()
        .standing_block(memory.actor(), input.world_ref)?
        .ok_or_else(block_not_found)?;
    Ok(block_view(&handle))
}

pub fn list_own_standing_blocks(memory: &Memory<'_>) -> MemoryResult<Vec<StandingBlockView>> {
    Ok(memory
        .vault()
        .standing_blocks(memory.actor())?
        .iter()
        .map(block_view)
        .collect())
}

pub fn edit_own_standing_block(
    memory: &Memory<'_>,
    input: StandingBlockEditRequest,
) -> MemoryResult<StandingBlockEditReceipt> {
    let vault = memory.vault();
    let handle = vault
        .standing_block(memory.actor(), input.world_ref)?
        .ok_or_else(block_not_found)?;
    let evidence = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: input.evidence_refs,
        chain: Vec::new(),
        source_meet: ClaimSource::Generated,
    });
    let claim_ref = vault.edit_standing_block(
        &handle,
        WriteActor::new(memory.actor(), memory.actor_class()),
        &input.run_ref,
        StandingBlockEdit::Claim {
            field: input.field.clone(),
            value: rmpv::Value::from(input.value.as_str()),
            evidence,
        },
    )?;
    Ok(StandingBlockEditReceipt {
        handle: handle.handle().to_owned(),
        claim_ref,
        field: input.field,
    })
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

impl From<DreamingModeInput> for DreamingMode {
    fn from(mode: DreamingModeInput) -> Self {
        match mode {
            DreamingModeInput::Own => Self::Own,
            DreamingModeInput::Inherit => Self::Inherit,
            DreamingModeInput::Off => Self::Off,
        }
    }
}

impl From<DreamingMode> for DreamingModeInput {
    fn from(mode: DreamingMode) -> Self {
        match mode {
            DreamingMode::Own => Self::Own,
            DreamingMode::Inherit => Self::Inherit,
            DreamingMode::Off => Self::Off,
        }
    }
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

fn dreaming_view(agent_def_ref: EntityId, definition: &AgentDefinition) -> AgentDreamingView {
    AgentDreamingView {
        agent_def_ref,
        version: definition.version.clone(),
        mode: definition.dreaming.map(DreamingModeInput::from),
        effective_mode: definition.dreaming_mode().into(),
        dreaming_model: definition
            .dreaming_model
            .as_ref()
            .map(|model| model.0.clone()),
    }
}

fn load_definition(vault: &Vault, id: EntityId) -> MemoryResult<AgentDefinition> {
    vault.get_agent_definition(&id)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "agent definition not found",
            &["Name an existing AGENT_DEF."],
        )
    })
}

pub fn read_agent_dreaming_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDreamingRequest,
) -> MemoryResult<AgentDreamingView> {
    owner.revalidate(vault)?;
    Ok(dreaming_view(
        input.agent_def_ref,
        &load_definition(vault, input.agent_def_ref)?,
    ))
}

pub fn set_agent_dreaming_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDreamingSetRequest,
) -> MemoryResult<AgentDreamingView> {
    owner.revalidate(vault)?;
    let existing = load_definition(vault, input.agent_def_ref)?;
    let mode = DreamingMode::from(input.mode);
    let model = input.dreaming_model.clone().map(ModelTierRef);
    if existing.dreaming == Some(mode) && existing.dreaming_model == model {
        return Ok(dreaming_view(input.agent_def_ref, &existing));
    }
    let mut updated = existing.clone();
    updated.dreaming = Some(mode);
    updated.dreaming_model = model;
    updated.version = input.new_version.clone();
    let now = crate::unix_seconds_now();
    vault.update_agent_definition_at_version_as(
        owner,
        &input.agent_def_ref,
        &input.expected_version,
        &updated,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(dreaming_view(input.agent_def_ref, &updated))
}
