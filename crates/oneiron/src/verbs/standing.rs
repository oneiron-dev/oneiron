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
use crate::{EntityId, TimeRange, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::standing::{
    AgentDreamingRequest, AgentDreamingSetRequest, AgentDreamingView, DreamingModeInput,
    OwnStandingBlockRequest, StandingBlockConfigureRequest, StandingBlockEditReceipt,
    StandingBlockEditRequest, StandingBlockRequest, StandingBlockView, StandingBlocksRequest,
};

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
        memory.write_actor(),
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
