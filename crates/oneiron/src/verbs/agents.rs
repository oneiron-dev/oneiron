//! Typed custom AGENT_DEF authoring. Authorship is the caller's, never input.
use serde::{Deserialize, Serialize};

use crate::agent_def::AgentDefinition;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::{EntityId, TimeRange, Vault};

pub use crate::code_run::workflow_operations::{
    AgentCeilingInput, AgentDefinitionSpec, AgentMcpInput, AgentScopeInput, AgentSkillInput,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionCreateRequest {
    pub agent_def_ref: EntityId,
    pub definition: AgentDefinitionSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionUpdateRequest {
    pub agent_def_ref: EntityId,
    pub expected_version: String,
    pub definition: AgentDefinitionSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionRequest {
    pub agent_def_ref: EntityId,
}

/// The persisted currentness axis, using its canonical wire spellings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentDefinitionLifecycle {
    Active,
    Superseded,
    Retracted,
}

impl From<ClaimLifecycleStatus> for AgentDefinitionLifecycle {
    fn from(status: ClaimLifecycleStatus) -> Self {
        match status {
            ClaimLifecycleStatus::Active => Self::Active,
            ClaimLifecycleStatus::Superseded => Self::Superseded,
            ClaimLifecycleStatus::Retracted => Self::Retracted,
        }
    }
}

/// The saved revision; its ceiling is a self-limit, never a dispatch grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDefinitionView {
    pub agent_def_ref: EntityId,
    pub definition: AgentDefinitionSpec,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: AgentDefinitionLifecycle,
}

fn view(agent_def_ref: EntityId, definition: &AgentDefinition) -> AgentDefinitionView {
    AgentDefinitionView {
        agent_def_ref,
        definition: definition.into(),
        approval_status: definition.approval_status,
        lifecycle_status: definition.lifecycle_status.into(),
    }
}

fn load(vault: &Vault, id: EntityId) -> MemoryResult<AgentDefinition> {
    vault.get_agent_definition(&id)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "agent definition not found",
            &["Name an existing AGENT_DEF."],
        )
    })
}

pub fn create_agent_definition_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDefinitionCreateRequest,
) -> MemoryResult<AgentDefinitionView> {
    let definition = input.definition.definition(owner.revalidate(vault)?);
    let now = crate::unix_seconds_now();
    vault.create_agent_definition_as(
        owner,
        &input.agent_def_ref,
        &definition,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(view(input.agent_def_ref, &definition))
}

pub fn update_agent_definition_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDefinitionUpdateRequest,
) -> MemoryResult<AgentDefinitionView> {
    owner.revalidate(vault)?;
    let mut definition = load(vault, input.agent_def_ref)?;
    input.definition.apply(&mut definition);
    let now = crate::unix_seconds_now();
    vault.update_agent_definition_at_version_as(
        owner,
        &input.agent_def_ref,
        &input.expected_version,
        &definition,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(view(input.agent_def_ref, &definition))
}

pub fn read_agent_definition_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDefinitionRequest,
) -> MemoryResult<AgentDefinitionView> {
    owner.revalidate(vault)?;
    Ok(view(
        input.agent_def_ref,
        &load(vault, input.agent_def_ref)?,
    ))
}
