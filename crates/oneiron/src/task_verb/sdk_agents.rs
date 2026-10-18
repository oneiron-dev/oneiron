//! Typed custom AGENT_DEF authoring. Authorship is the caller's, never input.
use serde::{Deserialize, Serialize};

use crate::agent_def::{
    AgentCeiling, AgentDefinition, AgentModel, AgentScope, McpRef, RefusalDial,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::llm::{ModelId, ModelTierRef};
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::skill::SkillDependency;
use crate::{EntityId, TimeRange, Vault};

/// A versioned composition reference, not an installed capability or grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSkillInput {
    pub skill_id: String,
    #[serde(default)]
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMcpInput {
    pub key: String,
    #[serde(default)]
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentScopeInput {
    #[default]
    All,
    Base,
    World {
        world: EntityId,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentCeilingInput {
    Auto,
    #[default]
    Proposed,
}

/// The authored composition. Importing one is the same inert create as
/// defining one locally; it cannot import approval, provenance or a system id.
/// Memory-profile and dreaming dials are not changed by this door.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionSpec {
    pub agent_id: String,
    pub desc: String,
    pub version: String,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub skills: Vec<AgentSkillInput>,
    #[serde(default)]
    pub connectors: Vec<String>,
    #[serde(default)]
    pub code_mode_mcps: Vec<AgentMcpInput>,
    #[serde(default)]
    pub model_tier: Option<String>,
    #[serde(default)]
    pub scope: AgentScopeInput,
    #[serde(default)]
    pub ceiling: AgentCeilingInput,
    #[serde(default)]
    pub forked_from: Option<EntityId>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Per-domain refusal settings. Omit or clear for vault-kind defaults;
    /// an explicit dial must set at least one domain. This grants no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<RefusalDial>,
    /// The models the agent may run on, in order, each with the owner's
    /// words on when it takes that model (FIX 4472). Empty: its one
    /// house-routed model. A wake runs only on a listed model.
    #[serde(default)]
    pub models: Vec<AgentModel>,
    /// The model that compacts the agent's window; absent takes the house's.
    /// It need not be listed.
    #[serde(default)]
    pub compaction_model: Option<ModelId>,
}

fn enabled_by_default() -> bool {
    true
}

impl AgentDefinitionSpec {
    pub(crate) fn definition(&self, author: EntityId) -> AgentDefinition {
        let mut definition = AgentDefinition::new(
            &self.agent_id,
            &self.desc,
            &self.version,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            AgentScope::All,
            AgentCeiling::Proposed,
            None,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("author"),
                    rmpv::Value::from(author.to_hex()),
                ),
                (
                    rmpv::Value::from("definedVia"),
                    rmpv::Value::from("typed_agent_definition"),
                ),
            ]),
            None,
            true,
            None,
        );
        self.apply(&mut definition);
        definition
    }

    fn apply(&self, definition: &mut AgentDefinition) {
        definition.agent_id = self.agent_id.clone();
        definition.desc = self.desc.clone();
        definition.version = self.version.clone();
        definition.instructions = self.instructions.clone();
        definition.skills = self
            .skills
            .iter()
            .map(|skill| {
                let mut dependency = SkillDependency::new(&skill.skill_id);
                dependency.min_version = skill.min_version.clone();
                dependency
            })
            .collect();
        definition.connectors = self.connectors.clone();
        definition.code_mode_mcps = self
            .code_mode_mcps
            .iter()
            .map(|mcp| {
                let mut reference = McpRef::new(&mcp.key);
                reference.min_version = mcp.min_version.clone();
                reference
            })
            .collect();
        definition.model_tier = self.model_tier.clone().map(ModelTierRef);
        definition.scope = match self.scope {
            AgentScopeInput::All => AgentScope::All,
            AgentScopeInput::Base => AgentScope::Base,
            AgentScopeInput::World { world } => AgentScope::World(world),
        };
        definition.ceiling = match self.ceiling {
            AgentCeilingInput::Auto => AgentCeiling::Auto,
            AgentCeilingInput::Proposed => AgentCeiling::Proposed,
        };
        definition.forked_from = self.forked_from;
        definition.enabled = self.enabled;
        definition.display_name = self.display_name.clone();
        definition.refusal = self.refusal;
        definition.models = self.models.clone();
        definition.compaction_model = self.compaction_model.clone();
    }
}

impl From<&AgentDefinition> for AgentDefinitionSpec {
    fn from(definition: &AgentDefinition) -> Self {
        Self {
            agent_id: definition.agent_id.clone(),
            desc: definition.desc.clone(),
            version: definition.version.clone(),
            instructions: definition.instructions.clone(),
            skills: definition
                .skills
                .iter()
                .map(|skill| AgentSkillInput {
                    skill_id: skill.skill_id.clone(),
                    min_version: skill.min_version.clone(),
                })
                .collect(),
            connectors: definition.connectors.clone(),
            code_mode_mcps: definition
                .code_mode_mcps
                .iter()
                .map(|mcp| AgentMcpInput {
                    key: mcp.key.clone(),
                    min_version: mcp.min_version.clone(),
                })
                .collect(),
            model_tier: definition.model_tier.as_ref().map(|tier| tier.0.clone()),
            scope: match definition.scope {
                AgentScope::All => AgentScopeInput::All,
                AgentScope::Base => AgentScopeInput::Base,
                AgentScope::World(world) => AgentScopeInput::World { world },
            },
            ceiling: match definition.ceiling {
                AgentCeiling::Auto => AgentCeilingInput::Auto,
                AgentCeiling::Proposed => AgentCeilingInput::Proposed,
            },
            forked_from: definition.forked_from,
            enabled: definition.enabled,
            display_name: definition.display_name.clone(),
            refusal: definition.refusal,
            models: definition.models.clone(),
            compaction_model: definition.compaction_model.clone(),
        }
    }
}

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
