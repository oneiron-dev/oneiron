//! Bounded guest definition request; actor, lease and approval stay host-owned.

use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope, McpRef};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::llm::ModelTierRef;
use crate::skill::SkillDependency;
use crate::{EntityId, Error, Result, TimeRange};

use super::SelfAgentDefinitionPutCall;

#[cfg(test)]
mod tests;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Draft {
    agent_id: String,
    desc: String,
    version: String,
    #[serde(default)]
    instructions: Option<String>,
    #[serde(default)]
    skills: Vec<String>,
    #[serde(default)]
    connectors: Vec<String>,
    #[serde(default)]
    code_mode_mcps: Vec<String>,
    #[serde(default)]
    model_tier: Option<String>,
    #[serde(default)]
    scope: Option<DraftScope>,
    #[serde(default)]
    ceiling: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DraftScope {
    All,
    Base,
    World { world: String },
}

/// The guest may request composition and self-limits, not authorship,
/// provenance, a parent attempt, an approval stamp, or a system logical id.
pub(crate) fn parse_agent_put_request(
    id: &str,
    definition: JsonValue,
    now: u64,
) -> Result<SelfAgentDefinitionPutCall> {
    if serde_json::to_vec(&definition).map_or(true, |body| body.len() > 32 * 1024) {
        return Err(Error::InvalidConfig(
            "agent definition request exceeds 32 KiB".into(),
        ));
    }
    let draft: Draft = serde_json::from_value(definition)
        .map_err(|_| Error::InvalidConfig("invalid agent definition request".into()))?;
    Ok(SelfAgentDefinitionPutCall {
        id: EntityId::from_hex(id)?,
        definition: Box::new(draft_definition(draft)?),
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
    })
}

/// The draft a hook reads for `definition`: the guest's own fields, in the
/// request's shape. `None` when the definition holds more than a draft
/// writes, so a rewrite from it would lose that.
pub(crate) fn agent_put_draft(definition: &AgentDefinition) -> Option<JsonValue> {
    let draft = Draft {
        agent_id: definition.agent_id.clone(),
        desc: definition.desc.clone(),
        version: definition.version.clone(),
        instructions: definition.instructions.clone(),
        skills: definition
            .skills
            .iter()
            .map(|skill| skill.skill_id.clone())
            .collect(),
        connectors: definition.connectors.clone(),
        code_mode_mcps: definition
            .code_mode_mcps
            .iter()
            .map(|mcp| mcp.key.clone())
            .collect(),
        model_tier: definition.model_tier.as_ref().map(|tier| tier.0.clone()),
        scope: Some(match &definition.scope {
            AgentScope::All => DraftScope::All,
            AgentScope::Base => DraftScope::Base,
            AgentScope::World(world) => DraftScope::World {
                world: world.to_hex(),
            },
        }),
        ceiling: Some(definition.ceiling.as_str().to_owned()),
        enabled: Some(definition.enabled),
        display_name: definition.display_name.clone(),
    };
    let value = serde_json::to_value(&draft).ok()?;
    (draft_definition(draft).ok()? == *definition).then_some(value)
}

/// The definition a draft requests, under the host's own approval, source
/// and provenance.
fn draft_definition(draft: Draft) -> Result<AgentDefinition> {
    let scope = match draft.scope.unwrap_or(DraftScope::All) {
        DraftScope::All => AgentScope::All,
        DraftScope::Base => AgentScope::Base,
        DraftScope::World { world } => AgentScope::World(EntityId::from_hex(&world)?),
    };
    let ceiling = draft
        .ceiling
        .as_deref()
        .map_or(Some(AgentCeiling::Proposed), AgentCeiling::parse)
        .ok_or_else(|| Error::InvalidConfig("invalid agent ceiling".into()))?;
    Ok(AgentDefinition::new(
        draft.agent_id,
        draft.desc,
        draft.version,
        draft.instructions,
        draft.skills.into_iter().map(SkillDependency::new).collect(),
        draft.connectors,
        draft.code_mode_mcps.into_iter().map(McpRef::new).collect(),
        draft.model_tier.map(ModelTierRef),
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Value::Map(vec![(
            Value::from("surface"),
            Value::from("vault.agents.put"),
        )]),
        None,
        draft.enabled.unwrap_or(true),
        draft.display_name,
    ))
}
