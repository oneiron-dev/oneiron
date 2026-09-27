//! Bounded guest definition request; actor, lease and approval stay host-owned.

use rmpv::Value;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope, McpRef};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::llm::ModelTierRef;
use crate::skill::SkillDependency;
use crate::{EntityId, Error, Result, TimeRange};

use super::SelfAgentDefinitionPutCall;

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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
    let scope = match draft.scope.unwrap_or(DraftScope::All) {
        DraftScope::All => AgentScope::All,
        DraftScope::Base => AgentScope::Base,
        DraftScope::World { world } => AgentScope::World(EntityId::from_hex(&world)?),
    };
    let ceiling = draft
        .ceiling
        .as_deref()
        .map(AgentCeiling::parse)
        .unwrap_or(Some(AgentCeiling::Proposed))
        .ok_or_else(|| Error::InvalidConfig("invalid agent ceiling".into()))?;
    let definition = AgentDefinition::new(
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
    );
    Ok(SelfAgentDefinitionPutCall {
        id: EntityId::from_hex(id)?,
        definition: Box::new(definition),
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
    })
}
