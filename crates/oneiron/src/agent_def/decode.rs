//! Per-field MessagePack decoders, the validate_* ladder, and text helpers.

use super::types::{
    AGENT_DESC_MAX_BYTES, AGENT_DISPLAY_NAME_MAX_BYTES, AGENT_ID_MAX_BYTES,
    AGENT_INSTRUCTIONS_MAX_BYTES, AGENT_LOGICAL_ID_MAX_BYTES, AGENT_MAX_LIST_ENTRIES,
    AGENT_MODEL_TIER_MAX_BYTES, AGENT_REF_KEY_MAX_BYTES, AGENT_VERSION_MAX_BYTES, AgentDefinition,
    CONTEXT_BUDGET_SPLIT_KEYS, CompactionOwnership, ContextBudgetSplit, KEY_DEP_MIN_VERSION,
    KEY_DEP_SKILL_ID, KEY_MCP_KEY, KEY_MCP_MIN_VERSION, KEY_PROFILE_BUDGET_SPLIT,
    KEY_PROFILE_COMPACTION, KEY_PROFILE_COMPACTION_BACKEND, KEY_PROFILE_WINDOW_TOKEN_BUDGET,
    MCP_REF_KEYS, MEMORY_PROFILE_KEYS, McpRef, MemoryProfile,
};
use crate::claim::ClaimSource;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::ModelTierRef;
use crate::skill::{SKILL_DEPENDENCY_KEYS, SkillDependency};
use rmpv::Value;
use std::collections::HashSet;

/// Strict [`MemoryProfile`] sub-map decode, mirroring the parent map's
/// discipline exactly: non-map value, non-string keys, unknown keys and
/// duplicate keys are all refused.
pub(super) fn decode_memory_profile(value: &Value) -> Result<MemoryProfile> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "memory_profile must be a MessagePack map",
        )));
    };

    let mut window_token_budget = None;
    let mut budget_split = None;
    let mut compaction_backend = None;
    let mut compaction = None;
    let mut seen = [false; MEMORY_PROFILE_KEYS.len()];

    for (entry_key, value) in entries {
        let Some(entry_key) = entry_key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "memory_profile keys must be strings",
            )));
        };
        let Some(index) = MEMORY_PROFILE_KEYS
            .iter()
            .position(|known| *known == entry_key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "memory_profile key is not in the pinned MEMORY_PROFILE_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate memory_profile key",
            )));
        }
        seen[index] = true;
        match MEMORY_PROFILE_KEYS[index] {
            KEY_PROFILE_WINDOW_TOKEN_BUDGET => {
                window_token_budget = Some(value.as_u64().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDefBody(
                        "memory_profile window_token_budget must be an unsigned integer",
                    ),
                ))?);
            }
            KEY_PROFILE_BUDGET_SPLIT => {
                budget_split = Some(decode_context_budget_split(value)?);
            }
            KEY_PROFILE_COMPACTION_BACKEND => {
                let tier = text_value(
                    value,
                    AGENT_MODEL_TIER_MAX_BYTES,
                    "memory_profile compaction_backend must be a non-empty UTF-8 string at most 256 bytes",
                )?;
                compaction_backend = Some(ModelTierRef(tier));
            }
            KEY_PROFILE_COMPACTION => {
                let text =
                    value
                        .as_str()
                        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                            "memory_profile compaction must be one of engine|byoa",
                        )))?;
                compaction = Some(CompactionOwnership::parse(text)?);
            }
            _ => unreachable!("index resolved from MEMORY_PROFILE_KEYS"),
        }
    }

    Ok(MemoryProfile {
        window_token_budget: window_token_budget.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody(
                "missing required memory_profile key window_token_budget",
            ),
        ))?,
        budget_split,
        compaction_backend: compaction_backend.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody(
                "missing required memory_profile key compaction_backend",
            ),
        ))?,
        compaction: compaction.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required memory_profile key compaction",
        )))?,
    })
}

fn decode_context_budget_split(value: &Value) -> Result<ContextBudgetSplit> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "budget_split must be a MessagePack map",
        )));
    };

    let mut fractions = [None; CONTEXT_BUDGET_SPLIT_KEYS.len()];

    for (entry_key, value) in entries {
        let Some(entry_key) = entry_key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "budget_split keys must be strings",
            )));
        };
        let Some(index) = CONTEXT_BUDGET_SPLIT_KEYS
            .iter()
            .position(|known| *known == entry_key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "budget_split key is not in the pinned CONTEXT_BUDGET_SPLIT_KEYS set",
            )));
        };
        if fractions[index].is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate budget_split key",
            )));
        }
        let Value::F32(fraction) = value else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "budget_split fractions must be 32-bit floats",
            )));
        };
        fractions[index] = Some(*fraction);
    }

    let missing = || {
        Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required budget_split key",
        ))
    };
    Ok(ContextBudgetSplit {
        claims: fractions[0].ok_or_else(missing)?,
        turns: fractions[1].ok_or_else(missing)?,
        summaries: fractions[2].ok_or_else(missing)?,
        other: fractions[3].ok_or_else(missing)?,
    })
}

pub(super) fn encode_mcp_ref(mcp: &McpRef) -> Value {
    Value::Map(vec![
        (Value::from(KEY_MCP_KEY), Value::from(mcp.key.as_str())),
        (
            Value::from(KEY_MCP_MIN_VERSION),
            mcp.min_version.as_deref().map_or(Value::Nil, Value::from),
        ),
    ])
}

pub(super) fn decode_skill_dependencies(value: &Value) -> Result<Vec<SkillDependency>> {
    let Value::Array(values) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "skills must be a MessagePack array",
        )));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "skills must contain at most 64 entries",
        )));
    }
    values.iter().map(decode_skill_dependency).collect()
}

fn decode_skill_dependency(value: &Value) -> Result<SkillDependency> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "skill dependency must be a MessagePack map",
        )));
    };

    let mut skill_id = None;
    let mut min_version = None;
    let mut seen = [false; SKILL_DEPENDENCY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "skill dependency keys must be strings",
            )));
        };
        let Some(index) = SKILL_DEPENDENCY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "skill dependency key must be skillId|minVersion",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate skill dependency key",
            )));
        }
        seen[index] = true;
        match SKILL_DEPENDENCY_KEYS[index] {
            KEY_DEP_SKILL_ID => {
                skill_id = Some(text_value(
                    value,
                    AGENT_REF_KEY_MAX_BYTES,
                    "skill dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DEP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        AGENT_VERSION_MAX_BYTES,
                        "skill dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
                    )?),
                });
            }
            _ => unreachable!("index resolved from SKILL_DEPENDENCY_KEYS"),
        }
    }

    Ok(SkillDependency {
        skill_id: skill_id.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required skill dependency key skillId",
        )))?,
        min_version: min_version.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required skill dependency key minVersion",
        )))?,
    })
}

pub(super) fn decode_connectors(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "connectors must be a MessagePack array",
        )));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "connectors must contain at most 64 entries",
        )));
    }
    values
        .iter()
        .map(|value| {
            text_value(
                value,
                AGENT_REF_KEY_MAX_BYTES,
                "connector key must be a non-empty UTF-8 string at most 256 bytes",
            )
        })
        .collect()
}

pub(super) fn decode_mcp_refs(value: &Value) -> Result<Vec<McpRef>> {
    let Value::Array(values) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "codeModeMcps must be a MessagePack array",
        )));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "codeModeMcps must contain at most 64 entries",
        )));
    }
    values.iter().map(decode_mcp_ref).collect()
}

fn decode_mcp_ref(value: &Value) -> Result<McpRef> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "MCP ref must be a MessagePack map",
        )));
    };

    let mut key = None;
    let mut min_version = None;
    let mut seen = [false; MCP_REF_KEYS.len()];

    for (entry_key, value) in entries {
        let Some(entry_key) = entry_key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "MCP ref keys must be strings",
            )));
        };
        let Some(index) = MCP_REF_KEYS.iter().position(|known| *known == entry_key) else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "MCP ref key must be key|minVersion",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate MCP ref key",
            )));
        }
        seen[index] = true;
        match MCP_REF_KEYS[index] {
            KEY_MCP_KEY => {
                key = Some(text_value(
                    value,
                    AGENT_REF_KEY_MAX_BYTES,
                    "MCP ref key must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_MCP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        AGENT_VERSION_MAX_BYTES,
                        "MCP ref minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
                    )?),
                });
            }
            _ => unreachable!("index resolved from MCP_REF_KEYS"),
        }
    }

    Ok(McpRef {
        key: key.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required MCP ref key key",
        )))?,
        min_version: min_version.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required MCP ref key minVersion",
        )))?,
    })
}

pub(super) fn validate_agent_definition(def: &AgentDefinition) -> Result<()> {
    validate_text_field(
        &def.agent_id,
        AGENT_ID_MAX_BYTES,
        "agentId must be a non-empty UTF-8 string at most 256 bytes",
    )?;
    validate_text_field(
        &def.desc,
        AGENT_DESC_MAX_BYTES,
        "desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text_field(
        &def.version,
        AGENT_VERSION_MAX_BYTES,
        "version must be a non-empty UTF-8 string at most 128 bytes",
    )?;
    if let Some(instructions) = &def.instructions {
        validate_text_field(
            instructions,
            AGENT_INSTRUCTIONS_MAX_BYTES,
            "instructions must be a non-empty UTF-8 string at most 16384 bytes",
        )?;
    }
    if let Some(model_tier) = &def.model_tier {
        validate_text_field(
            model_tier.as_str(),
            AGENT_MODEL_TIER_MAX_BYTES,
            "modelTier must be a non-empty UTF-8 string at most 256 bytes",
        )?;
    }
    if let Some(logical_id) = &def.logical_id {
        validate_text_field(
            logical_id,
            AGENT_LOGICAL_ID_MAX_BYTES,
            "logicalId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
    }
    if let Some(display_name) = &def.display_name {
        validate_text_field(
            display_name,
            AGENT_DISPLAY_NAME_MAX_BYTES,
            "displayName must be a non-empty UTF-8 string at most 256 bytes",
        )?;
    }
    if !def.confidence.is_finite() || !(0.0..=1.0).contains(&def.confidence) {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "confidence must be finite in the unit interval",
        )));
    }
    if def.generated == def.human_authored {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "exactly one of generated or humanAuthored must be true",
        )));
    }
    if def.generated != (def.source == ClaimSource::Generated) {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "generated flag must match generated source",
        )));
    }
    validate_provenance(&def.provenance)?;
    validate_skill_dependencies(&def.skills)?;
    validate_connectors(&def.connectors)?;
    validate_mcp_refs(&def.code_mode_mcps)?;
    if let Some(profile) = &def.memory_profile {
        validate_memory_profile(profile)?;
    }
    Ok(())
}

/// RT-05 profile validation (ONE-1687). Rides the existing
/// [`ArtifactError::InvalidAgentDefBody`](crate::error::ArtifactError::InvalidAgentDefBody) axis — no new error family.
///
/// The frontier-tier ban is deliberately NOT here: decode holds no vault and
/// no registry, so a string sniff would be the wrong authority. It fires at
/// backend resolution instead, where the registered tier class is known.
fn validate_memory_profile(profile: &MemoryProfile) -> Result<()> {
    if profile.window_token_budget == 0 {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "memory_profile window_token_budget must be greater than zero",
        )));
    }
    validate_text_field(
        profile.compaction_backend.as_str(),
        AGENT_MODEL_TIER_MAX_BYTES,
        "memory_profile compaction_backend must be a non-empty UTF-8 string at most 256 bytes",
    )?;
    if let Some(split) = profile.budget_split {
        let fractions = [split.claims, split.turns, split.summaries, split.other];
        if fractions
            .iter()
            .any(|f| !f.is_finite() || *f <= 0.0 || *f >= 1.0)
        {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "memory_profile budget_split fractions must be finite and inside (0.0, 1.0)",
            )));
        }
        let sum: f32 = fractions.iter().sum();
        if (sum - 1.0).abs() > 1e-6 {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "memory_profile budget_split fractions must sum to 1.0",
            )));
        }
    }
    Ok(())
}

fn validate_provenance(provenance: &Value) -> Result<()> {
    let Value::Map(entries) = provenance else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "provenance must be a non-empty MessagePack map",
        )));
    };
    if entries.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "provenance must be a non-empty MessagePack map",
        )));
    }
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "provenance keys must be strings",
            )));
        };
        if key.trim().is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "provenance keys must be non-empty strings",
            )));
        }
        if !seen.insert(key) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate provenance key",
            )));
        }
    }
    Ok(())
}

fn validate_skill_dependencies(skills: &[SkillDependency]) -> Result<()> {
    if skills.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "skills must contain at most 64 entries",
        )));
    }
    let mut seen = HashSet::new();
    for dependency in skills {
        validate_text_field(
            &dependency.skill_id,
            AGENT_REF_KEY_MAX_BYTES,
            "skill dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if !seen.insert(dependency.skill_id.as_str()) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate skill dependency",
            )));
        }
        if let Some(min_version) = &dependency.min_version {
            validate_text_field(
                min_version,
                AGENT_VERSION_MAX_BYTES,
                "skill dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

fn validate_connectors(connectors: &[String]) -> Result<()> {
    if connectors.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "connectors must contain at most 64 entries",
        )));
    }
    let mut seen = HashSet::new();
    for connector in connectors {
        validate_text_field(
            connector,
            AGENT_REF_KEY_MAX_BYTES,
            "connector key must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if !seen.insert(connector.as_str()) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate connector",
            )));
        }
    }
    Ok(())
}

fn validate_mcp_refs(mcps: &[McpRef]) -> Result<()> {
    if mcps.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "codeModeMcps must contain at most 64 entries",
        )));
    }
    let mut seen = HashSet::new();
    for mcp in mcps {
        validate_text_field(
            &mcp.key,
            AGENT_REF_KEY_MAX_BYTES,
            "MCP ref key must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if !seen.insert(mcp.key.as_str()) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate MCP ref",
            )));
        }
        if let Some(min_version) = &mcp.min_version {
            validate_text_field(
                min_version,
                AGENT_VERSION_MAX_BYTES,
                "MCP ref minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

pub(super) fn text_value(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value
        .as_str()
        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(context)))?;
    validate_text_field(text, max_bytes, context)?;
    Ok(text.to_owned())
}

pub(super) fn validate_text_field(
    text: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(context)));
    }
    Ok(())
}
