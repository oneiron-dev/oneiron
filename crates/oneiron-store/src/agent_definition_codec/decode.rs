//! Per-field MessagePack decoders, the validate_* ladder, and text helpers.

use crate::agent_definition_codec::keys::KEY_DEP_MIN_VERSION;
use crate::agent_definition_codec::keys::KEY_DEP_SKILL_ID;
use crate::agent_definition_codec::keys::MAX_MEMORY_PROFILE_VERBATIM_PIN_BYTES;
use crate::agent_definition_codec::keys::OUTPUT_DECAY_KEYS;
use crate::agent_manifest::AGENT_DISPLAY_NAME_MAX_BYTES;
use crate::agent_manifest::AGENT_LOGICAL_ID_MAX_BYTES;
use crate::agent_manifest::validate_text_field;
use crate::agent_record::AGENT_DESC_MAX_BYTES;
use crate::agent_record::AGENT_ID_MAX_BYTES;
use crate::agent_record::AGENT_INSTRUCTIONS_MAX_BYTES;
use crate::agent_record::AGENT_MODEL_TIER_MAX_BYTES;
use crate::agent_record::AGENT_REF_KEY_MAX_BYTES;
use crate::agent_record::AGENT_VERSION_MAX_BYTES;
use crate::agent_record::CONTEXT_BUDGET_SPLIT_KEYS;
use crate::agent_record::CompactionOwnership;
use crate::agent_record::MCP_REF_KEYS;
use crate::agent_record::MEMORY_PROFILE_KEYS;
use crate::write_envelope::skill_record::{SKILL_DEPENDENCY_KEYS, SkillDependency};
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimSource;
use oneiron_model::llm::ModelTierRef;
use rmpv::Value;
use std::collections::HashSet;

pub fn decode_skill_dependencies(value: &Value) -> Result<Vec<SkillDependency>> {
    let Value::Array(values) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "skills must be a MessagePack array",
        )));
    };
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
                    "skill dependency skillId must be a non-empty UTF-8 string",
                )?);
            }
            KEY_DEP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        AGENT_VERSION_MAX_BYTES,
                        "skill dependency minVersion must be nil or a non-empty UTF-8 string",
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

pub fn decode_connectors(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "connectors must be a MessagePack array",
        )));
    };
    values
        .iter()
        .map(|value| {
            text_value(
                value,
                AGENT_REF_KEY_MAX_BYTES,
                "connector key must be a non-empty UTF-8 string",
            )
        })
        .collect()
}

pub fn validate_provenance(provenance: &Value) -> Result<()> {
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

pub fn validate_skill_dependencies(skills: &[SkillDependency]) -> Result<()> {
    let mut seen = HashSet::new();
    for dependency in skills {
        validate_text_field(
            &dependency.skill_id,
            AGENT_REF_KEY_MAX_BYTES,
            "skill dependency skillId must be a non-empty UTF-8 string",
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
                "skill dependency minVersion must be nil or a non-empty UTF-8 string",
            )?;
        }
    }
    Ok(())
}

pub fn validate_connectors(connectors: &[String]) -> Result<()> {
    let mut seen = HashSet::new();
    for connector in connectors {
        validate_text_field(
            connector,
            AGENT_REF_KEY_MAX_BYTES,
            "connector key must be a non-empty UTF-8 string",
        )?;
        if !seen.insert(connector.as_str()) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate connector",
            )));
        }
    }
    Ok(())
}

pub fn text_value(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value
        .as_str()
        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(context)))?;
    validate_text_field(text, max_bytes, context)?;
    Ok(text.to_owned())
}
