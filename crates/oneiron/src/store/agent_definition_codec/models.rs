//! The AGENT_DEF `models` list and `compaction_model` codec (FIX 4472): the
//! strict decode, the pinned-key encode and the list rules every encode and
//! decode holds.

use oneiron_model::llm::ModelId;
use rmpv::Value;

use super::decode::text_value;
use super::keys::{KEY_MODEL_REF, KEY_MODEL_WHEN};
use crate::error::{ArtifactError, Error, Result};
use crate::store::agent_definition::AgentDefinition;
use crate::store::agent_manifest::validate_text_field;
use crate::store::agent_model::AgentModel;
use crate::store::agent_record::{AGENT_DESC_MAX_BYTES, AGENT_MODEL_TIER_MAX_BYTES};

const MODEL_REF_TEXT: &str = "model entry model_ref must be a provider/name@revision model id";
const WHEN_TEXT: &str = "model entry when must be a non-empty UTF-8 string";
const COMPACTION_MODEL_TEXT: &str = "compaction_model must be a provider/name@revision model id";

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDefBody(reason))
}

/// The `models` value: each entry the [`super::AGENT_MODEL_KEYS`] in pinned
/// order, in the owner's list order.
pub(crate) fn encode_agent_models(models: &[AgentModel]) -> Value {
    Value::Array(
        models
            .iter()
            .map(|model| {
                Value::Map(vec![
                    (
                        Value::from(KEY_MODEL_REF),
                        Value::from(model.model_ref.as_str()),
                    ),
                    (
                        Value::from(KEY_MODEL_WHEN),
                        Value::from(model.when.as_str()),
                    ),
                ])
            })
            .collect(),
    )
}

/// Strict `models` decode: an array of maps, each holding both pinned keys
/// once and nothing else. Every entry is kept, however many (rule 5): the
/// put's scan row asks past its threshold.
pub(crate) fn decode_agent_models(value: &Value) -> Result<Vec<AgentModel>> {
    let Value::Array(values) = value else {
        return Err(invalid("models must be a MessagePack array"));
    };
    values.iter().map(decode_agent_model).collect()
}

fn decode_agent_model(value: &Value) -> Result<AgentModel> {
    let Value::Map(entries) = value else {
        return Err(invalid("model entry must be a MessagePack map"));
    };
    let (mut model_ref, mut when) = (None, None);
    for (key, value) in entries {
        match key.as_str() {
            Some(KEY_MODEL_REF) if model_ref.is_none() => {
                model_ref = Some(decode_model_id(value, MODEL_REF_TEXT)?);
            }
            Some(KEY_MODEL_WHEN) if when.is_none() => {
                when = Some(text_value(value, AGENT_DESC_MAX_BYTES, WHEN_TEXT)?);
            }
            _ => return Err(invalid("unknown or duplicate model entry key")),
        }
    }
    Ok(AgentModel {
        model_ref: model_ref
            .ok_or_else(|| invalid("missing required model entry key model_ref"))?,
        when: when.ok_or_else(|| invalid("missing required model entry key when"))?,
    })
}

/// Strict `compaction_model` decode: one revision-pinned model id.
pub(crate) fn decode_compaction_model(value: &Value) -> Result<ModelId> {
    decode_model_id(value, COMPACTION_MODEL_TEXT)
}

fn decode_model_id(value: &Value, context: &'static str) -> Result<ModelId> {
    ModelId::new(text_value(value, AGENT_MODEL_TIER_MAX_BYTES, context)?)
        .map_err(|_| invalid(context))
}

/// The list rules every encode and decode holds: each entry a model id
/// listed once, with a non-blank `when`, of any length (a put observes
/// their bytes, FIX 10542). The compaction model need not be listed: it
/// compacts the agent's window and runs none of its wakes.
pub(crate) fn validate_agent_models(def: &AgentDefinition) -> Result<()> {
    for (index, model) in def.models.iter().enumerate() {
        validate_text_field(
            model.model_ref.as_str(),
            AGENT_MODEL_TIER_MAX_BYTES,
            MODEL_REF_TEXT,
        )?;
        validate_text_field(&model.when, AGENT_DESC_MAX_BYTES, WHEN_TEXT)?;
        if def.models[..index]
            .iter()
            .any(|listed| listed.model_ref == model.model_ref)
        {
            return Err(invalid("models must not list a model twice"));
        }
    }
    if let Some(model) = &def.compaction_model {
        validate_text_field(
            model.as_str(),
            AGENT_MODEL_TIER_MAX_BYTES,
            COMPACTION_MODEL_TEXT,
        )?;
    }
    Ok(())
}
