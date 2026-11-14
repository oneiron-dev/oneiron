//! Moved from `crates/oneiron/src/llm/routing.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::routing::readings::DescriptionGrading;
pub use crate::store::model_description_rows::DescriptionPolicy;
pub use crate::store::model_description_rows::ModelDescription;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ReasoningEffort;
pub use oneiron_store::model_description_rows::MeasuredDescription;
use oneiron_store::model_description_rows::ModelWireFormat;
pub use oneiron_store::model_description_rows::OwnerModelLine;
use oneiron_verb_wire::llm::seat::DescriptionSource;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

impl ModelDescription {
    /// The first available line in the seat policy's evidence order.
    fn line<'a>(
        &'a self,
        measurement: Option<&'a MeasuredDescription>,
        order: &[DescriptionSource],
    ) -> Option<&'a str> {
        order.iter().find_map(|source| match source {
            DescriptionSource::Owner => self
                .owner
                .as_ref()
                .filter(|line| line.model == self.model)
                .map(|line| line.text.as_str()),
            DescriptionSource::Measured => measurement.map(|line| line.text.as_str()),
            DescriptionSource::Benchmarks => self.public_benchmark.as_deref(),
            DescriptionSource::Vendor => self.vendor.as_deref(),
        })
    }
}

impl DescriptionPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.contradiction_margin_millionths > 1_000_000
            || self.models.is_empty()
            || self.models.iter().any(|row| {
                row.effort_ladder.is_empty()
                    || row.owner.as_ref().is_some_and(|line| {
                        line.text.trim().is_empty()
                            || line.expected_quality > 1_000_000
                            || line.model.provider() != row.model.provider()
                            || line.model.name() != row.model.name()
                    })
                    || (row.owner.is_none()
                        && row.public_benchmark.as_deref().is_none_or(str::is_empty)
                        && row.vendor.as_deref().is_none_or(str::is_empty))
            })
            || self.models.iter().enumerate().any(|(i, row)| {
                self.models[i + 1..]
                    .iter()
                    .any(|other| other.model == row.model)
            })
        {
            return Err(invalid("invalid description routing policy"));
        }
        Ok(())
    }
}

/// Overrides filter the description candidates; they never bypass judgment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatSettings {
    pub allowed_models: Option<Vec<ModelId>>,
    pub effort: Option<ReasoningEffort>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inference_overrides: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaskTrigger {
    RevisionChanged,
    MeasuredContradiction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionReask {
    pub identity: String,
    pub owner_model: ModelId,
    pub observed_model: ModelId,
    pub trigger: ReaskTrigger,
    #[serde(default)]
    pub acknowledged: bool,
}

pub fn validate_overrides(overrides: &BTreeMap<String, serde_json::Value>) -> Result<()> {
    if overrides.keys().any(|key| {
        key.trim().is_empty()
            || matches!(
                key.as_str(),
                "reasoning_effort"
                    | "reasoning"
                    | "thinking"
                    | "model"
                    | "messages"
                    | "stream"
                    | "response_format"
                    | "tools"
                    | "provider_options"
                    | "output_config"
                    | "system"
                    | "cachedContent"
                    | "thinkingConfig"
                    | "thinking_config"
            )
    }) {
        return Err(invalid("invalid routed inference override"));
    }
    Ok(())
}

/// The Gemini adapter spells these five public params differently on the
/// wire. Seat overrides compare and write the effective wire field, not the
/// caller's spelling, so a later alias cannot win during adapter iteration.
pub fn gemini_wire_field(key: &str) -> &str {
    match key {
        "max_tokens" => "maxOutputTokens",
        "top_p" => "topP",
        "top_k" => "topK",
        "presence_penalty" => "presencePenalty",
        "frequency_penalty" => "frequencyPenalty",
        other => other,
    }
}

/// Reject fields that would win after the adapter merges provider options.
/// Unknown provider-specific fields remain available, but cannot shadow a
/// routed inference setting or carry a competing reasoning dial.
pub fn apply_controls(
    request: &mut LlmRequest,
    wire: ModelWireFormat,
    effort: ReasoningEffort,
    overrides: &BTreeMap<String, serde_json::Value>,
) -> Result<()> {
    validate_overrides(overrides)?;
    let mut resolved_overrides = BTreeMap::new();
    for (key, value) in overrides {
        let wire_key = if wire == ModelWireFormat::Gemini {
            gemini_wire_field(key)
        } else {
            key
        };
        if resolved_overrides
            .insert(wire_key.to_owned(), value.clone())
            .is_some()
        {
            return Err(invalid("duplicate routed provider parameter"));
        }
    }
    for options in request.provider_options.values() {
        let fields = options
            .as_object()
            .ok_or_else(|| invalid("invalid provider options"))?;
        if fields.keys().any(|key| {
            resolved_overrides.contains_key(if wire == ModelWireFormat::Gemini {
                gemini_wire_field(key)
            } else {
                key
            }) || matches!(
                key.as_str(),
                "reasoning_effort"
                    | "reasoning"
                    | "thinking"
                    | "thinkingConfig"
                    | "thinking_config"
                    | "output_config"
                    | "model"
            )
        }) {
            return Err(invalid("provider options shadow routed inference controls"));
        }
    }
    // The Anthropic adapter merges output_config into its final wire JSON.
    // Preserve independent format/limits, but never the call's effort.
    let mut output_config = match request.params.get("output_config") {
        Some(serde_json::Value::Object(fields)) if wire == ModelWireFormat::AnthropicMessages => {
            Some(fields.clone())
        }
        Some(_) => return Err(invalid("invalid routed output_config")),
        None => None,
    };
    // Gemini has no effort enum mapping without an owner-supplied budget.
    // Refuse an unsupported non-None setting instead of misreporting it.
    if effort != ReasoningEffort::None && wire == ModelWireFormat::Gemini {
        return Err(invalid(
            "Gemini effort requires an explicit provider policy",
        ));
    }
    request.params.retain(|key, _| {
        let wire_key = if wire == ModelWireFormat::Gemini {
            gemini_wire_field(key)
        } else {
            key
        };
        !resolved_overrides.contains_key(wire_key)
    });
    request.params.extend(resolved_overrides);
    request.params.remove("reasoning");
    request.params.remove("thinking");
    request.params.remove("thinkingConfig");
    request.params.remove("thinking_config");
    request.params.remove("reasoning_effort");
    request.params.remove("output_config");
    if let Some(fields) = output_config.as_mut() {
        fields.remove("effort");
    }
    if effort != ReasoningEffort::None {
        if wire == ModelWireFormat::AnthropicMessages {
            output_config
                .get_or_insert_with(serde_json::Map::new)
                .insert("effort".into(), serde_json::json!(effort));
        } else {
            request
                .params
                .insert("reasoning_effort".into(), serde_json::json!(effort));
        }
    }
    if let Some(fields) = output_config.filter(|fields| !fields.is_empty()) {
        request
            .params
            .insert("output_config".into(), serde_json::Value::Object(fields));
    }
    Ok(())
}
pub mod readings;
