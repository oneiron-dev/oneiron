//! Request validation and metadata capability probing with key normalization.
use std::collections::BTreeMap;

use oneiron::{
    ContentPart, FatalLlmError, LlmCapability, LlmCatalogEntry, LlmRequest, LlmResult,
    ResponseFormat, UnsupportedCapability,
};
use serde_json::Value as JsonValue;

pub(crate) fn validate_request(
    request: &LlmRequest,
    descriptor: &LlmCatalogEntry,
) -> LlmResult<()> {
    if request.model != descriptor.model {
        return Err(FatalLlmError::InvalidRequest.into());
    }

    if !request.tools.is_empty() {
        require_capability(
            descriptor,
            LlmCapability::ToolCalling,
            "loaded model metadata does not advertise tool calling",
        )?;
    }

    if request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .any(|part| matches!(part, ContentPart::ToolResult { .. }))
    {
        require_capability(
            descriptor,
            LlmCapability::ToolResults,
            "loaded model metadata does not advertise tool-result replay",
        )?;
    }

    if request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .any(|part| matches!(part, ContentPart::Image { .. }))
    {
        require_capability(
            descriptor,
            LlmCapability::ImageInput,
            "loaded model metadata does not advertise image input",
        )?;
    }

    if matches!(
        request.envelope.response_format,
        ResponseFormat::Json { .. }
    ) {
        require_capability(
            descriptor,
            LlmCapability::JsonResponse,
            "loaded model metadata does not advertise JSON response mode",
        )?;
    }

    Ok(())
}

pub(crate) fn require_capability(
    descriptor: &LlmCatalogEntry,
    capability: LlmCapability,
    reason: &'static str,
) -> LlmResult<()> {
    if descriptor.supports(&capability) {
        Ok(())
    } else {
        Err(FatalLlmError::Unsupported(UnsupportedCapability {
            capability,
            model: Some(descriptor.model.clone()),
            reason: Some(reason.to_owned()),
        })
        .into())
    }
}

pub(crate) fn push_capability(capabilities: &mut Vec<LlmCapability>, capability: LlmCapability) {
    if !capabilities.contains(&capability) {
        capabilities.push(capability);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CapabilityProbe {
    JsonResponse,
    ImageInput,
    Reasoning,
    Voice,
}

pub(crate) fn metadata_declares_tool_calling(metadata: &BTreeMap<String, JsonValue>) -> bool {
    metadata.iter().any(|(key, value)| {
        key_declares_tool_calling(key, value)
            || capability_list_contains(value, "tool_calling")
            || value_declares_tool_calling(value)
    })
}

fn value_declares_tool_calling(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            key_declares_tool_calling(key, value)
                || capability_list_contains(value, "tool_calling")
                || value_declares_tool_calling(value)
        }),
        JsonValue::Array(values) => values.iter().any(value_declares_tool_calling),
        JsonValue::String(value) => template_has_tool_calling(value),
        _ => false,
    }
}

fn key_declares_tool_calling(key: &str, value: &JsonValue) -> bool {
    let normalized = normalize_key(key);
    matches!(
        normalized.as_str(),
        "tool_calling"
            | "tool_calls"
            | "supports_tools"
            | "supports_tool_calls"
            | "tool_use"
            | "function_calling"
    ) && truthy(value)
        || (normalized.contains("chat_template")
            && value.as_str().is_some_and(template_has_tool_calling))
}

pub(crate) fn metadata_declares_capability(
    metadata: &BTreeMap<String, JsonValue>,
    probe: CapabilityProbe,
) -> bool {
    metadata
        .iter()
        .any(|(key, value)| key_declares_capability(key, value, probe))
}

fn value_declares_capability(value: &JsonValue, probe: CapabilityProbe) -> bool {
    match value {
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            key_declares_capability(key, value, probe) || value_declares_capability(value, probe)
        }),
        JsonValue::Array(values) => values
            .iter()
            .any(|value| value_declares_capability(value, probe)),
        _ => false,
    }
}

fn key_declares_capability(key: &str, value: &JsonValue, probe: CapabilityProbe) -> bool {
    if capability_list_contains(value, probe.capability_name()) {
        return true;
    }

    let normalized = normalize_key(key);
    probe
        .key_aliases()
        .iter()
        .any(|alias| normalized == *alias && truthy(value))
        || value_declares_capability(value, probe)
}

impl CapabilityProbe {
    fn capability_name(self) -> &'static str {
        match self {
            Self::JsonResponse => "json_response",
            Self::ImageInput => "image_input",
            Self::Reasoning => "reasoning",
            Self::Voice => "voice",
        }
    }

    fn key_aliases(self) -> &'static [&'static str] {
        match self {
            Self::JsonResponse => &["json_response", "json_mode", "response_format_json"],
            Self::ImageInput => &["image_input", "vision", "multimodal"],
            Self::Reasoning => &["reasoning", "thinking"],
            Self::Voice => &["voice", "audio_output"],
        }
    }
}

fn capability_list_contains(value: &JsonValue, capability: &str) -> bool {
    match value {
        JsonValue::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|entry| normalize_key(entry) == capability)
        }),
        JsonValue::String(value) => normalize_key(value) == capability,
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            normalize_key(key) == "capabilities" && capability_list_contains(value, capability)
        }),
        _ => false,
    }
}

fn truthy(value: &JsonValue) -> bool {
    match value {
        JsonValue::Bool(value) => *value,
        JsonValue::Number(value) => value.as_u64().is_some_and(|value| value > 0),
        JsonValue::String(value) => matches!(
            normalize_key(value).as_str(),
            "true" | "yes" | "1" | "supported" | "native" | "enabled"
        ),
        _ => false,
    }
}

fn template_has_tool_calling(template: &str) -> bool {
    let template = template.to_ascii_lowercase();
    template.contains("tool_call")
        || template.contains("<tool_call")
        || template.contains("available_tools")
        || template.contains("{% if tools")
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}
