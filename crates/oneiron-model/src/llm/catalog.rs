//! Capability catalog: flags, entries with supports/require, costs, and reasoning effort.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::media::{AiOperation, MediaCaps, MediaRequest, Modality};
use super::{FatalLlmError, ModelId, ModelLocality, UnsupportedCapability};

/// The metadata key a catalog row's [`MediaCaps`] sit under.
pub const MEDIA_METADATA_KEY: &str = "media";
/// The metadata key a catalog row's model family sits under.
const FAMILY_METADATA_KEY: &str = "family";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmCapability {
    Streaming,
    ToolCalling,
    ToolResults,
    ImageInput,
    JsonResponse,
    Reasoning,
    Voice,
    /// The model continues a trailing assistant message as its own answer
    /// (native prefill), so an interrupted reply resumes from its saved text.
    AssistantPrefill,
    /// The model hears input audio clips in a chat message
    /// ([`super::ContentPart::Audio`]).
    AudioInput,
}

impl LlmCapability {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::ToolCalling => "tool_calling",
            Self::ToolResults => "tool_results",
            Self::ImageInput => "image_input",
            Self::JsonResponse => "json_response",
            Self::Reasoning => "reasoning",
            Self::Voice => "voice",
            Self::AssistantPrefill => "assistant_prefill",
            Self::AudioInput => "audio_input",
        }
    }
}

impl fmt::Display for LlmCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCatalogEntry {
    pub model: ModelId,
    pub display_name: String,
    pub locality: ModelLocality,
    pub context_window_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<LlmCatalogCost>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<LlmCapability>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, JsonValue>,
}

impl LlmCatalogEntry {
    #[must_use]
    pub fn supports(&self, capability: &LlmCapability) -> bool {
        self.capabilities.iter().any(|entry| entry == capability)
    }

    /// Shared capability/locality admission for raw wire adapters. A request
    /// that picks its model or route through a param or provider option is
    /// refused: the request's model id and this row pick both.
    pub fn admit(&self, request: &super::LlmRequest, stream: bool) -> super::LlmResult<()> {
        if self.model != request.model
            || self.locality != request.envelope.locality
            || request.route_selector_override().is_some()
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if stream {
            self.require(LlmCapability::Streaming)?;
        }
        if !request.tools.is_empty() {
            self.require(LlmCapability::ToolCalling)?;
        }
        if matches!(
            request.envelope.response_format,
            super::ResponseFormat::Json { .. }
        ) {
            self.require(LlmCapability::JsonResponse)?;
        }
        for part in request.messages.iter().flat_map(|m| &m.content) {
            match part {
                super::ContentPart::ToolCall { .. } => self.require(LlmCapability::ToolCalling)?,
                super::ContentPart::ToolResult { .. } => {
                    self.require(LlmCapability::ToolResults)?;
                }
                super::ContentPart::Image { .. } => self.require(LlmCapability::ImageInput)?,
                super::ContentPart::Audio { .. } => self.require(LlmCapability::AudioInput)?,
                super::ContentPart::Reasoning { .. } => self.require(LlmCapability::Reasoning)?,
                _ => {}
            }
        }
        self.admit_raw_controls(request)?;
        Ok(())
    }

    /// Raw params and provider options reach a provider's wire beside the
    /// typed fields. A raw spelling of a typed control (a tool declaration or
    /// choice, a JSON output format or schema) needs the capability the typed
    /// field needs. A provider cache reference may carry tools the request
    /// cannot see, so it needs tool calling too.
    pub fn admit_raw_controls(&self, request: &super::LlmRequest) -> super::LlmResult<()> {
        let namespaces = request
            .provider_options
            .values()
            .filter_map(JsonValue::as_object)
            .flat_map(|fields| fields.iter());
        for (key, value) in request.params.iter().chain(namespaces) {
            if let Some(capability) = raw_control_capability(key, value) {
                self.require(capability)?;
            }
        }
        Ok(())
    }

    /// What this row serves past text, from its `media` metadata. A row
    /// with none serves text in and out, and images in when it takes them.
    #[must_use]
    pub fn media(&self) -> MediaCaps {
        if let Some(caps) = self
            .metadata
            .get(MEDIA_METADATA_KEY)
            .and_then(|value| serde_json::from_value(value.clone()).ok())
        {
            return caps;
        }
        let mut caps = MediaCaps::for_operation(AiOperation::Text);
        if self.supports(&LlmCapability::ImageInput) {
            caps.inputs.insert(Modality::Image);
        }
        if self.supports(&LlmCapability::AudioInput) {
            caps.inputs.insert(Modality::Audio);
        }
        caps
    }

    /// The family of models this row's model belongs to (the line one
    /// developer trains), as its config or its pack names it. `None` when
    /// nothing names one: a family is never read off a provider or an id.
    #[must_use]
    pub fn family(&self) -> Option<&str> {
        self.metadata
            .get(FAMILY_METADATA_KEY)
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|family| !family.is_empty())
    }

    /// This row, its model of `family`.
    #[must_use]
    pub fn with_family(mut self, family: &str) -> Self {
        self.metadata.insert(
            FAMILY_METADATA_KEY.to_owned(),
            JsonValue::String(family.to_owned()),
        );
        self
    }

    /// This row, serving `caps`.
    #[must_use]
    pub fn with_media(mut self, caps: &MediaCaps) -> Self {
        if let Ok(value) = serde_json::to_value(caps) {
            self.metadata.insert(MEDIA_METADATA_KEY.to_owned(), value);
        }
        self
    }

    /// Shared admission for one media call on this row: its model and
    /// locality, no route selector, an operation and inputs the row serves,
    /// and no more reference images than it takes.
    pub fn admit_media(&self, request: &MediaRequest) -> super::LlmResult<()> {
        if self.model != request.model
            || self.locality != request.envelope.locality
            || request
                .admission_request()
                .route_selector_override()
                .is_some()
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let caps = self.media();
        if !caps.serves(request.operation, &request.inputs())
            || request.references.len() > caps.max_references
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }

    pub fn require(&self, capability: LlmCapability) -> std::result::Result<(), FatalLlmError> {
        if self.supports(&capability) {
            Ok(())
        } else {
            Err(FatalLlmError::Unsupported(UnsupportedCapability {
                capability,
                model: Some(self.model.clone()),
                reason: None,
            }))
        }
    }
}

/// The capability a raw param or provider-option field needs, by the
/// spellings the OpenAI-compatible, Anthropic and Gemini wires read.
fn raw_control_capability(key: &str, value: &JsonValue) -> Option<LlmCapability> {
    match key {
        "tools"
        | "tool_choice"
        | "functions"
        | "function_call"
        | "parallel_tool_calls"
        | "mcp_servers"
        | "toolConfig"
        | "tool_config"
        | "cachedContent"
        | "cached_content" => Some(LlmCapability::ToolCalling),
        "structured_outputs"
        | "output_format"
        | "guided_json"
        | "json_schema"
        | "responseSchema"
        | "response_schema"
        | "responseJsonSchema"
        | "response_json_schema" => Some(LlmCapability::JsonResponse),
        "response_format" => (value.get("type").and_then(JsonValue::as_str) != Some("text"))
            .then_some(LlmCapability::JsonResponse),
        "output_config" => value
            .get("format")
            .is_some()
            .then_some(LlmCapability::JsonResponse),
        "responseMimeType" | "response_mime_type" => {
            (value.as_str() != Some("text/plain")).then_some(LlmCapability::JsonResponse)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCatalogCost {
    pub input_per_million: String,
    pub output_per_million: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_per_million: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_per_million: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    None,
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
}

/// The request param that carries a thinking budget, in tokens, beside a
/// seat's effort pin. An OpenAI-compatible own server (llama.cpp) reads it
/// per request; an adapter whose wire has no such field drops it.
pub const REASONING_BUDGET_PARAM: &str = "reasoning_budget_tokens";
