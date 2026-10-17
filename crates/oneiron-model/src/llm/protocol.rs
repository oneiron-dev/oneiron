//! Wire protocol: requests, responses, messages, content parts, stream events, usage, tool specs, and canonical JSON.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use super::{CallEnvelope, ModelId};
use oneiron_contracts::entity_id::bytes_to_hex_lower;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmRequest {
    pub model: ModelId,
    pub envelope: CallEnvelope,
    pub messages: Vec<LlmMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<LlmToolSpec>,
    /// Generic sampling and output params. Never `model`, `models`, `route` or
    /// `provider`: the model id above and the host's binding pick the model and
    /// its route, so the adapters, the catalog admission, the run admission and
    /// the raw inference routes refuse a request that names one
    /// ([`Self::route_selector_override`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, JsonValue>,
    /// Provider options by namespace (`openai`, `anthropic`, ...). Neither a
    /// namespace nor a key inside one may be `model`, `models`, `route` or
    /// `provider`, as for [`Self::params`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_options: BTreeMap<String, JsonValue>,
}

impl LlmRequest {
    /// Canonical JSON bytes used as the durable BLAKE3 request-key input.
    ///
    /// Struct and JSON-object fields are recursively sorted by key, while
    /// arrays retain order because message, content, and tool order are
    /// semantic.
    pub fn canonical_bytes(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        canonical_json_bytes(self)
    }

    pub fn canonical_hash(&self) -> std::result::Result<[u8; 32], serde_json::Error> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn canonical_hash_hex(&self) -> std::result::Result<String, serde_json::Error> {
        let bytes = self.canonical_hash()?;
        Ok(bytes_to_hex_lower(&bytes))
    }

    /// The first generic param, provider-option namespace or provider-option
    /// key that would pick the model or the route on a provider's wire, as
    /// `key` or `namespace.key`. The request's model id and the host's binding
    /// pick both; an adapter refuses a request that names another. A
    /// namespace no adapter reads is caller text, so it is named `*` instead:
    /// refusals, receipts and replies quote the result.
    #[must_use]
    pub fn route_selector_override(&self) -> Option<String> {
        if let Some(key) = self.params.keys().find(|key| is_route_selector(key)) {
            return Some(key.clone());
        }
        for (namespace, options) in &self.provider_options {
            if is_route_selector(namespace) {
                return Some(namespace.clone());
            }
            if let Some(key) = options
                .as_object()
                .and_then(|options| options.keys().find(|key| is_route_selector(key)))
            {
                let namespace = if KNOWN_NAMESPACES.contains(&namespace.as_str()) {
                    namespace.as_str()
                } else {
                    OTHER_NAMESPACE
                };
                return Some(format!("{namespace}.{key}"));
            }
        }
        None
    }
}

/// Body fields that choose which model, or which upstream, serves a call:
/// the model itself, a fallback model list, and a router's route or provider
/// preference.
const ROUTE_SELECTOR_KEYS: [&str; 4] = ["model", "models", "route", "provider"];

/// The provider-option namespaces the adapters read.
const KNOWN_NAMESPACES: [&str; 3] = ["openai", "anthropic", "gemini"];

/// How [`LlmRequest::route_selector_override`] names any other namespace.
const OTHER_NAMESPACE: &str = "*";

fn is_route_selector(key: &str) -> bool {
    ROUTE_SELECTOR_KEYS.contains(&key)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmResponse {
    pub message: LlmMessage,
    pub usage: LlmUsage,
    pub finish_reason: FinishReason,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: LlmMessageRole,
    pub content: Vec<ContentPart>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmMessageRole {
    System,
    User,
    Assistant,
    Tool,
}

/// Bidirectional content representation shared by history-in and generation-out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
    },
    Reasoning {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    ToolCall {
        call_id: String,
        name: String,
        input: JsonValue,
    },
    ToolResult {
        call_id: String,
        output: JsonValue,
        #[serde(default)]
        is_error: bool,
    },
    Image {
        media_type: String,
        image: ImageContent,
    },
    /// An input audio clip: standard padded base64 of its encoded bytes, with
    /// no `data:` prefix. Only a row that admits
    /// [`LlmCapability::AudioInput`](crate::llm::LlmCapability::AudioInput)
    /// takes it; a wire with no audio encoder refuses it.
    Audio {
        media_type: String,
        data: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ImageContent {
    Base64 { data: String },
    Url { url: String },
}

/// Typed stream events. Deltas are transient; only [`Self::Done`] is durable.
///
/// Adapters must not emit [`Self::Done`] for a successful empty response; they
/// should report [`FatalLlmError::EmptyResponse`](crate::llm::FatalLlmError::EmptyResponse) instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LlmStreamEvent {
    TextStart {
        part_id: String,
    },
    TextDelta {
        part_id: String,
        text: String,
    },
    TextEnd {
        part_id: String,
    },
    ReasoningStart {
        part_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    ReasoningDelta {
        part_id: String,
        text: String,
    },
    ReasoningEnd {
        part_id: String,
    },
    ToolCallStart {
        part_id: String,
        call_id: String,
        name: String,
    },
    ToolCallDelta {
        part_id: String,
        input_fragment: String,
    },
    ToolCallEnd {
        part_id: String,
        call_id: String,
        name: String,
        input: JsonValue,
    },
    ToolResultStart {
        part_id: String,
        call_id: String,
    },
    ToolResultDelta {
        part_id: String,
        output_fragment: String,
    },
    ToolResultEnd {
        part_id: String,
        call_id: String,
        output: JsonValue,
        #[serde(default)]
        is_error: bool,
    },
    ImageStart {
        part_id: String,
        media_type: String,
    },
    ImageDelta {
        part_id: String,
        data_fragment: String,
    },
    ImageEnd {
        part_id: String,
        media_type: String,
        image: ImageContent,
    },
    Done {
        message: LlmMessage,
        usage: LlmUsage,
        finish_reason: FinishReason,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmUsage {
    pub input: LlmInputUsage,
    pub output: LlmOutputUsage,
    pub raw_provider: JsonValue,
}

impl LlmUsage {
    /// Key in a ladder's served receipt naming the provider of the rung that
    /// answered. The host's own stamp, written beside the provider's usage.
    pub const SERVED_PROVIDER_KEY: &'static str = "provider";

    #[must_use]
    pub fn zero() -> Self {
        Self {
            input: LlmInputUsage::default(),
            output: LlmOutputUsage::default(),
            raw_provider: JsonValue::Null,
        }
    }

    /// The provider a host's model ladder says answered this call: the
    /// served receipt's [`Self::SERVED_PROVIDER_KEY`]. A served receipt names
    /// its rung and holds the provider's own usage under `usage`, so a
    /// provider's usage object is never read as one. `None` when no ladder
    /// stamped the answer.
    #[must_use]
    pub fn served_provider(&self) -> Option<&str> {
        let receipt = self.raw_provider.as_object()?;
        if !receipt.get("rung").is_some_and(JsonValue::is_u64) || !receipt.contains_key("usage") {
            return None;
        }
        receipt
            .get(Self::SERVED_PROVIDER_KEY)?
            .as_str()
            .map(str::trim)
            .filter(|provider| !provider.is_empty())
    }
}

/// Absolute per-attempt input token totals, never retry deltas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LlmInputUsage {
    pub total: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// Absolute per-attempt output token totals, never retry deltas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LlmOutputUsage {
    pub total: u64,
    pub text: u64,
    pub reasoning: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFiltered,
    Cancelled,
    Other { name: String },
}

/// Serializes `value` as JSON with every object's keys sorted, so equal values hash equal.
pub fn canonical_json_bytes<T: Serialize>(
    value: &T,
) -> std::result::Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&canonicalize_json(value))
}

fn canonicalize_json(value: JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(values) => {
            JsonValue::Array(values.into_iter().map(canonicalize_json).collect())
        }
        JsonValue::Object(entries) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize_json(value));
            }

            let mut canonical = JsonMap::new();
            for (key, value) in sorted {
                canonical.insert(key, value);
            }
            JsonValue::Object(canonical)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests;
