//! Namespaced provider options and thinking controls with wire-field projection.

use std::collections::BTreeMap;

use oneiron::{FatalLlmError, LlmRequest, LlmResult};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnthropicProviderOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<AnthropicThinkingOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, JsonValue>,
}

impl AnthropicProviderOptions {
    pub const NAMESPACE: &'static str = "anthropic";

    pub fn from_request(request: &LlmRequest) -> LlmResult<Self> {
        request
            .provider_options
            .get(Self::NAMESPACE)
            .map_or_else(|| Ok(Self::default()), Self::from_namespaced_value)
    }

    pub fn from_namespaced_value(value: &JsonValue) -> LlmResult<Self> {
        let object = value.as_object().ok_or(FatalLlmError::InvalidRequest)?;
        let mut options = Self::default();

        for (key, value) in object {
            match key.as_str() {
                "thinking" => {
                    options.thinking = Some(
                        serde_json::from_value(value.clone())
                            .map_err(|_| FatalLlmError::InvalidRequest)?,
                    );
                }
                "metadata" => {
                    options.metadata = Some(value.clone());
                }
                _ => {
                    options.raw.insert(key.clone(), value.clone());
                }
            }
        }

        Ok(options)
    }

    #[must_use]
    pub fn to_wire_fields(&self) -> BTreeMap<String, JsonValue> {
        let mut fields = self.raw.clone();
        if let Some(thinking) = &self.thinking {
            fields.insert(
                "thinking".to_owned(),
                serde_json::to_value(thinking)
                    .expect("Anthropic thinking options serialize without failure"),
            );
        }
        if let Some(metadata) = &self.metadata {
            fields.insert("metadata".to_owned(), metadata.clone());
        }
        fields
    }

    #[must_use]
    pub fn requires_reasoning(&self) -> bool {
        self.thinking.is_some()
    }

    /// The prompt-cache tier a request's marked blocks are written at (FIX
    /// 6029), one parser for the wire and the host: the provider's default
    /// five minutes, unless a `cache_control` the request's own raw options
    /// carry asks for one hour. Every `cache_control` they carry counts, and
    /// tiers that differ take the shortest. `None` for one this parser does
    /// not know: the wire then marks as it always did, and the host reads no
    /// lifetime.
    #[must_use]
    pub fn cache_tier(&self) -> Option<AnthropicCacheTier> {
        let mut asked = Vec::new();
        for (key, value) in &self.raw {
            collect_cache_tiers(key, value, &mut asked);
        }
        let mut tier = None;
        for one in asked {
            let one = one?;
            tier = Some(tier.map_or(one, |held: AnthropicCacheTier| held.min(one)));
        }
        Some(tier.unwrap_or(AnthropicCacheTier::FiveMinutes))
    }
}

/// How long a prompt-cache entry this wire writes lives (FIX 6029). Ordered
/// shortest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnthropicCacheTier {
    /// The provider's default, written as a bare `{type: ephemeral}`.
    FiveMinutes,
    /// Written as `{type: ephemeral, ttl: "1h"}`, only where a request's own
    /// options ask for it.
    OneHour,
}

/// Each tier a `cache_control` asks for in `value`, held under `key`, at any
/// depth: `None` for one that names an unknown type or lifetime.
fn collect_cache_tiers(key: &str, value: &JsonValue, tiers: &mut Vec<Option<AnthropicCacheTier>>) {
    if key == "cache_control" {
        tiers.push(cache_control_tier(value));
        return;
    }
    match value {
        JsonValue::Object(object) => {
            for (key, inner) in object {
                collect_cache_tiers(key, inner, tiers);
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                collect_cache_tiers("", item, tiers);
            }
        }
        _ => {}
    }
}

fn cache_control_tier(control: &JsonValue) -> Option<AnthropicCacheTier> {
    if control.get("type").and_then(JsonValue::as_str) != Some("ephemeral") {
        return None;
    }
    match control.get("ttl") {
        None => Some(AnthropicCacheTier::FiveMinutes),
        Some(ttl) => match ttl.as_str()? {
            "5m" => Some(AnthropicCacheTier::FiveMinutes),
            "1h" => Some(AnthropicCacheTier::OneHour),
            _ => None,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicThinkingOptions {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u64>,
}
