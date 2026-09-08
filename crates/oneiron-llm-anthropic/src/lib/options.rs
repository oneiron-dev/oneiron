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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicThinkingOptions {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u64>,
}
