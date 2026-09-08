//! Namespaced provider options and reasoning controls with wire-field projection.

use oneiron::{FatalLlmError, LlmRequest, LlmResult};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OpenAiProviderOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<OpenAiReasoningOptions>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, JsonValue>,
}

impl OpenAiProviderOptions {
    pub const NAMESPACE: &'static str = "openai";

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
                "parallel_tool_calls" => {
                    options.parallel_tool_calls =
                        Some(value.as_bool().ok_or(FatalLlmError::InvalidRequest)?);
                }
                "reasoning" => {
                    options.reasoning = Some(
                        serde_json::from_value(value.clone())
                            .map_err(|_| FatalLlmError::InvalidRequest)?,
                    );
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
        if let Some(parallel_tool_calls) = self.parallel_tool_calls {
            fields.insert(
                "parallel_tool_calls".to_owned(),
                JsonValue::Bool(parallel_tool_calls),
            );
        }
        if let Some(reasoning) = &self.reasoning {
            fields.insert(
                "reasoning".to_owned(),
                serde_json::to_value(reasoning)
                    .expect("OpenAI reasoning options serialize without failure"),
            );
        }
        fields
    }

    #[must_use]
    pub fn requires_reasoning(&self) -> bool {
        self.reasoning.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiReasoningOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}
