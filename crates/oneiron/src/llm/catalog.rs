//! Capability catalog: flags, entries with supports/require, costs, and reasoning effort.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{FatalLlmError, ModelId, ModelLocality, UnsupportedCapability};

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
