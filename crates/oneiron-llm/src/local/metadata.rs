//! Loaded-model metadata, catalog descriptor, and capability detection.
use std::collections::BTreeMap;

use oneiron::{LlmCapability, LlmCatalogEntry, ModelId, ModelLocality};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::capabilities::{
    CapabilityProbe, metadata_declares_capability, metadata_declares_tool_calling, push_capability,
};

/// Metadata for the currently loaded local model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalModelMetadata {
    pub model: ModelId,
    pub display_name: String,
    pub locality: ModelLocality,
    pub context_window_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, JsonValue>,
}

impl LocalModelMetadata {
    #[must_use]
    pub fn new(
        model: ModelId,
        display_name: impl Into<String>,
        context_window_tokens: u64,
    ) -> Self {
        Self {
            model,
            display_name: display_name.into(),
            locality: ModelLocality::OnDevice,
            context_window_tokens,
            max_output_tokens: None,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: BTreeMap<String, JsonValue>) -> Self {
        self.metadata = metadata;
        self
    }

    #[must_use]
    pub fn with_max_output_tokens(mut self, max_output_tokens: u64) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    #[must_use]
    pub fn with_locality(mut self, locality: ModelLocality) -> Self {
        self.locality = locality;
        self
    }

    /// Build the engine catalog descriptor from loaded model metadata.
    #[must_use]
    pub fn catalog_entry(&self) -> LlmCatalogEntry {
        LlmCatalogEntry {
            model: self.model.clone(),
            display_name: if self.display_name.is_empty() {
                self.model.name().to_owned()
            } else {
                self.display_name.clone()
            },
            locality: self.locality,
            context_window_tokens: self.context_window_tokens,
            max_output_tokens: self.max_output_tokens,
            cost: None,
            capabilities: self.detect_capabilities(),
            metadata: self.metadata.clone(),
        }
    }

    #[must_use]
    pub fn detect_capabilities(&self) -> Vec<LlmCapability> {
        let mut capabilities = Vec::new();
        push_capability(&mut capabilities, LlmCapability::Streaming);

        if metadata_declares_tool_calling(&self.metadata) {
            push_capability(&mut capabilities, LlmCapability::ToolCalling);
            push_capability(&mut capabilities, LlmCapability::ToolResults);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::JsonResponse) {
            push_capability(&mut capabilities, LlmCapability::JsonResponse);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::ImageInput) {
            push_capability(&mut capabilities, LlmCapability::ImageInput);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::Reasoning) {
            push_capability(&mut capabilities, LlmCapability::Reasoning);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::Voice) {
            push_capability(&mut capabilities, LlmCapability::Voice);
        }

        capabilities
    }
}
