//! The description rows model routing keeps: the owner's description
//! policy (`LLM_DESCRIPTION_POLICY`) with its model descriptions, owner
//! lines and wire formats, and the vault-measured descriptions
//! (`LLM_DESCRIPTION_MEASUREMENTS`). Routing (`llm::routing`) writes, reads
//! and validates them; each row's side-table declaration names its lift
//! acceptance.
use std::collections::BTreeMap;

use oneiron_model::llm::{ModelId, ModelLocality, ReasoningEffort};
use serde::{Deserialize, Serialize};

/// Vault-measured real-task evidence, never substituted for an owner's line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredDescription {
    pub model: ModelId,
    pub text: String,
    pub quality_millionths: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModelWireFormat {
    OpenaiCompat,
    AnthropicMessages,
    Gemini,
    OwnServer,
    Local,
}

/// The owner line stays attached to its exact model revision. A newer revision
/// may use lower-ranked evidence temporarily, but does not inherit this line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerModelLine {
    pub model: ModelId,
    pub text: String,
    /// Owner's quality estimate on the same millionths scale as measurements.
    pub expected_quality: u32,
}
