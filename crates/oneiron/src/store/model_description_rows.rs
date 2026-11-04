//! The description rows model routing keeps: the owner's description
//! policy (`LLM_DESCRIPTION_POLICY`) with its model descriptions, owner
//! lines and wire formats, and the vault-measured descriptions
//! (`LLM_DESCRIPTION_MEASUREMENTS`). Routing (`llm::routing`) writes, reads
//! and validates them; each row's side-table declaration names its lift
//! acceptance.
use std::collections::BTreeMap;

use oneiron_model::llm::{ModelId, ModelLocality, ReasoningEffort};
use serde::{Deserialize, Serialize};

use crate::side_table::LegacyJson;

/// Vault-measured real-task evidence, never substituted for an owner's line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredDescription {
    pub model: ModelId,
    pub text: String,
    pub quality_millionths: u32,
}

/// Whether a masked copy of a `LLM_DESCRIPTION_MEASUREMENTS` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_description_measurements_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<BTreeMap<ModelId, MeasuredDescription>, LegacyJson>(bytes)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDescription {
    pub model: ModelId,
    pub wire: ModelWireFormat,
    pub locality: ModelLocality,
    pub owner: Option<OwnerModelLine>,
    pub public_benchmark: Option<String>,
    pub vendor: Option<String>,
    /// Cheapest supported effort first. The owner can override this per seat.
    pub effort_ladder: Vec<ReasoningEffort>,
}

/// Hidden-by-default vault configuration; no UI or model names are shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionPolicy {
    pub models: Vec<ModelDescription>,
    /// Configured by the owner, not fixed by the routing implementation.
    pub contradiction_margin_millionths: u32,
    pub vault_effort: Option<ReasoningEffort>,
    pub purpose_effort: BTreeMap<String, ReasoningEffort>,
    pub global_effort: Option<ReasoningEffort>,
}

/// Whether a masked copy of a `LLM_DESCRIPTION_POLICY` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_description_policy_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<DescriptionPolicy, LegacyJson>(bytes)
}
