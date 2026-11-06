//! Core half of `store::model_description_rows`: its store-layer items live in `oneiron_store::model_description_rows` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::model_description_rows::*;

use crate::side_table::LegacyJson;
use oneiron_model::llm::{ModelId, ModelLocality, ReasoningEffort};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Whether a masked copy of a `LLM_DESCRIPTION_MEASUREMENTS` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_description_measurements_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<BTreeMap<ModelId, MeasuredDescription>, LegacyJson>(bytes)
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
