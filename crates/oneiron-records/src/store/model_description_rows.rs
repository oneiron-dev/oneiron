//! Moved from `crates/oneiron/src/store/model_description_rows.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelLocality;
use oneiron_model::llm::ReasoningEffort;
pub use oneiron_store::model_description_rows::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

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
