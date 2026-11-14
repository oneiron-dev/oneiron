//! Moved from `crates/oneiron/src/llm/registry.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::registry::backend::ModelBackendPin;
pub use crate::llm::registry::backend::ModelCostReceipt;
pub use crate::llm::registry::backend::PricedModelBackend;
pub use crate::llm::registry::backend::catalog_usage_cost;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ModelId;
pub use oneiron_store::model_description_rows::ModelWireFormat;
pub use oneiron_store::model_score_diff::ModelScoreDiff;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScoreObservation {
    pub model: ModelId,
    pub benchmark: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScoreSnapshot {
    pub source: String,
    pub fetched_at: u64,
    pub observations: Vec<ScoreObservation>,
    /// The rows the observations were read from (FIX 5760): none for a
    /// public benchmark fetch. `None`, unknown, for a snapshot whose
    /// producer named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
}

pub fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}

pub fn price(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && value.bytes().filter(|c| *c == b'.').count() <= 1
        && value.bytes().any(|c| c.is_ascii_digit())
}
pub mod backend;
