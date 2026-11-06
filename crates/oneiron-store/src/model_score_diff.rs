//! One benchmark-score change of a model (`LLM_SCORE_DIFFS` rows). The model
//! registry (`llm::registry`) records and reads the bounded history; the
//! row's side-table declaration names its lift acceptance.
use oneiron_model::llm::ModelId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelScoreDiff {
    pub model: ModelId,
    pub source: String,
    pub benchmark: String,
    pub previous: Option<f64>,
    pub score: f64,
    pub fetched_at: u64,
}
