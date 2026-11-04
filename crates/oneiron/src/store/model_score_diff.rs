//! One benchmark-score change of a model (`LLM_SCORE_DIFFS` rows). The model
//! registry (`llm::registry`) records and reads the bounded history; the
//! row's side-table declaration names its lift acceptance.
use oneiron_model::llm::ModelId;
use serde::{Deserialize, Serialize};

use crate::side_table::LegacyJson;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelScoreDiff {
    pub model: ModelId,
    pub source: String,
    pub benchmark: String,
    pub previous: Option<f64>,
    pub score: f64,
    pub fetched_at: u64,
}

/// Whether a masked copy of a `LLM_SCORE_DIFFS` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_score_diffs_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<Vec<ModelScoreDiff>, LegacyJson>(bytes)
}
