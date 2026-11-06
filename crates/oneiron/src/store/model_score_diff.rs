//! Core half of `store::model_score_diff`: its store-layer items live in `oneiron_store::model_score_diff` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::model_score_diff::*;

use crate::side_table::LegacyJson;
use oneiron_model::llm::ModelId;
use serde::{Deserialize, Serialize};

/// Whether a masked copy of a `LLM_SCORE_DIFFS` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_score_diffs_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<Vec<ModelScoreDiff>, LegacyJson>(bytes)
}
