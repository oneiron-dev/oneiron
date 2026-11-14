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

#[doc(hidden)]
pub use oneiron_records::store::model_description_rows::{DescriptionPolicy, ModelDescription};

/// Whether a masked copy of a `LLM_DESCRIPTION_POLICY` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_description_policy_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<DescriptionPolicy, LegacyJson>(bytes)
}
