//! The vault-measured description rows model routing keeps
//! (`LLM_DESCRIPTION_MEASUREMENTS`). Routing (`llm::routing`) writes and
//! reads them; the row's side-table declaration names its lift acceptance.
use std::collections::BTreeMap;

use oneiron_model::llm::ModelId;
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
