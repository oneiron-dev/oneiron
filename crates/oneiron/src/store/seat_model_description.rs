//! The seat-birth model description row routing keeps
//! (`LLM_MODEL_DESCRIPTION`), keyed by the fully revisioned model id. Seat
//! routing (`llm::seat`) writes, reads and renders it; the row's side-table
//! declaration names its lift acceptance.
use oneiron_model::llm::ModelId;
use serde::{Deserialize, Serialize};

use crate::side_table::LegacyJson;

/// A description is keyed by the fully revisioned model ID. Absence is not a
/// recommendation; the router cannot judge an undocumented model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDescription {
    pub model: ModelId,
    /// Capability profile, not a provider, tier or model-family name.
    pub facet: String,
    pub owner: Option<String>,
    pub measured: Option<String>,
    pub benchmarks: Option<String>,
    pub vendor: Option<String>,
}

/// Whether a masked copy of a `LLM_MODEL_DESCRIPTION` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn llm_model_description_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<ModelDescription, LegacyJson>(bytes)
}
