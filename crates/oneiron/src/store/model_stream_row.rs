//! The durable row of one shared model stream (`MODEL_STREAM`): its owner,
//! stable key, frozen request and terminal. Shared model streams
//! (`llm::model_stream`) write and read it; the row's side-table
//! declaration names its lift acceptance.
use oneiron_model::llm::{LlmRequest, LlmResponse};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::side_table::Named;

/// Whether a masked copy of a `MODEL_STREAM` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn model_stream_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<StreamRow, Named>(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StreamRow {
    pub(crate) actor: EntityId,
    pub(crate) stream_key: String,
    pub(crate) request: LlmRequest,
    pub(crate) response: Option<LlmResponse>,
    pub(crate) failure: Option<String>,
}
