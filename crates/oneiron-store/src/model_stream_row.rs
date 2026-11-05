//! The durable row of one shared model stream (`MODEL_STREAM`): its owner,
//! stable key, frozen request and terminal. Shared model streams
//! (`llm::model_stream`) write and read it; the row's side-table
//! declaration names its lift acceptance.
use oneiron_model::llm::{LlmRequest, LlmResponse};
use serde::{Deserialize, Serialize};

use oneiron_contracts::entity_id::EntityId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRow {
    pub actor: EntityId,
    pub stream_key: String,
    pub request: LlmRequest,
    pub response: Option<LlmResponse>,
    pub failure: Option<String>,
}
