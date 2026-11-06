//! Core half of `store::model_stream_row`: its store-layer items live in `oneiron_store::model_stream_row` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::model_stream_row::*;

use crate::entity_id::EntityId;
use crate::side_table::Named;
use oneiron_model::llm::{LlmRequest, LlmResponse};
use serde::{Deserialize, Serialize};

/// Whether a masked copy of a `MODEL_STREAM` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn model_stream_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<StreamRow, Named>(bytes)
}
