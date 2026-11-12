//! Moved from `crates/oneiron/src/note/lifecycle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::documents::invalid;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_NOTE;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::side_table::key::HexId;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

/// `vault.notes.seal` and `vault.notes.lifecycle`: the NOTE named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteRefRequest {
    pub note_ref: String,
}
