//! Moved from `crates/oneiron/src/deletion/receipt.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactionScope {
    pub entity_ids: Vec<String>,
    pub revision_ids: Vec<String>,
}

impl RedactionScope {
    pub fn entity(entity_id: &EntityId) -> Self {
        Self {
            entity_ids: vec![entity_id.to_hex()],
            revision_ids: Vec::new(),
        }
    }
}
