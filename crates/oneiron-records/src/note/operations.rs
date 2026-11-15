//! Moved from `crates/oneiron/src/note/operations.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::document::NotePin;
use crate::note::document::NoteScalarEdit;
use crate::note::document::invalid;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Idempotent command carried by the canonical document frame. There is no
/// actor field: the receiving host obtains that from its authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteOperation {
    #[serde(with = "super::id_codec")]
    pub request_id: EntityId,
    pub change: NoteChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoteChange {
    Edit {
        base: Vec<u8>,
        edits: Vec<NoteScalarEdit>,
    },
    Cite {
        pin: NotePin,
    },
    SetTitle {
        title: String,
    },
}

/// No length refuses an operation (rule 5, FIX 10345). A peer's bytes are
/// bounded by the frame that carried them, and a JSON decode allocates no
/// more than they hold.
impl NoteOperation {
    pub fn encode(&self) -> oneiron_base::error::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("NOTE operation encode"))
    }

    pub fn decode(bytes: &[u8]) -> oneiron_base::error::Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid NOTE operation"))
    }

    pub fn hash(&self) -> oneiron_base::error::Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}
