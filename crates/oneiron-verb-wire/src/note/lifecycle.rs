//! Moved from `crates/oneiron/src/note/lifecycle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.notes.seal` and `vault.notes.lifecycle`: the NOTE named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteRefRequest {
    pub note_ref: String,
}
