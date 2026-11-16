//! Moved from `crates/oneiron/src/note/archive_import.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// What the vault's current owner reads of an imported NOTE
/// ([`Vault::read_imported_note`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedNoteRead {
    /// The NOTE's kind, as its body stores it.
    pub kind: String,
    /// The author the source vault recorded, as a hex id: provenance, never
    /// a local actor.
    pub source_author: String,
    /// Its current markdown.
    pub markdown: String,
}
