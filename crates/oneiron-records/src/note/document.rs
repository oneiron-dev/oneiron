//! Moved from `crates/oneiron/src/note/document.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::CommitOptions;
use loro::Container;
use loro::ExportMode;
use loro::Frontiers;
use loro::LoroDoc;
use loro::LoroMap;
use loro::LoroValue;
use loro::ValueOrContainer;
use loro::cursor::Cursor;
use loro::cursor::Side;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub const BODY: &str = "body";

/// Positions use Unicode scalar indices in the named base frontier. Batches
/// are ordered, so each operation sees the preceding operations in its batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteScalarEdit {
    pub start: usize,
    pub delete: usize,
    pub insert: String,
}

/// A citation is data, not a rendered view. Its cursors are bound to one
/// document and frontier. The original quote is retained even after drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotePin {
    #[serde(with = "super::id_codec")]
    pub claim: EntityId,
    #[serde(with = "super::id_codec")]
    pub document: EntityId,
    pub frontier: Vec<u8>,
    pub start_cursor: Vec<u8>,
    pub end_cursor: Vec<u8>,
    pub quote_hash: [u8; 32],
    pub quote_text: String,
}

pub fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(reason))
}

/// Decodes a NOTE frontier. No length refuses it (rule 5, FIX 10345): a NOTE
/// many devices edited at once has a wide one, and its decode allocates no
/// more than its bytes hold.
pub fn frontier(bytes: &[u8]) -> Result<Frontiers> {
    Frontiers::decode(bytes).map_err(|_| invalid("invalid NOTE frontier"))
}

impl NotePin {
    /// Checks the citation's shape: its frontier, its two cursors and its
    /// quote's hash. No quote length refuses it (rule 5, FIX 10345); a cursor
    /// past its shape check is a body cursor, small by construction.
    pub fn validate(&self) -> Result<()> {
        frontier(&self.frontier)?;
        quoted_cursor(&self.start_cursor, Side::Left)?;
        quoted_cursor(&self.end_cursor, Side::Right)?;
        if self.quote_hash != *blake3::hash(self.quote_text.as_bytes()).as_bytes() {
            return Err(invalid("NOTE quote hash mismatch"));
        }
        Ok(())
    }
}

/// A cited span's endpoint, decoded and checked for its shape: in the body
/// text, on a quoted character, on `side`. A pin's validation and a live
/// span's read judge it alike (FIX 10747).
pub fn quoted_cursor(bytes: &[u8], side: Side) -> Result<Cursor> {
    let cursor = Cursor::decode(bytes).map_err(|_| invalid("invalid NOTE cursor"))?;
    if cursor.container != loro::ContainerID::new_root(BODY, loro::ContainerType::Text) {
        return Err(invalid("NOTE cursor is not in the body"));
    }
    // Both endpoints name quoted characters, never a moving document
    // boundary. The sides describe the edges of those characters.
    if cursor.id.is_none() || cursor.side != side {
        return Err(invalid("NOTE cursor is not a quoted character boundary"));
    }
    Ok(cursor)
}
