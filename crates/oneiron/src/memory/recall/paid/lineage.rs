//! The rows each rerank document is read from (FIX 7001), kept beside its
//! text so the host's call is sourced from exactly the rows whose words it
//! sends.

use crate::entity_id::EntityId;
use crate::memory::MemoryItem;

/// Each block candidate's read set, aligned with its text: `None` where a
/// set is not known whole.
pub(super) type DocumentSources = Vec<Option<Vec<EntityId>>>;

/// The rows `item`'s words are read from: the record, the records it
/// supersedes and, for a TURN, each message it reads them from or quotes
/// (`MemoryProvenance::source_revision_ids`). `None` when one entry names
/// no row: the set is then unknown, which sources nothing and refuses
/// nothing.
pub(super) fn item_source_rows(item: &MemoryItem) -> Option<Vec<EntityId>> {
    item.provenance
        .source_revision_ids
        .iter()
        .map(|id| EntityId::from_hex(id).ok())
        .collect()
}
