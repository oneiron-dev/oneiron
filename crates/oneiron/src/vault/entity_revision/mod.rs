//! Per-entity Loro history, exact reads, and idle-only index publication.
//! The original entity row remains the birth representation. The document is
//! born at its first edit or citation, and retains its full operation history.

mod citations;
mod idle;
mod pending_index;
mod phonetic;
pub(crate) use pending_index::defer_index_inputs;
pub(crate) use phonetic::defer_phonetic;
mod storage;
mod types;

pub(crate) use storage::{
    capture_entity_revision, ensure_document, entity_has_pending_revision,
    entity_owns_revision_in_txn, read_entity_revision_from_store_in_txn,
    read_entity_revision_in_txn, remove_entity_revisions, revision_for_mode_in_txn,
    storage_manages_text,
};
pub use types::{
    IndexedRefreshReport, IndexedRevisionEmbedder, IndexedRevisionInput, PinnedCitation, ReadMode,
    ResolvedCitation, RevisionRef,
};

#[cfg(test)]
mod tests;
