//! How many rows a read's text and vector indexes can return: the
//! populations a scoped channel widens to, for a room's union read as for
//! base's own.

use heed::RoTxn;

use crate::error::{Error, Result};
use crate::store::StoreRead;

/// The text documents `store` can match, bounded from above.
pub(crate) fn indexed_text_population(store: &StoreRead<'_>, rtxn: &RoTxn<'_>) -> Result<usize> {
    let mut indexed_docs = crate::bm25::read_total_docs(store, rtxn)?;
    if store.is_union() {
        // A room stages the count it read when it indexed, and base keeps
        // growing on record: base's own count bounds what base adds since.
        indexed_docs =
            indexed_docs.saturating_add(crate::bm25::read_total_docs(store.base(), rtxn)?);
    }
    usize::try_from(indexed_docs).map_err(|_| Error::IndexOverflow("bm25 total docs"))
}

/// The vectors `store` can score, bounded from above.
pub(crate) fn indexed_vector_population(store: &StoreRead<'_>, rtxn: &RoTxn<'_>) -> Result<usize> {
    // A room stages its graph's count with its graph, and base keeps growing
    // on record: the walk runs on base's graph and scores the room's vectors
    // beside it, so both bound it.
    let staged = store
        .vectors
        .staged_rows()
        .map_or(0, |staged| staged.rows.len());
    Ok(crate::hnsw::hnsw_entity_count(store.base(), rtxn)?.saturating_add(staged))
}
