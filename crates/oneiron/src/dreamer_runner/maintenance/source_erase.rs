//! The one entity eraser maintenance registers with both delete doors
//! (`deletion::derived_rows`): each copy of an erased record's bytes a
//! maintenance facet keeps goes in the erase's own transaction, before the
//! record's body and edges do. Identity's open asks, saved hints and
//! inverses, and the Coach drafts on live agent-health cards (FIX 9221).
use crate::store::Store;
use crate::{EntityId, Result};

/// Drops every copy maintenance keeps of the erased `id`'s bytes; a no-op
/// for an id none names.
pub(crate) fn erase_source_copies_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    super::identity::erase_sources_in_txn(store, txn, id)?;
    super::agent_health::erase_sources_in_txn(store, txn, id)
}
