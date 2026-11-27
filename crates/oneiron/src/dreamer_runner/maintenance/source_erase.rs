//! The one entity eraser maintenance registers with both delete doors
//! (`deletion::derived_rows`): each copy of an erased record's bytes a
//! maintenance facet keeps goes in the erase's own transaction, before the
//! record's body and edges do. Identity's open asks, saved hints and
//! inverses, the Coach drafts on live agent-health cards (FIX 9221), the
//! stored proactivity digests, and the Coach's topology-audit candidates (FIX 7817).
use crate::secret_custody::CustodyWrite;
use crate::{EntityId, Result};

/// Drops every copy maintenance keeps of the erased `id`'s bytes; a no-op
/// for an id none names.
pub(crate) fn erase_source_copies_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = write.store;
    super::identity::erase_sources_in_txn(store, txn, id)?;
    super::agent_health::erase_sources_in_txn(store, txn, id)?;
    // PROACTIVITY-DIGEST-COPY-ERASURE: the stored proactivity digests' copies of a proposal's words.
    super::digest::erase_sources_in_txn(write, txn, id)?;
    // FIX 7817: the Coach's topology-audit candidates naming it.
    crate::identity_topology::erase_topology_audit_sources_in_txn(store, txn, id)
}
