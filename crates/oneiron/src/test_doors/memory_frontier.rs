//! Doors for `tests/memory_frontier_timeline.rs` to the vault's memory
//! timeline (L3-39): the frontier its committed head stands at, the revision
//! a row held at a frontier, and the bytes of a revision. The graph-FS memory
//! fork reads the timeline through the same functions.

use crate::error::Result;
pub use crate::vault::entity_revision::MemoryFrontier;
use crate::vault::entity_revision::{
    ReadMode, RevisionRef, memory_frontier_in_txn, revision_at_frontier_in_txn,
};
use crate::{EntityId, Vault};

/// The frontier the vault's committed head stands at now, stamped with its
/// recording clock.
///
/// # Errors
///
/// Storage errors.
pub fn frontier_now(vault: &Vault) -> Result<MemoryFrontier> {
    let txn = vault.store.env.read_txn()?;
    memory_frontier_in_txn(&vault.store, &txn, vault.now_recorded_at())
}

/// The revision `id` held live at `frontier`, if it held one there.
///
/// # Errors
///
/// Storage errors.
pub fn revision_at(
    vault: &Vault,
    id: &EntityId,
    frontier: MemoryFrontier,
) -> Result<Option<RevisionRef>> {
    let txn = vault.store.env.read_txn()?;
    revision_at_frontier_in_txn(&vault.store, &txn, id, frontier)
}

/// The raw row of `id` at `revision`, as a pinned read serves it.
///
/// # Errors
///
/// The pinned read's own errors.
pub fn raw_at(vault: &Vault, id: &EntityId, revision: RevisionRef) -> Result<Option<Vec<u8>>> {
    vault.get_raw_with_mode(id, ReadMode::Pinned(revision))
}
