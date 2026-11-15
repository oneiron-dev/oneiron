//! Red stub of the memory-frontier doors (L3-39 PR 1, red run only): main
//! keeps no memory timeline, so no frontier orders a row's revisions. The
//! stub answers what main can: the head at zero and no revision at it.

use crate::error::Result;
use crate::vault::entity_revision::{ReadMode, RevisionRef};
use crate::{EntityId, Vault};

/// The frontier's shape on the PR head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFrontier {
    /// The live-revision moves committed at the frontier.
    pub sequence: u64,
    /// The recording clock when the frontier was handed out.
    pub recorded_at: u64,
}

/// Main numbers no move: the head stands at zero.
///
/// # Errors
///
/// None on main.
pub fn frontier_now(_vault: &Vault) -> Result<MemoryFrontier> {
    Ok(MemoryFrontier {
        sequence: 0,
        recorded_at: 0,
    })
}

/// Main orders no revision, so none is named at a frontier.
///
/// # Errors
///
/// None on main.
pub fn revision_at(
    _vault: &Vault,
    _id: &EntityId,
    _frontier: MemoryFrontier,
) -> Result<Option<RevisionRef>> {
    Ok(None)
}

/// The raw row of `id` at `revision`, as a pinned read serves it.
///
/// # Errors
///
/// The pinned read's own errors.
pub fn raw_at(vault: &Vault, id: &EntityId, revision: RevisionRef) -> Result<Option<Vec<u8>>> {
    vault.get_raw_with_mode(id, ReadMode::Pinned(revision))
}
