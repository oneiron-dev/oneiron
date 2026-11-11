//! Reference preflight for the existing `self.workflows.dispatch_bound` run row.

use crate::claim::{ClaimReadStatus, PointRead, ScopedReadActorKey};
use crate::{EntityId, Result, Vault};

/// Whether `reader`'s lane reads every one of `refs`, bodies included, in
/// one snapshot. Every ref is read, however many.
pub(crate) fn refs_readable(
    vault: &Vault,
    reader: &ScopedReadActorKey,
    refs: &[EntityId],
) -> Result<bool> {
    let points: Vec<_> = refs.iter().copied().map(PointRead::id).collect();
    let checked = vault
        .scoped_read(reader.clone())
        .with_claim_status(ClaimReadStatus::Recorded)
        .read(&points, None)?;
    Ok(checked
        .value
        .iter()
        .all(|row| row.as_ref().is_some_and(|row| row.body.is_some())))
}
