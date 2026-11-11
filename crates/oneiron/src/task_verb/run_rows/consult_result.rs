//! Reference admission for the existing `tasks.consult.result` run row.

use crate::claim::{ClaimReadStatus, PointRead, ScopedReadActorKey};
use crate::{EntityId, Result, Vault};

/// Whether `reader`'s lane reads every one of `refs`, bodies included, in
/// one snapshot: the TASK, result, evidence and reason refs a landing names.
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
    Ok(!checked
        .value
        .iter()
        .any(|row| row.as_ref().is_none_or(|row| row.body.is_none())))
}
