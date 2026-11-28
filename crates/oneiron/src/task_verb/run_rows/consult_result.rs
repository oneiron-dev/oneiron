//! Reference and run admission for the existing `tasks.consult.result` run
//! row.

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

/// Whether a run that leased `leased` (`None`: no TASK) and runs as `actor`
/// lands `task`'s consult: the TASK it leased, or a consult addressed to
/// `actor` as a running child. A child's consult is its inbox input, which no
/// attempt leases (`tasks.create` routes it `ChildAddressed`), so the child's
/// own live run lands it whatever TASK that run leased. Any other consult
/// lands only from the run that leased it, never from another run of the
/// agent it addresses.
pub(crate) fn lands_from_run(
    vault: &Vault,
    task: EntityId,
    leased: Option<EntityId>,
    actor: EntityId,
) -> Result<bool> {
    if leased == Some(task) {
        return Ok(true);
    }
    let assignee =
        crate::task_verb::wire_decode::task_verb_body(vault, task)?.and_then(|body| body.assignee);
    Ok(matches!(
        assignee,
        Some(crate::task_verb::TaskAssignee::Child { actor_ref }) if actor_ref == actor
    ))
}
