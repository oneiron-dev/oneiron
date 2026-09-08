//! The ack/cancel render-state door: reads the TASK authority facts and appends them inside a caller transaction.

use super::projection::TaskIntentPresence;
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
use crate::{EntityId, Result, Vault};

/// Both render-tier state bits for one TASK.
///
/// `cancelled` is answered BEFORE `acked` by every consumer: a Cancelled fact
/// takes the row off the active surface even when an Acked fact merged in
/// beside it, in either order, on either replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskRenderState {
    pub(crate) acked: bool,
    pub(crate) cancelled: bool,
}

pub(crate) fn task_is_acked(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    Ok(task_render_state(vault, task_ref)?.acked)
}

/// Appends the immutable Acked fact for one TASK, inside the caller's
/// transaction — so the acknowledgement commits with the verified `tasks.ack`
/// effect that earned it, or not at all.
pub(crate) fn ack_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    actor: EntityId,
    now: u64,
) -> Result<()> {
    put_task_state_fact_in_txn(
        vault,
        wtxn,
        task_ref,
        TaskAuthorityFactKind::Acked,
        actor,
        now,
    )
}

pub(crate) fn task_is_cancelled(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    Ok(task_render_state(vault, task_ref)?.cancelled)
}

/// Appends the immutable Cancelled fact for one TASK. Monotonic by
/// construction: the fact is a row, never a flag, so nothing that merges in
/// later can clear it.
pub(crate) fn cancel_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    actor: EntityId,
    now: u64,
) -> Result<()> {
    put_task_state_fact_in_txn(
        vault,
        wtxn,
        task_ref,
        TaskAuthorityFactKind::Cancelled,
        actor,
        now,
    )
}

fn put_task_state_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
    now: u64,
) -> Result<()> {
    put_task_authority_fact_in_txn(
        vault,
        wtxn,
        TaskAuthorityFact {
            task_ref,
            kind,
            actor_ref: actor,
            occurred_at: now,
        },
    )
    .map(|_fact_ref| ())
}

/// One transaction for a direct caller that holds none of its own; the page
/// scan reaches the same read through [`TaskIntentPresence::render_state_in`].
///
/// Strictness travels with the fold: the `Err` a poisoned companion set
/// produces reaches [`task_is_cancelled`] / [`task_is_acked`] unchanged. Board
/// call sites degrade it per row (skip in the page scan, `Ok(None)` by id);
/// authority call sites keep failing closed on it.
pub(super) fn task_render_state(vault: &Vault, task_ref: EntityId) -> Result<TaskRenderState> {
    let rtxn = vault.store.env.read_txn()?;
    TaskIntentPresence::render_state_in(vault, &rtxn, task_ref)
}
