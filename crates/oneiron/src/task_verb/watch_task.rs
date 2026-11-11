//! Watch TASKs (FIX 22121; ARCH-0080 §4 Watchers). A watch TASK is a TASK
//! with a due time whose work is what the hooks on its `schedule.tick` do:
//! its create queues no realizing attempt and dispatches nothing
//! (`create_facade`), and the write that releases its tick settles it Done
//! (`runtime_hooks::source::schedule`). An ordinary due TASK keeps its
//! realizing attempt at create and ticks only while it stays open.
//!
//! Entry [`reject_unfit_watch`] at create, [`settle_watch_task_in_txn`] at
//! the tick's release, [`tick_due_at_in_txn`] where a hook is offered it.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::memory::{MemoryError, MemoryResult};

use super::create_spec::TaskCreateSpec;
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::TaskAssignee;
use super::wire_decode::{task_body_optional, task_verb_body_in};
use super::wire_encode::encode_task_verb_body;

/// Refuses a watch create its tick cannot carry: one with no due time, which
/// would never tick, and one addressed to anyone but the Dreamer. An agent,
/// peer, child or person starts work at create, and a watch TASK's work is
/// what the hooks on its tick enqueue. A create that is no watch passes.
pub(super) fn reject_unfit_watch(spec: &TaskCreateSpec) -> MemoryResult<()> {
    if !spec.watch {
        return Ok(());
    }
    if spec.due_at.is_none() {
        return Err(MemoryError::bad_request_with(
            "a watch TASK needs due_at, the time its tick runs its hooks",
            &["Set due_at, or drop watch."],
        ));
    }
    if !matches!(spec.assignee, None | Some(TaskAssignee::Dreamer)) {
        return Err(MemoryError::bad_request_with(
            "a watch TASK is assigned to no one or the Dreamer: its hooks do its work",
            &["Leave assignee unset or the Dreamer, or drop watch."],
        ));
    }
    Ok(())
}

/// A body's or a create proposal's `watch` key: absent or `Nil` is no
/// watch, and anything but a boolean is a corrupt row, named by `field`.
pub(super) fn decode_watch(entries: &[(Value, Value)], field: &'static str) -> Result<bool> {
    task_body_optional(entries, "watch")?.map_or(Ok(false), |value| {
        value
            .as_bool()
            .ok_or(Error::Record(RecordError::InvalidTaskBody(field)))
    })
}

/// A body's `due_at` key (FIX685): its own key, a due annotation, never the
/// `ttl` expiry map; anything but Unix seconds is a corrupt row, named by
/// `field`.
pub(super) fn decode_due_at(
    entries: &[(Value, Value)],
    field: &'static str,
) -> Result<Option<u64>> {
    task_body_optional(entries, "due_at")?
        .map(|value| {
            value
                .as_u64()
                .ok_or(Error::Record(RecordError::InvalidTaskBody(field)))
        })
        .transpose()
}

/// The due time `task_ref` was open at, for a hook offered its tick. An
/// open TASK's due time, to any hook: one bound after it ticked is still
/// offered that tick. A watch TASK's, once it settled at or after that
/// time as the release of its tick settles it, only to a hook
/// `bound_at_release`, enabled before that release: one bound after it
/// finds the watch's work done (review #6784). `None` when the row is
/// gone, settled otherwise, cancelled (review #6784) or carries no due
/// time; a body no reader can decode reads as none, as
/// [`super::open_task_due_at_in_txn`] reads it.
pub(crate) fn tick_due_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    bound_at_release: bool,
) -> Result<Option<u64>> {
    let body = match task_verb_body_in(vault, txn, task_ref) {
        Ok(body) => body,
        Err(Error::Record(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let due_at = body.and_then(|body| match body.terminal() {
        None => body.due_at,
        Some(_) if !bound_at_release => None,
        Some(terminal) => body
            .watch_due_at()
            .filter(|due_at| terminal.finished_at >= *due_at),
    });
    if due_at.is_some() && vault.task_authority_facts_in(txn, task_ref)?.cancelled {
        return Ok(None);
    }
    Ok(due_at)
}

/// Settles a watch TASK Done in the write that releases its tick, at `now`
/// (Unix seconds, at or after its due time). It names no result: its work
/// is what the hooks on that tick enqueue. The write is the engine's own,
/// as the tick is, through the internal TASK body door, and the storage
/// door drops the TASK's due rows as it lands. An ordinary TASK, or one
/// already settled, is left alone.
pub(crate) fn settle_watch_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    now: u64,
) -> Result<()> {
    let Some(mut body) = task_verb_body_in(vault, &*txn, task_ref)? else {
        return Ok(());
    };
    if !body.watch
        || body.terminal().is_some()
        || body.settled_ladder_disposition().is_some()
        || vault.task_authority_facts_in(&*txn, task_ref)?.cancelled
    {
        return Ok(());
    }
    body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: None,
        summary: None,
        finished_at: now,
        ladder: None,
        counter_task_ref: None,
    }));
    vault
        .batch_in()
        .put_internal(
            &task_ref,
            crate::registry::ENTITY_TYPE_TASK,
            crate::TimeRange {
                start: now,
                end: now,
            },
            now,
            &encode_task_verb_body(body),
        )
        .apply(txn)?;
    // As every settlement does: a review the owner accepted before the TASK
    // settled anchors it, and the routing folds count it.
    super::settlement_anchor::anchor_kept_review_in_txn(vault, txn, task_ref, None)?;
    crate::edit_distance::routing::refold_task_outcomes_in_txn(vault, txn, task_ref);
    Ok(())
}
