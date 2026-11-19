//! The same-TASK continuation of a failed agent run (FIX 3694, OF-568,
//! ruling 3).
//!
//! An owner who approves a prompt continuation of a failed attempt that
//! realized a TASK continues that TASK: in the transaction that enqueues the
//! successor attempt, the TASK goes back to its runner lane as `Queued`, so
//! the successor's Host Accept and Report find a live runner task again.
//! Only the TASK the failure settled moves: a standard task whose terminal
//! record is `Failed` with no ladder settlement, still assigned to the
//! failed attempt's agent on the runner lane, and not cancelled since. Any
//! other state is the TASK having moved on, and the continuation refuses.
//!
//! The failure stays in the TASK's lifecycle receipts, which this never
//! rewrites; the move keeps a receipt of its own beside them, naming the
//! failed attempt, when it failed and the approval that continued it.

use std::collections::{BTreeMap, HashSet};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::memory::MemoryError;

use super::highway_accept::{Lane, lane_of};
use super::highway_report::requeue;
use super::highway_types::TaskVia;
use super::lifecycle_receipt;
use super::terminal_state::TaskTerminalDisposition;
use super::verb_kind::{TaskAssignee, TaskKind};
use super::wire_decode::task_verb_body_in;

/// The lifecycle call a continued TASK's receipt records.
const CONTINUE_CALL: &str = "continue";

/// One approved continuation, as its TASK's move needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FailedTaskContinuation {
    /// The TASK the failed attempt realized.
    pub(crate) task: EntityId,
    /// The failed attempt's agent: the AGENT_DEF its dispatch targets.
    pub(crate) agent: EntityId,
    /// The failed attempt.
    pub(crate) predecessor: AttemptId,
    /// The owner's approval of the continuation.
    pub(crate) approval: EntityId,
    /// The approving owner, who makes the move.
    pub(crate) by: EntityId,
    pub(crate) now: u64,
}

/// What a continuation found its TASK as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskContinuationOutcome {
    /// The TASK is queued on its runner lane again.
    Reactivated,
    /// The TASK is not the one the failure settled: missing, still live,
    /// settled another way, cancelled, or no longer the agent's. Nothing was
    /// written.
    Moved,
}

/// Puts the TASK `continuation` names back on its runner lane, in the
/// caller's write transaction, when the failure of its predecessor is still
/// how the TASK stands; answers [`TaskContinuationOutcome::Moved`], with
/// nothing written, when it is not.
///
/// # Errors
///
/// The shared TASK-body writer's and the lifecycle receipt's refusals, and
/// storage errors. The caller aborts its transaction then.
pub(crate) fn continue_failed_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    continuation: &FailedTaskContinuation,
) -> Result<TaskContinuationOutcome> {
    let task = continuation.task;
    let Some(mut body) = task_verb_body_in(vault, txn, task)? else {
        return Ok(TaskContinuationOutcome::Moved);
    };
    // A live TASK was never settled by the failure, or moved on since.
    let Some(failed) = body.terminal().cloned() else {
        return Ok(TaskContinuationOutcome::Moved);
    };
    let assigned = matches!(
        body.assignee,
        Some(TaskAssignee::AgentDef { agent_def_ref }) if agent_def_ref == continuation.agent
    );
    if body.task_kind() != TaskKind::Standard
        || failed.disposition != TaskTerminalDisposition::Failed
        || failed.ladder.is_some()
        || failed.counter_task_ref.is_some()
        || lane_of(body.assignee) != Lane::Runner
        || !assigned
    {
        return Ok(TaskContinuationOutcome::Moved);
    }
    let Some(standing) = vault.task_standing_in(txn, task)? else {
        return Ok(TaskContinuationOutcome::Moved);
    };
    if standing.cancelled
        || standing
            .assignee
            .is_some_and(|assignee| assignee != continuation.agent)
    {
        return Ok(TaskContinuationOutcome::Moved);
    }

    requeue(&mut body);
    let memory = vault.memory(continuation.by, EdgeActorClass::Human);
    memory
        .rewrite_task_in_txn(txn, task, body, continuation.now)
        .map_err(refused)?;
    if memory.keeps_lifecycle() {
        let mut lifecycle = memory.lifecycle_record(
            &TaskVia::Wire,
            CONTINUE_CALL,
            "queued",
            Some(task),
            Some(continuation.predecessor),
            continuation.now,
        );
        lifecycle
            .fields
            .insert("from".to_owned(), failed.disposition.as_str().to_owned());
        lifecycle
            .fields
            .insert("failed_at".to_owned(), failed.finished_at.to_string());
        lifecycle
            .fields
            .insert("approval".to_owned(), continuation.approval.to_hex());
        let id = lifecycle_receipt::receipt_id(
            CONTINUE_CALL,
            &[
                task.as_bytes().as_slice(),
                continuation.predecessor.as_bytes().as_slice(),
                continuation.approval.as_bytes().as_slice(),
            ],
        )
        .map_err(refused)?;
        lifecycle_receipt::stamp_record_in(vault, txn, &lifecycle, id, None).map_err(refused)?;
    }
    Ok(TaskContinuationOutcome::Reactivated)
}

/// When `task` settled as it stands now, or `None` while it is live or
/// unknown. A continuation puts a failed TASK back on its lane, so the
/// owner's acknowledgement of that failure answers it alone, never the
/// successor's later settlement.
///
/// A typed terminal is the settlement when one stands; a persisted `Expired`
/// settles at the deadline the sweep expired, not at the sweep's own write,
/// so an acknowledgement between the two still answers the expiry it read.
/// Otherwise the failures the board actually folds decide: the newest
/// projected failed head realizing this TASK (queue-only when the TASK body
/// carries no terminal, a malformed body included), or the passed deadline
/// when the row derives expired with no failed head. Live work and
/// non-failed heads settle nothing. A connector-send outcome carries no
/// settlement instant, so a Failed outcome without a failed head settles
/// nothing yet.
///
/// # Errors
///
/// Storage errors; a TASK body that fails to read for a reason other
/// than a malformed body (a malformed body falls back to its jobs, as
/// the dismissal projection does).
pub(crate) fn task_settled_at_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<Option<u64>> {
    let body = match task_verb_body_in(vault, rtxn, task) {
        Ok(body) => body,
        Err(Error::Record(RecordError::InvalidTaskBody(_))) => None,
        Err(error) => return Err(error),
    };
    if let Some(terminal) = body.as_ref().and_then(|body| body.terminal()) {
        if terminal.disposition == TaskTerminalDisposition::Expired
            && let Some(deadline) = body
                .as_ref()
                .and_then(|body| body.ttl.as_ref().map(|ttl| ttl.deadline_at))
        {
            return Ok(Some(terminal.finished_at.min(deadline)));
        }
        return Ok(Some(terminal.finished_at));
    }
    // No typed terminal: the newest failure the board folds for this TASK —
    // the same projected failed heads, so a job kind the board excludes
    // never moves the settlement — or the passed deadline when the row
    // derives expired. A retry successor supersedes its source, and the
    // newest failure wins, so an older ack never dismisses a later
    // continuation's failure.
    let task_hex = task.to_hex();
    let records =
        crate::attempt_queue::AttemptQueue::new(vault).task_subtree_in_txn(rtxn, &task_hex)?;
    let failed = projected_failed_head_settled_at(records, &task_hex)?;
    let expired = body.as_ref().and_then(|body| {
        let deadline = body.ttl.as_ref().map(|ttl| ttl.deadline_at)?;
        if body.settled_ladder_disposition().is_some() {
            return None;
        }
        (deadline <= vault.store.clock.now_recorded_at()).then_some(deadline)
    });
    Ok(failed.into_iter().chain(expired).max())
}

/// The newest failure instant over the failed heads the board folds for one
/// TASK, each stamped with its backing row's terminal instant; `None` when no
/// head failed. The heads come from the scan's own walk
/// ([`super::presence_jobs::for_each_head_job`]: retry-chain heads only, each
/// judged by the board's accept rule), so a job kind the board excludes never
/// moves the settlement the fence reads, and the newest failure wins.
fn projected_failed_head_settled_at(
    records: Vec<AttemptRecord>,
    task_hex: &str,
) -> Result<Option<u64>> {
    let members: HashSet<String> = records
        .iter()
        .filter(|record| record.task_ref.as_deref() == Some(task_hex))
        .map(|record| super::presence_scan::attempt_hex(record.id))
        .collect();
    let settled_by_attempt: BTreeMap<String, u64> = records
        .iter()
        .map(|record| {
            (
                super::presence_scan::attempt_hex(record.id),
                record.settled_at.unwrap_or(record.updated_at),
            )
        })
        .collect();
    let mut max_settled = None;
    super::presence_jobs::for_each_head_job(records, |node, job, _| {
        if members.contains(&node.attempt_id)
            && job.status == crate::context_board::TaskBoardStatus::Failed
        {
            max_settled = max_settled.max(settled_by_attempt.get(&node.attempt_id).copied());
        }
    })?;
    Ok(max_settled)
}

/// A TASK writer's refusal, as the engine's error.
fn refused(error: MemoryError) -> Error {
    Error::InvalidConfig(format!("task continuation refused: {}", error.message))
}
