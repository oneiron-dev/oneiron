//! Engine runners on the task highway (OF-220).
//!
//! The Dreamer runner and agent dispatch keep leasing the queue directly:
//! the JobQueue is plumbing the agent never touches. Their TASK transitions
//! go through the highway's Host Accept and Report, run inside the runner's
//! own write transaction: the take co-commits with the lease, and a report
//! lands before the runner clears its lease, while the fence still holds.
//! A Host report never touches the queue row; the runner keeps its own
//! set_result, complete, fail and retry.
//!
//! Durable rows are written in the runner's transaction. The one in-memory
//! wake a report can owe, a settled TASK's peer-result signal, is
//! [`RunnerTaskEffects`]: run after commit where the caller has a point for
//! it, and otherwise replayed from the binding index by the next wake pass.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::write_envelope::WriteActor;

use super::consts::TASK_REALIZE_ATTEMPT_KIND;
use super::highway::{attempt_hex, invalid_state, local_node_in, qualified_key};
use super::highway_accept::{Lane, lane_of};
use super::highway_types::{
    AttemptHandle, HostBinding, TaskCallReceipt, TaskHandle, TaskOutcome, TaskPhase, TaskReport,
    TaskReportBody, TaskVia,
};
use super::runner_done::RunnerDoneAnswer;
use super::verb_kind::TaskKind;
use super::wire_decode::task_verb_body_in;

impl HostBinding {
    /// The binding a runner calls under, from the leased row it holds: the
    /// row's own id, lease owner and attempt count. A row with no live
    /// lease binds nothing. `run_ref` is the run entity a caller actually
    /// bound, or `None`: the queue's string `run_id` tag is never read as
    /// one.
    pub(crate) fn from_leased(
        record: &AttemptRecord,
        run_ref: Option<EntityId>,
    ) -> MemoryResult<Self> {
        match record.lease_owner.as_deref() {
            Some(lease_owner) if record.state.is_running() => Ok(Self::new(
                record.id,
                lease_owner.to_owned(),
                record.attempt_count,
                run_ref,
            )),
            _ => Err(invalid_state(
                "the runner's try holds no live lease",
                "Accept or report while the try is leased.",
            )),
        }
    }
}

/// The key of one runner transition: `{attempt id}:{attempt_count}:{transition}`.
pub(crate) fn runner_task_key(record: &AttemptRecord, transition: &str) -> String {
    format!(
        "{}:{}:{transition}",
        attempt_hex(record.id),
        record.attempt_count
    )
}

/// The TASK a runner's row realizes, while it is one the runner may move:
/// a live, uncancelled standard task on a runner lane. `None` means no TASK
/// write is owed.
pub(super) fn runner_task_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> MemoryResult<Option<EntityId>> {
    let Some(task_ref) = record
        .task_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let Some(body) = task_verb_body_in(vault, txn, task_ref)? else {
        return Ok(None);
    };
    if body.task_kind() != TaskKind::Standard
        || body.terminal().is_some()
        || body.settled_ladder_disposition().is_some()
        || lane_of(body.assignee) != Lane::Runner
        || vault
            .task_standing_in(txn, task_ref)?
            .is_none_or(|standing| standing.cancelled)
    {
        return Ok(None);
    }
    Ok(Some(task_ref))
}

/// A runner's Host Accept, inside the transaction that leased its try.
///
/// `Ok(None)`, with nothing written, when the row realizes no TASK, the
/// TASK is missing, not standard, already terminal or cancelled, or this
/// same try already took it.
pub(crate) fn accept_runner_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    record: &AttemptRecord,
    run_ref: Option<EntityId>,
) -> MemoryResult<Option<TaskCallReceipt>> {
    let Some(task_ref) = runner_task_in(vault, txn, record)? else {
        return Ok(None);
    };
    let memory = vault.memory(actor.entity_ref(), actor.actor_class());
    memory.verify_actor_write_in_txn(txn)?;
    let via = TaskVia::Host(HostBinding::from_leased(record, run_ref)?);
    let key = qualified_key(&via, &runner_task_key(record, "accept"), "intent key")?;
    let receipt = memory.accept_in_runner_txn(txn, &via, task_ref, key)?;
    Ok((!receipt.idempotent_replay).then_some(receipt))
}

/// A runner's Host Report, inside its transaction and before it clears
/// its lease. The queue row is the runner's to settle.
///
/// `Ok(None)`, with nothing written, when the row realizes no TASK, or the
/// TASK is missing, not standard, already terminal or cancelled.
pub(crate) fn report_runner_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    record: &AttemptRecord,
    run_ref: Option<EntityId>,
    report_key: &str,
    body: TaskReportBody,
    judged: Option<RunnerDoneAnswer>,
) -> MemoryResult<Option<TaskCallReceipt>> {
    let Some(task_ref) = runner_task_in(vault, txn, record)? else {
        return Ok(None);
    };
    let memory = vault.memory(actor.entity_ref(), actor.actor_class());
    memory.verify_actor_write_in_txn(txn)?;
    let via = TaskVia::Host(HostBinding::from_leased(record, run_ref)?);
    let attempt = AttemptHandle {
        task_ref,
        attempt_ref: record.id,
        attempt_count: record.attempt_count,
        node_ref: local_node_in(vault, txn)?,
    };
    memory
        .report_in_runner_txn(
            txn,
            &via,
            TaskReport {
                task_ref,
                attempt: Some(attempt),
                report_key: report_key.to_owned(),
                body,
            },
            judged,
        )
        .map(Some)
}

/// What a runner's caller owes once its transaction commits: the
/// peer-result signal of a TASK its report settled. Never run before
/// commit; a caller with no post-commit point leaves it to the wake pass,
/// which replays it from the binding index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(
    dead_code,
    reason = "held for the resident pump, which runs it after its commit"
)]
pub(crate) struct RunnerTaskEffects {
    settled: Option<EntityId>,
}

#[allow(
    dead_code,
    reason = "held for the resident pump, which runs it after its commit"
)]
impl RunnerTaskEffects {
    /// The effects one runner receipt owes.
    pub(crate) fn of(receipt: &TaskCallReceipt) -> Self {
        let task_ref = match receipt.handle {
            TaskHandle::Task { task_ref } | TaskHandle::Attempt(AttemptHandle { task_ref, .. }) => {
                Some(task_ref)
            }
            TaskHandle::Proposed { .. } | TaskHandle::Ask { .. } => None,
        };
        let settled = matches!(
            receipt.outcome,
            TaskOutcome::Reported {
                phase: TaskPhase::Terminal { .. }
            }
        );
        Self {
            settled: task_ref.filter(|_| settled),
        }
    }

    /// Runs them, after the runner's commit.
    pub(crate) fn run(self, vault: &Vault, now: u64) -> Result<()> {
        if let Some(task_ref) = self.settled {
            crate::llm::send_peer_result_signal(vault, task_ref, now)?;
            crate::llm::reconcile_peer_result_signals(vault, now)?;
        }
        Ok(())
    }
}

/// How a runner's queue door settles the try it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnerSettle<'a> {
    /// The try finished. Its row's result, when it names a durable entity,
    /// is the TASK's result; without one no TASK report is made.
    Done,
    /// The try finished, as [`Self::Done`], and its runner answered "Done
    /// means met?" before it settled (OF-533).
    Judged(RunnerDoneAnswer),
    /// The try failed; `retryable` when the queue tries it again.
    Failed { error: &'a str, retryable: bool },
}

/// The actor a leased row's TASK transitions run as, the one the runner
/// already writes it as: an agent dispatch's agent definition; otherwise
/// the base agent stamped on the Dreamer row, or the Dreamer for a TASK
/// realization. `None` when the row names none, and then nothing is owed.
fn runner_actor_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<Option<WriteActor>> {
    if record.kind == crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND
        && let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
        && payload.attempt_type == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
    {
        let input = crate::agent_dispatch::decode_agent_dispatch_input(&payload.input)?;
        return crate::agent_dispatch::agent_dispatch_actor(&input).map(Some);
    }
    if let Some(stamp) = vault.dreamer_attempt_authority_in_txn(txn, record.id)? {
        return Ok(Some(WriteActor::new(stamp.actor, EdgeActorClass::System)));
    }
    if record.kind == TASK_REALIZE_ATTEMPT_KIND {
        return vault
            .dreamer_authority_in_txn(txn, record.created_at)
            .map(Some);
    }
    Ok(None)
}

pub(super) fn runner_refusal(error: MemoryError) -> Error {
    Error::InvalidConfig(format!("runner task transition refused: {}", error.message))
}

/// The engine runner's take of the TASK its freshly leased row realizes:
/// [`accept_runner_task_in_txn`] as the runner's own actor, in the
/// transaction that leased it. A row that realizes no TASK is left alone.
pub(crate) fn accept_leased_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    if record.task_ref.is_none() || !record.state.is_running() {
        return Ok(());
    }
    let Some(actor) = runner_actor_in(vault, txn, record)? else {
        return Ok(());
    };
    accept_runner_task_in_txn(vault, txn, actor, record, None).map_err(runner_refusal)?;
    Ok(())
}

/// The engine runner's report on the TASK its held row realizes:
/// [`report_runner_task_in_txn`] as the runner's own actor, in the
/// transaction that settles the try and before it clears the lease. A row
/// that realizes no TASK, or holds no live lease, is left alone; a Done
/// without a durable result entity reports nothing.
pub(crate) fn report_leased_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    settle: RunnerSettle<'_>,
) -> Result<()> {
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? else {
        return Ok(());
    };
    if record.task_ref.is_none() || !record.state.is_running() {
        return Ok(());
    }
    let judged = match settle {
        RunnerSettle::Judged(answer) => Some(answer),
        RunnerSettle::Done | RunnerSettle::Failed { .. } => None,
    };
    let (transition, body) = match settle {
        RunnerSettle::Done | RunnerSettle::Judged(_) => {
            let Some(result_ref) = record
                .result_ref
                .as_ref()
                .and_then(|result| EntityId::from_hex(result.as_str()).ok())
            else {
                return Ok(());
            };
            if vault.get_entity_type_in_txn(txn, &result_ref)?.is_none() {
                return Ok(());
            }
            (
                "done",
                TaskReportBody::Done {
                    result_ref,
                    confession: None,
                },
            )
        }
        RunnerSettle::Failed { error, retryable } => (
            if retryable { "retry" } else { "failed" },
            TaskReportBody::Failed {
                error: if error.trim().is_empty() {
                    "the runner's try failed".to_owned()
                } else {
                    error.to_owned()
                },
                retryable,
                result_ref: None,
            },
        ),
    };
    let Some(actor) = runner_actor_in(vault, txn, &record)? else {
        return Ok(());
    };
    report_runner_task_in_txn(
        vault,
        txn,
        actor,
        &record,
        None,
        &runner_task_key(&record, transition),
        body,
        judged,
    )
    .map_err(runner_refusal)?;
    Ok(())
}

/// The queue kind of the one try that realizes a Dreamer-lane TASK, for the
/// Dreamer runner that executes it.
pub(crate) const REALIZE_ATTEMPT_KIND: &str = TASK_REALIZE_ATTEMPT_KIND;

/// What a runner realizes its leased row's TASK from: the TASK and its
/// current typed brief, while it is one the runner may move. `None` when the
/// row realizes no TASK, or one that is missing, terminal or cancelled.
pub(crate) fn runner_task_brief(
    vault: &Vault,
    record: &AttemptRecord,
) -> Result<Option<(EntityId, Option<super::brief::QueueTaskBrief>)>> {
    let txn = vault.store.env.read_txn()?;
    let Some(task_ref) = runner_task_in(vault, &txn, record).map_err(runner_refusal)? else {
        return Ok(None);
    };
    let brief = task_verb_body_in(vault, &txn, task_ref)?
        .and_then(|body| body.brief)
        .map(|stored| stored.brief);
    Ok(Some((task_ref, brief)))
}
