//! A saved workflow's wrapper as the try that realizes a TASK (FIX 4391).
//!
//! The actor whose Owner standing the TASK's facts prove binds one run of a
//! saved workflow to an idle standard TASK on a runner lane that no try
//! realizes now, and the wrapper takes the TASK in the writer that admits
//! the run. The owner binds through his door; a leased agent binds as
//! itself, under its own lease, and a member as themselves, under the
//! funding they accepted (FIX 5316). The wrapper reaches the highway's
//! take and report through a host binding of its own, whose fence only a
//! registered wrapper bound to this TASK, by this actor under its class, and
//! still the TASK's newest try passes; no lease is relaxed. When the run
//! ends its TASK settles in a writer of its own, after the wrapper's
//! terminal commit, through the report reductions a runner's Done or final
//! failure lands through, as the actor who bound it: a binder other than
//! the owner at his door on the right its bind recorded (FIX 5349). The
//! leaves never touch the TASK.

use std::collections::HashSet;

use crate::Vault;
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, AgentSpawnContext, DispatchAgent, WorkflowStepResult,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::authority::TaskActorVerb;
use crate::context_board::{JobPresence, TaskBoardStatus, fold_up_status};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::ActorContentTxn;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::note::{NoteBody, NoteKind, encode_note_body};
use crate::run_tree::{RunTreeNode, RunTreeStatus};
use crate::task_authority::TaskStanding;
use crate::task_verb::create_validation::task_body_in_txn;
use crate::task_verb::highway::{
    attempt_hex, forbidden, not_found, phase_of, qualified_key, stamp_fields,
};
use crate::task_verb::highway_accept::{HostFence, Lane, lane_of, require_live_standard};
use crate::task_verb::lifecycle_receipt;
use crate::task_verb::runner_done::workflow_done_question;
use crate::task_verb::wire_decode::task_verb_body_in;
use crate::task_verb::{
    HostBinding, RunnerDoneAnswer, RunnerDoneQuestion, TaskCallReceipt, TaskExecutionState,
    TaskHandle, TaskKind, TaskOutcome, TaskReport, TaskReportBody, TaskTerminalDisposition,
    TaskTerminalRecord, TaskVia, prove_task_owner_in,
};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::{RunnerTaskEffects, runner_refusal};

mod binder;
mod recorded_right;

pub(crate) use binder::{WorkflowBinder, WorkflowFunding, WorkflowTaskBind};

/// The lease owner a wrapper's own host binding names. No queue lease
/// carries it: it selects the wrapper's fence, never a lease's.
pub(in crate::task_verb) const WORKFLOW_TRY_OWNER: &str = "oneiron.workflow-task-try";
/// The take's intent key, qualified by the wrapper.
const TAKE_KEY: &str = "workflow.take";
/// A run's report is a research NOTE, as a realization's result is.
const REPORT_NOTE_KIND: &str = "research";
/// Domain of a run's report NOTE id.
const REPORT_NOTE_DOMAIN: &[u8] = b"oneiron.workflow.task_report.v1";

/// One ended TASK-bound run, as its wrapper's durable rows hold it.
pub(crate) struct WorkflowRunEnd {
    pub(crate) wrapper: AttemptRecord,
    pub(crate) task: EntityId,
    /// The actor whose standing admitted the binding, under its class.
    pub(crate) bound_by: WriteActor,
    /// The run settles on the right its bind recorded (FIX 5349).
    pub(crate) settles_on_bind: bool,
    pub(crate) workflow: EntityId,
    pub(crate) steps: usize,
    pub(crate) results: Vec<WorkflowStepResult>,
}

/// How a TASK-bound run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunEnd {
    Completed,
    Failed,
    Cancelled,
    Abandoned,
}

impl RunEnd {
    const fn of(state: AttemptState) -> Option<Self> {
        match state {
            AttemptState::Completed => Some(Self::Completed),
            AttemptState::Failed => Some(Self::Failed),
            AttemptState::Cancelled => Some(Self::Cancelled),
            AttemptState::Abandoned => Some(Self::Abandoned),
            AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled
            | AttemptState::Landing => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }

    /// The key its settlement reports under, qualified by the wrapper: one
    /// per run and end, so a replay answers the first.
    fn report_key(self) -> String {
        format!("workflow.{}", self.as_str())
    }
}

/// The host binding a wrapper reaches its TASK's highway under: its own
/// row and count, and the owner no lease carries.
fn try_binding(wrapper: &AttemptRecord) -> HostBinding {
    HostBinding::new(
        wrapper.id,
        WORKFLOW_TRY_OWNER.to_owned(),
        wrapper.attempt_count,
        None,
    )
}

fn refused(message: String) -> MemoryError {
    MemoryError::from(Error::Refused(message))
}

/// Admits one TASK-bound run of a saved workflow as `caller`, whose run has
/// the parent its proof gives. The same intent key with the same TASK
/// answers its first run before the TASK is read or any lane is checked
/// (FIX 5415); another TASK, or none, under it is refused. Otherwise one
/// writer holds the caller's proof, a member's reads of what the binding
/// names on their own lane, its standing on the TASK, the bind gate, the
/// run's admission with the backlink on its wrapper alone, and the
/// wrapper's take.
pub(crate) fn dispatch_bound(
    vault: &Vault,
    caller: &WorkflowBinder<'_>,
    input: DispatchAgent,
    spawn: AgentSpawnContext,
    task: EntityId,
) -> MemoryResult<AgentDispatchOutcome> {
    let actor = caller.actor(vault)?;
    let bind = caller.bind(task, actor);
    let dispatcher = AgentDispatcher::new(vault);
    let spawn = dispatcher.prepare_bound_workflow(&input, spawn, caller.parent())?;
    let refusal = |key: &str, first| caller.retry_refusal(key, first);
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if let Some(existing) =
            dispatcher.bound_workflow_existing_in(&txn, &input, &spawn, &bind, &refusal)?
        {
            return Ok(existing);
        }
    }
    let lane = caller.member_lane()?;
    let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
    if let Some(existing) =
        dispatcher.bound_workflow_existing_in(&txn, &input, &spawn, &bind, &refusal)?
    {
        return Ok(existing);
    }
    caller.revalidate_in_txn(vault, &txn)?;
    binder::member_reads_in(vault, &mut txn, lane.as_ref(), task, &input.target)?;
    admit_in_txn(vault, &txn, actor, task)?;
    caller.fund_in_txn(vault, &mut txn, actor)?;
    let outcome = dispatcher.dispatch_bound_workflow_in_txn(&mut txn, input, spawn, &bind)?;
    if let AgentDispatchOutcome::WorkflowDispatched(status) = &outcome {
        take_in_txn(vault, &mut txn, actor, &status.attempt, task)?;
    }
    txn.commit().map_err(Error::from)?;
    vault.store.notify_attempt_observers();
    vault.store.notify_task_updates([task]);
    Ok(outcome)
}

/// The bind gate, in the admitting writer: the actor's standing on the TASK
/// by the rule every owner verb on a TASK runs, under its real class, then
/// an idle standard TASK on a runner lane that no try realizes now. Every
/// backlink is read, however many the TASK has; a refusal names the try or
/// the state found.
pub(crate) fn admit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    task: EntityId,
) -> MemoryResult<()> {
    let hex = task.to_hex();
    let standing = vault.task_standing_in(txn, task)?.ok_or_else(not_found)?;
    if standing.cancelled && standing.owner == actor.entity_ref() {
        return Err(refused(format!(
            "TASK {hex} was cancelled, and a cancelled task takes no more work"
        )));
    }
    prove_task_owner_in(
        &vault.memory(actor.entity_ref(), actor.actor_class()),
        txn,
        task,
    )?;
    let body = task_body_in_txn(vault, txn, task)?;
    if body.task_kind() != TaskKind::Standard {
        return Err(refused(format!(
            "TASK {hex} is a consult or reconciliation task; a workflow realizes only a standard task"
        )));
    }
    if let Some(terminal) = body.terminal() {
        return Err(refused(format!(
            "TASK {hex} is already {}; a terminal task takes no more work",
            terminal.disposition.as_str()
        )));
    }
    if body.settled_ladder_disposition().is_some() {
        return Err(refused(format!(
            "TASK {hex} has a settled ladder that handed it to a follow-on; it takes no more work"
        )));
    }
    if lane_of(body.assignee) != Lane::Runner {
        return Err(refused(format!(
            "TASK {hex} is addressed to a peer, a child or a person; a workflow realizes only a task the engine's runner takes"
        )));
    }
    for record in AttemptQueue::new(vault).list_task_in_txn(txn, &hex)? {
        if !record.state.is_terminal() {
            return Err(refused(format!(
                "TASK {hex} already has a live try: attempt {} is {}; cancel it or let it settle first",
                attempt_hex(record.id),
                record.state.as_str()
            )));
        }
    }
    match &body.state {
        None | Some(TaskExecutionState::Queued) => Ok(()),
        Some(state) => Err(refused(format!(
            "TASK {hex} is {}, not queued; a workflow takes only an idle task",
            busy(state, &standing)
        ))),
    }
}

/// How a TASK that is not idle stands, for its refusal: a take names its
/// taker.
fn busy(state: &TaskExecutionState, standing: &TaskStanding) -> String {
    let taker = standing
        .taker
        .map_or_else(|| "nobody".to_owned(), |taker| taker.actor.to_hex());
    match state {
        TaskExecutionState::Working { .. } => format!("working, taken by {taker}"),
        TaskExecutionState::Blocked { .. } => format!("blocked, taken by {taker}"),
        TaskExecutionState::Interrupted { .. } => "interrupted".to_owned(),
        TaskExecutionState::Queued | TaskExecutionState::Terminal(_) => "settled".to_owned(),
    }
}

/// The wrapper's take of its TASK, in the writer that admitted it: the
/// highway's Accept under the wrapper's binding, which leaves the TASK
/// Working with the binder's Accepted fact.
pub(crate) fn take_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    wrapper: &AttemptRecord,
    task: EntityId,
) -> MemoryResult<()> {
    let via = TaskVia::Host(try_binding(wrapper));
    let key = qualified_key(&via, TAKE_KEY, "intent key")?;
    let receipt = vault
        .memory(actor.entity_ref(), actor.actor_class())
        .accept_in_runner_txn(txn, &via, task, key)?;
    match receipt.outcome {
        TaskOutcome::Accepted { .. } => Ok(()),
        _ => Err(refused(format!(
            "TASK {} was not taken by its new workflow run",
            task.to_hex()
        ))),
    }
}

/// Whether `wrapper` is still its TASK's newest try: every other row the
/// TASK's backlinks name has settled, and none was made after it.
fn newest_try_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wrapper: &AttemptRecord,
    task_hex: &str,
) -> Result<bool> {
    Ok(AttemptQueue::new(vault)
        .list_task_in_txn(txn, task_hex)?
        .iter()
        .all(|row| {
            row.id == wrapper.id
                || (row.state.is_terminal() && row.created_at <= wrapper.created_at)
        }))
}

impl Memory<'_> {
    /// The fence a wrapper's own binding runs where a runner's runs its
    /// lease: the binding names a registered wrapper bound to this TASK by
    /// this actor under its class, at its current count, and still the
    /// TASK's newest try. A held fence proves the actor by the TASK's Owner
    /// rule, over the TASK's facts alone for a binder that settles on its
    /// bind (FIX 5349); a stale or missing one answers the TASK's standing.
    pub(in crate::task_verb) fn workflow_try_standing_in(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &HostBinding,
        task_ref: EntityId,
    ) -> MemoryResult<(TaskStanding, HostFence)> {
        let vault = self.vault();
        let task_hex = task_ref.to_hex();
        let mut on_bind = false;
        let fence = match AttemptQueue::new(vault).get_in_txn(txn, binding.parent())? {
            None => HostFence::Missing,
            Some(record) => {
                if record.task_ref.as_deref() != Some(task_hex.as_str()) {
                    return Err(forbidden(
                        "this host's attempt does not realize the task",
                        "Report against the task your own attempt realizes.",
                    ));
                }
                let binder = WriteActor::new(self.actor(), self.actor_class());
                let source = AgentDispatcher::new(vault)
                    .workflow_task_source_in_txn(txn, &record)?
                    .filter(|source| source.task == task_ref && source.bound_by == binder);
                if let Some(source) = source
                    && record.attempt_count == binding.attempt_count()
                    && newest_try_in(vault, txn, &record, &task_hex)?
                {
                    on_bind = source.settles_on_bind();
                    HostFence::Held(record)
                } else {
                    HostFence::Stale
                }
            }
        };
        let standing = match &fence {
            // FIX 5349: the fence matched the binding; its bind proved the
            // binder, and no fresh proof of its live right is asked.
            HostFence::Held(_) if on_bind => {
                recorded_right::standing_in(vault, txn, task_ref, self.actor())?
            }
            HostFence::Held(_) => self.highway_task_actor_in(
                txn,
                task_ref,
                TaskActorVerb::Owner,
                "A workflow run moves only the task its binder bound it to.",
            )?,
            HostFence::Stale | HostFence::Missing => vault
                .task_standing_in(txn, task_ref)?
                .ok_or_else(not_found)?,
        };
        Ok((standing, fence))
    }
}

/// Whether an ended run still owes its TASK the settlement: the live
/// standard runner TASK its wrapper took, still Working, taken by the actor
/// who bound it, and not cancelled. A TASK that moved on is not this try's
/// to settle, and an already-cancelled TASK's fact stands.
fn owed_in(vault: &Vault, txn: &heed::RoTxn<'_>, end: &WorkflowRunEnd) -> Result<bool> {
    let (Some(body), Some(standing)) = (
        task_verb_body_in(vault, txn, end.task)?,
        vault.task_standing_in(txn, end.task)?,
    ) else {
        return Ok(false);
    };
    Ok(body.task_kind() == TaskKind::Standard
        && body.terminal().is_none()
        && body.settled_ladder_disposition().is_none()
        && lane_of(body.assignee) == Lane::Runner
        && matches!(body.state, Some(TaskExecutionState::Working { .. }))
        && !standing.cancelled
        && standing
            .taker
            .is_some_and(|taker| taker.actor == end.bound_by.entity_ref()))
}

/// The "Done means met?" an ended run's settlement asks, as a leased
/// runner's Done asks it over its result: here over the run's report NOTE,
/// landed first so the judge reads it, and each settled leaf's output its
/// binder's lane reads (FIX 5293). `None` when the run did not complete,
/// its TASK is no longer its to settle, or no question is owed.
pub(crate) fn done_question(
    vault: &Vault,
    end: &WorkflowRunEnd,
) -> Result<Option<RunnerDoneQuestion>> {
    if end.wrapper.state != AttemptState::Completed {
        return Ok(None);
    }
    {
        let txn = vault.store.env.read_txn()?;
        if !owed_in(vault, &txn, end)? {
            return Ok(None);
        }
    }
    let note = report_note_id(end.wrapper.id)?;
    land_report_note(vault, end, RunEnd::Completed, note)?;
    let leaves: Vec<EntityId> = end
        .results
        .iter()
        .filter_map(|step| EntityId::from_hex(&step.result_ref).ok())
        .collect();
    workflow_done_question(vault, end.task, note, &leaves, end.bound_by)
}

/// Settles one ended run's TASK in a writer of its own, after the wrapper's
/// terminal commit: the report NOTE first, then, on the binder's task-work
/// turn and under its class, one writer that re-proves the try, moves the
/// TASK and marks the run settled. A completed run reports Done, judged
/// against the TASK's done-means (`judged`, given outside the writer, or the
/// ask a missing answer opens); a failed one reports its final failure; a
/// cancelled or abandoned one closes the TASK so. A TASK that moved on is
/// marked with no move. The peer-result signal goes after commit; a signal
/// that fails is logged and the wake pass replays it.
pub(crate) fn settle(
    vault: &Vault,
    end: &WorkflowRunEnd,
    judged: Option<RunnerDoneAnswer>,
    now: u64,
) -> Result<bool> {
    let Some(ended) = RunEnd::of(end.wrapper.state) else {
        return Ok(false);
    };
    let note = report_note_id(end.wrapper.id)?;
    land_report_note(vault, end, ended, note)?;
    let memory = vault
        .memory(end.bound_by.entity_ref(), end.bound_by.actor_class())
        .task_work_memory();
    let mut txn = vault.store.env.write_txn()?;
    let receipt = if owed_in(vault, &txn, end)? {
        let right = recorded_right::binder_right_in(&memory, &txn, end, note);
        let moved = match ended {
            RunEnd::Completed | RunEnd::Failed => {
                report_in(&memory, &mut txn, end, ended, note, right, judged)
            }
            RunEnd::Cancelled | RunEnd::Abandoned => {
                close_in(&memory, &mut txn, end, ended, note, right, now)
            }
        };
        Some(moved.map_err(runner_refusal)?)
    } else {
        None
    };
    AgentDispatcher::new(vault).mark_workflow_task_settled_in(
        &mut txn,
        end.wrapper.id,
        ended.as_str(),
    )?;
    txn.commit()?;
    let Some(receipt) = receipt else {
        return Ok(false);
    };
    vault.store.notify_attempt_observers();
    vault.store.notify_task_updates([end.task]);
    if let Err(error) = RunnerTaskEffects::of(&receipt).run(vault, now) {
        tracing::warn!(kind = ?error.kind(), task = %end.task.to_hex(), "a settled workflow TASK's peer signal did not go out; the wake pass replays it");
    }
    Ok(matches!(
        receipt.outcome,
        TaskOutcome::Reported { .. } | TaskOutcome::AskedUp { .. }
    ))
}

/// A completed or failed run's report on its TASK, in the settling writer:
/// Done with the report NOTE as its result, or a final failure keeping the
/// NOTE as its exhaust. The highway's report runs its fence, judgment,
/// reductions, receipt and journal; the receipt names a binder's right that
/// no longer held (`right`, FIX 5349).
fn report_in(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    end: &WorkflowRunEnd,
    ended: RunEnd,
    note: EntityId,
    right: Option<&str>,
    judged: Option<RunnerDoneAnswer>,
) -> MemoryResult<TaskCallReceipt> {
    let body = if ended == RunEnd::Completed {
        TaskReportBody::Done {
            result_ref: note,
            confession: None,
        }
    } else {
        TaskReportBody::Failed {
            error: end.wrapper.last_error.as_deref().map_or_else(
                || "the workflow run failed".to_owned(),
                |error| format!("the workflow run failed: {error}"),
            ),
            retryable: false,
            result_ref: Some(note),
        }
    };
    memory.report_in_runner_txn_noting(
        txn,
        &TaskVia::Host(try_binding(&end.wrapper)),
        TaskReport {
            task_ref: end.task,
            attempt: None,
            report_key: ended.report_key(),
            body,
        },
        judged,
        right.map(|right| (recorded_right::BINDER_RIGHT, right)),
    )
}

/// A cancelled or abandoned run closes its TASK the same way, in the
/// settling writer, under the fence a report runs: the terminal record
/// keeps the report NOTE, through the shared TASK-body writer, and its
/// lifecycle receipt is marked the settling one, naming a binder's right
/// that no longer held (`right`, FIX 5349).
fn close_in(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    end: &WorkflowRunEnd,
    ended: RunEnd,
    note: EntityId,
    right: Option<&str>,
    now: u64,
) -> MemoryResult<TaskCallReceipt> {
    let vault = memory.vault();
    let binding = try_binding(&end.wrapper);
    let via = TaskVia::Host(binding.clone());
    let key = qualified_key(&via, &ended.report_key(), "report key")?;
    let disposition = if ended == RunEnd::Cancelled {
        TaskTerminalDisposition::Cancelled
    } else {
        TaskTerminalDisposition::Abandoned
    };
    let mut lifecycle = memory.lifecycle_record(
        &via,
        "report",
        disposition.as_str(),
        Some(end.task),
        Some(end.wrapper.id),
        now,
    );
    lifecycle
        .fields
        .insert("report_key".to_owned(), key.clone());
    lifecycle
        .fields
        .insert("body".to_owned(), ended.as_str().to_owned());
    lifecycle
        .fields
        .insert("result_ref".to_owned(), note.to_hex());
    if let Some(right) = right {
        lifecycle
            .fields
            .insert(recorded_right::BINDER_RIGHT.to_owned(), right.to_owned());
    }
    let (standing, fence) = memory.workflow_try_standing_in(&*txn, &binding, end.task)?;
    let mut body = task_body_in_txn(vault, &*txn, end.task)?;
    require_live_standard(&body, &standing)?;
    stamp_fields(&mut lifecycle.fields, body.brief.as_ref());
    let handle = TaskHandle::Task { task_ref: end.task };
    if !matches!(fence, HostFence::Held(_)) {
        lifecycle.outcome = "stale_fence".to_owned();
        return Ok(TaskCallReceipt {
            handle,
            related: Vec::new(),
            outcome: TaskOutcome::StaleFence,
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        });
    }
    body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition,
        result_ref: Some(note),
        summary: None,
        finished_at: now,
        ladder: None,
        counter_task_ref: None,
    }));
    let phase = phase_of(&body);
    memory.rewrite_task_in_txn(txn, end.task, body, now)?;
    let mut receipt = TaskCallReceipt {
        handle,
        related: Vec::new(),
        outcome: TaskOutcome::Reported { phase },
        receipt_ref: None,
        lifecycle: Some(lifecycle),
        idempotent_replay: false,
    };
    if memory.keeps_lifecycle() {
        let id = lifecycle_receipt::receipt_id(
            "report",
            &[
                end.task.as_bytes().as_slice(),
                end.wrapper.id.as_bytes().as_slice(),
                key.as_bytes(),
            ],
        )?;
        lifecycle_receipt::stamp_in(vault, txn, &mut receipt, id, None)?;
        if let Some(id) = &receipt.receipt_ref {
            lifecycle_receipt::mark_settled_in(vault, txn, id)?;
        }
    }
    Ok(receipt)
}

/// A run's report NOTE id, derived from its wrapper alone, so every pass
/// names the same entity.
fn report_note_id(root: AttemptId) -> Result<EntityId> {
    EntityId::derive(REPORT_NOTE_DOMAIN, &[root.as_bytes().as_slice()])
}

/// Lands an ended run's report NOTE in a writer of its own unless it is
/// there. Pointer-only: the run, its TASK, how it ended and each settled
/// step's result by its handle, never an output body. The actor who bound
/// the run authors it, under its class; a binder that settles on its bind
/// authors it on that recorded right, its live Grant not asked (FIX 5349).
fn land_report_note(
    vault: &Vault,
    end: &WorkflowRunEnd,
    ended: RunEnd,
    note: EntityId,
) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    if vault.get_entity_type_in_txn(&txn, &note)?.is_some() {
        return Ok(());
    }
    let now = vault.now_recorded_at();
    let body = encode_note_body(&NoteBody {
        kind: NoteKind::parse(REPORT_NOTE_KIND).ok_or(Error::InvariantViolation(
            "the research NOTE kind is not shipped",
        ))?,
        author_ref: end.bound_by.entity_ref(),
        markdown: report_markdown(end, ended),
        source_revision_ref: *note.as_bytes(),
    })?;
    let batch = || {
        vault
            .batch_in()
            .put_authored_note(
                &note,
                &end.bound_by.entity_ref(),
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .edge(&note, EdgeKind::AuthoredBy, &end.bound_by.entity_ref(), 1.0)
            .edge(&note, EdgeKind::About, &end.task, 1.0)
    };
    if end.settles_on_bind {
        batch().apply(&mut txn)?;
    } else {
        let mut content = ActorContentTxn::new(vault, &mut txn, end.bound_by)?;
        content.apply_batch(batch())?;
        content.finish()?;
    }
    txn.commit()?;
    Ok(())
}

/// The report NOTE's text: refs and handles only.
fn report_markdown(end: &WorkflowRunEnd, ended: RunEnd) -> String {
    let mut lines = vec![
        "# Workflow run report".to_owned(),
        String::new(),
        format!("- workflow: {}", end.workflow.to_hex()),
        format!("- run: {}", attempt_hex(end.wrapper.id)),
        format!("- task: {}", end.task.to_hex()),
        format!("- ended: {}", ended.as_str()),
    ];
    if let Some(cause) = end.wrapper.last_error.as_deref() {
        lines.push(format!("- cause: {cause}"));
    }
    lines.push(String::new());
    lines.push(format!(
        "Steps settled: {} of {}",
        end.results.len(),
        end.steps
    ));
    lines.extend(end.results.iter().map(|step| {
        format!(
            "{}. agent {} (requested {}), attempt {}: {}",
            step.ordinal + 1,
            step.dispatched_agent,
            step.requested_agent,
            attempt_hex(step.attempt_id),
            step.result_ref
        )
    }));
    lines.join("\n")
}

/// A TASK-bound wrapper's job on the board. The wrapper waits paused while
/// its active leaf works, so a paused one reads as that leaf stands:
/// running, held or queued. Any other job is left as it is.
pub(in crate::task_verb) fn bound_wrapper_job(
    node: &RunTreeNode,
    mut job: JobPresence,
    superseded: &HashSet<String>,
) -> JobPresence {
    if node.status != RunTreeStatus::Paused
        || !AgentDispatcher::is_workflow_attempt_type(&node.worker_kind)
    {
        return job;
    }
    let mut live = Vec::new();
    live_leaves(&node.children, superseded, &mut live);
    for (leaf, status) in [
        (RunTreeStatus::Running, TaskBoardStatus::Running),
        (RunTreeStatus::Paused, TaskBoardStatus::Scheduled),
        (RunTreeStatus::Queued, TaskBoardStatus::Queued),
    ] {
        if live.contains(&leaf) {
            job.status = status;
            break;
        }
    }
    job
}

/// The statuses of a wrapper's live leaves no later try replaces, their
/// retries included.
fn live_leaves(nodes: &[RunTreeNode], superseded: &HashSet<String>, out: &mut Vec<RunTreeStatus>) {
    for node in nodes {
        if !superseded.contains(&node.attempt_id)
            && matches!(
                node.status,
                RunTreeStatus::Queued | RunTreeStatus::Running | RunTreeStatus::Paused
            )
        {
            out.push(node.status);
        }
        live_leaves(&node.children, superseded, out);
    }
}

/// Whether a realizing job is a bound workflow run that completed.
fn completed_run(job: &JobPresence) -> bool {
    job.status == TaskBoardStatus::Done && AgentDispatcher::is_workflow_attempt_type(&job.kind)
}

/// An open TASK's board status from its realizing jobs. A bound workflow
/// run that completed has not settled its TASK until the TASK says so: its
/// Done never stands for an open TASK, and while the TASK is still Working
/// its settlement is work in flight. With no such run this is the ordinary
/// fold.
pub(in crate::task_verb) fn open_task_status(
    state: Option<&TaskExecutionState>,
    jobs: &[JobPresence],
) -> TaskBoardStatus {
    if !jobs.iter().any(completed_run) {
        return fold_up_status(jobs).unwrap_or(TaskBoardStatus::Queued);
    }
    let live: Vec<JobPresence> = jobs
        .iter()
        .filter(|&job| !completed_run(job))
        .cloned()
        .collect();
    match fold_up_status(&live) {
        Some(status) => status,
        None if matches!(state, Some(TaskExecutionState::Working { .. })) => {
            TaskBoardStatus::Running
        }
        None => TaskBoardStatus::Queued,
    }
}
