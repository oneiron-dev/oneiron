//! The highway's Report arm (OF-220): progress, blocked, done, failed and
//! release against a fenced handle, the owner's acknowledgement of a
//! failure, and brief revisions.
//!
//! STUCK is `tasks.update(blocked)` and DONE is `tasks.update(resultRef)`
//! (ARCH-0079). A report updates intent facts, never queue leases, except
//! where it settles the reporter's own external try in the transaction that
//! moves the TASK. The fence is checked twice: before any surface question
//! or ask, and again in the committing transaction. A rebind, reap or
//! cancel turns every later report into `StaleFence`; a report that reaches
//! a node without the try gets `WrongNode`.
//!
//! An engine runner reports from inside its own write transaction, through
//! the same bodies: its reads, asks and commit run in that transaction, with
//! no decisions, so no model or ladder runs under the writer.

use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState, CompleteAttempt, FailAttempt,
    RetryAttempt, SetAttemptResult,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::ask_types::{
    TaskAskDecision, TaskAskDefault, TaskAskHandle, TaskAskOptionId, TaskAskQuestion, TaskAskSpec,
    TaskAskStatus,
};
use super::brief::{EscalationTrigger, StoredBrief};
use super::consts::TASK_EXTERNAL_ATTEMPT_KIND;
use super::consult_result::TaskVerbBody;
use super::create_validation::task_body_in_txn;
use super::decision_port::{PortAnswer, TaskDecisions, TaskQuestion, ask};
use super::highway::{
    invalid_state, lease_owner_for, local_node_in, not_found, phase_of, qualified_key, stamp_fields,
};
use super::highway_accept::{
    HostFence, Lane, host_fence_in, lane_of, require_assignee, require_live_standard,
};
use super::highway_block::{BlockContinuation, BlockPurpose, selected_task_ask_option};
use super::highway_types::{
    AttemptHandle, TaskCallReceipt, TaskHandle, TaskLifecycleRecord, TaskOutcome, TaskPhase,
    TaskReport, TaskReportBody, TaskVia,
};
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::wire_decode::task_verb_body;

/// The option an escalated done-means ask settles on for "met".
pub(super) const DONE_MET_OPTION: &str = "met";
/// The option an escalated done-means ask settles on for "not met".
pub(super) const DONE_UNMET_OPTION: &str = "unmet";
/// Failure reason stamped on a try whose result did not meet done-means.
const CRITERIA_UNMET_REASON: &str = "done-means not met";

/// What a report's fence proved, in one transaction.
enum Fence {
    /// The reporter holds the work: its lane, and its live external try and
    /// lease owner when the lane has one.
    Held {
        lane: Lane,
        attempt: Option<AttemptRecord>,
        lease_owner: Option<String>,
        /// OF-540: the team run the realizing attempt's dispatch froze.
        team: Option<crate::agent_dispatch::TeamRunStamp>,
    },
    /// The reporter's external try already settled.
    Settled,
    Stale,
    WrongNode,
}

impl Fence {
    fn held(&self) -> Option<(Lane, Option<AttemptRecord>, Option<String>)> {
        match self {
            Self::Held {
                lane,
                attempt,
                lease_owner,
                ..
            } => Some((*lane, attempt.clone(), lease_owner.clone())),
            Self::Settled | Self::Stale | Self::WrongNode => None,
        }
    }

    fn outcome(&self) -> Option<TaskOutcome> {
        match self {
            Self::Held { .. } => None,
            Self::Settled | Self::Stale => Some(TaskOutcome::StaleFence),
            Self::WrongNode => Some(TaskOutcome::WrongNode),
        }
    }
}

/// What a Done report resolves to.
enum DoneVerdict {
    Met,
    Unmet,
    AskedUp(TaskAskHandle),
    /// No ask could be opened and the rule's default holds the work.
    Held,
}

/// What an escalation trigger did.
enum Escalation {
    NotListed,
    Asked(TaskAskHandle),
    /// The agent chose not to ask: its own act, never anyone's answer.
    Declined,
    /// An ask was due but the brief names no question to ask with.
    Default(TaskAskDefault),
}

/// Where one report reads, asks and commits.
///
/// A wire or host call opens its own transactions, as it always has. An
/// engine runner reports inside the write it already holds, so its take or
/// result co-commits with its queue change while its lease still fences
/// it; there admission's read-only rules run before any ask, and an ask
/// they refuse is not opened and is named in the receipt instead.
pub(super) struct ReportTxn<'a, 't> {
    txn: Option<&'a mut heed::RwTxn<'t>>,
    refused: Vec<String>,
}

impl ReportTxn<'_, '_> {
    /// A wire or host call: every read, ask and the commit opens its own.
    pub(super) const fn own() -> Self {
        Self {
            txn: None,
            refused: Vec::new(),
        }
    }
}

impl<'a, 't> ReportTxn<'a, 't> {
    /// A runner's report, inside the write transaction it holds.
    pub(super) const fn runner(txn: &'a mut heed::RwTxn<'t>) -> Self {
        Self {
            txn: Some(txn),
            refused: Vec::new(),
        }
    }
}

fn handle_entity(handle: &TaskHandle) -> EntityId {
    match handle {
        TaskHandle::Proposed { proposal_ref } => *proposal_ref,
        TaskHandle::Task { task_ref } => *task_ref,
        TaskHandle::Attempt(attempt) => attempt.task_ref,
        TaskHandle::Ask { group_ref } => *group_ref,
    }
}

fn blocked_on(body: &TaskVerbBody) -> Vec<EntityId> {
    match &body.state {
        Some(TaskExecutionState::Blocked { on, .. }) => on.clone(),
        _ => Vec::new(),
    }
}

/// Moves a live TASK to `Blocked`, keeping what it already waited on.
fn block(body: &mut TaskVerbBody, waits: &[EntityId], now: u64) {
    let (since, mut on) = match &body.state {
        Some(TaskExecutionState::Blocked { since, on }) => (*since, on.clone()),
        _ => (now, Vec::new()),
    };
    for wait in waits {
        if !on.contains(wait) {
            on.push(*wait);
        }
    }
    body.state = Some(TaskExecutionState::Blocked { since, on });
}

/// Moves a live TASK back to `Queued`: the next accept is a new try, not a
/// new TASK.
pub(super) fn requeue(body: &mut TaskVerbBody) {
    body.state = Some(TaskExecutionState::Queued);
}

/// Done means met: the held external try, when there is one, takes the
/// result and completes, and the TASK lands `Completed`.
pub(super) fn land_done_in(
    queue: &AttemptQueue<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    body: &mut TaskVerbBody,
    held: Option<(&AttemptRecord, &str)>,
    result_ref: EntityId,
    now: u64,
) -> MemoryResult<()> {
    if let Some((record, lease_owner)) = held {
        queue.set_result_in_txn(
            wtxn,
            SetAttemptResult {
                id: record.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: record.attempt_count,
                result_ref: AttemptResultRef::new(result_ref.to_hex())?,
                now,
            },
        )?;
        queue.complete_in_txn(
            wtxn,
            CompleteAttempt {
                id: record.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: record.attempt_count,
                now,
            },
        )?;
    }
    body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: Some(result_ref),
        summary: None,
        finished_at: now,
        ladder: None,
        counter_task_ref: None,
    }));
    Ok(())
}

/// Done means not met: the held external try fails and the TASK requeues.
pub(super) fn fail_unmet_in(
    queue: &AttemptQueue<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    body: &mut TaskVerbBody,
    held: Option<(&AttemptRecord, &str)>,
    now: u64,
) -> MemoryResult<()> {
    if let Some((record, lease_owner)) = held {
        queue.fail_in_txn(
            wtxn,
            FailAttempt {
                id: record.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: record.attempt_count,
                reason: CRITERIA_UNMET_REASON.to_owned(),
                now,
            },
        )?;
    }
    requeue(body);
    Ok(())
}

/// A final failure: the held external try keeps any exhaust and fails, and
/// the TASK lands `Failed`.
pub(super) fn fail_final_in(
    queue: &AttemptQueue<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    body: &mut TaskVerbBody,
    held: Option<(&AttemptRecord, &str)>,
    error: &str,
    result_ref: Option<EntityId>,
    now: u64,
) -> MemoryResult<()> {
    if let Some((record, lease_owner)) = held {
        if let Some(result_ref) = result_ref {
            queue.set_result_in_txn(
                wtxn,
                SetAttemptResult {
                    id: record.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: record.attempt_count,
                    result_ref: AttemptResultRef::new(result_ref.to_hex())?,
                    now,
                },
            )?;
        }
        queue.fail_in_txn(
            wtxn,
            FailAttempt {
                id: record.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: record.attempt_count,
                reason: error.to_owned(),
                now,
            },
        )?;
    }
    body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Failed,
        result_ref,
        summary: None,
        finished_at: now,
        ladder: None,
        counter_task_ref: None,
    }));
    Ok(())
}

/// The held external try a fence proved, for the queue half of a report.
fn held_try(
    held: &(Lane, Option<AttemptRecord>, Option<String>),
) -> Option<(&AttemptRecord, &str)> {
    held.1.as_ref().zip(held.2.as_deref())
}

pub(super) fn short_digest(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().as_str()[..16].to_owned()
}

/// The continuation an engine-opened ask on this report's block carries:
/// the TASK, what it waits on, and the try that blocked.
fn block_continuation(
    via: &TaskVia,
    task_ref: EntityId,
    attempt: Option<&AttemptHandle>,
    purpose: BlockPurpose,
) -> BlockContinuation {
    let (attempt, attempt_count) = match via {
        TaskVia::Host(binding) => (Some(binding.parent()), binding.attempt_count()),
        TaskVia::Wire => (
            attempt.map(|attempt| attempt.attempt_ref),
            attempt.map_or(0, |attempt| attempt.attempt_count),
        ),
    };
    BlockContinuation {
        task: task_ref,
        purpose,
        attempt,
        attempt_count,
    }
}

impl Memory<'_> {
    pub(super) fn highway_report(
        &self,
        via: &TaskVia,
        report: TaskReport,
        decisions: Option<&TaskDecisions<'_>>,
    ) -> MemoryResult<TaskCallReceipt> {
        let key = qualified_key(via, &report.report_key, "report key")?;
        let task_ref = report.task_ref;
        let now = self.vault().now_recorded_at();
        match report.body {
            TaskReportBody::Ack => self.report_ack(via, task_ref, &key, now),
            TaskReportBody::Brief(next) => self.report_brief(via, task_ref, &key, *next, now),
            body => {
                if self.credential_withholds(task_ref)? {
                    return Err(not_found());
                }
                if super::ask_record::ask_is_terminal(self.vault(), task_ref)?.is_some() {
                    return Err(invalid_state(
                        "an ask is answered with tasks.answer, not reported on",
                        "Answer the ask through its handle.",
                    ));
                }
                let lifecycle =
                    self.work_lifecycle(via, task_ref, &key, report.attempt.as_ref(), &body, now);
                self.report_work(
                    &mut ReportTxn::own(),
                    via,
                    task_ref,
                    &key,
                    report.attempt,
                    body,
                    decisions,
                    lifecycle,
                    now,
                )
            }
        }
    }

    /// A runner's work report inside the write transaction it holds (R1):
    /// the same bodies as the public door, with no decisions, and no
    /// after-commit signal: the caller's commit announces the TASK write.
    pub(super) fn report_in_runner_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        via: &TaskVia,
        report: TaskReport,
    ) -> MemoryResult<TaskCallReceipt> {
        let key = qualified_key(via, &report.report_key, "report key")?;
        let task_ref = report.task_ref;
        let now = self.vault().now_recorded_at();
        if matches!(report.body, TaskReportBody::Ack | TaskReportBody::Brief(_)) {
            return Err(MemoryError::bad_request(
                "an acknowledgement or brief revision is not a runner report",
            ));
        }
        let lifecycle = self.work_lifecycle(
            via,
            task_ref,
            &key,
            report.attempt.as_ref(),
            &report.body,
            now,
        );
        self.report_work(
            &mut ReportTxn::runner(wtxn),
            via,
            task_ref,
            &key,
            report.attempt,
            report.body,
            None,
            lifecycle,
            now,
        )
    }

    /// The receipt skeleton of one work report.
    fn work_lifecycle(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        attempt: Option<&AttemptHandle>,
        body: &TaskReportBody,
        now: u64,
    ) -> TaskLifecycleRecord {
        let mut lifecycle = self.lifecycle_record(
            via,
            "report",
            body.as_str(),
            Some(task_ref),
            attempt.map(|attempt| attempt.attempt_ref),
            now,
        );
        lifecycle
            .fields
            .insert("report_key".to_owned(), key.to_owned());
        lifecycle
            .fields
            .insert("body".to_owned(), body.as_str().to_owned());
        lifecycle
    }

    /// `Ack`: the owner's dismissal of a failed task, today's `tasks.update`.
    fn report_ack(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        let acked = self.tasks_ack_core(task_ref)?;
        let mut lifecycle =
            self.lifecycle_record(via, "report", "acked", Some(task_ref), None, now);
        lifecycle
            .fields
            .insert("report_key".to_owned(), key.to_owned());
        lifecycle.fields.insert("body".to_owned(), "ack".to_owned());
        lifecycle
            .fields
            .insert("acked".to_owned(), acked.acked.to_string());
        let phase = task_verb_body(self.vault(), task_ref)?
            .as_ref()
            .map_or(TaskPhase::Queued, phase_of);
        Ok(TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: Vec::new(),
            outcome: TaskOutcome::Reported { phase },
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// The fence one report runs, in `txn`: the immutable facts name the
    /// reporter, the TASK is a live standard task, and the reporter still
    /// holds the work its lane holds work by.
    fn report_fence_in(
        &self,
        txn: &heed::RoTxn<'_>,
        via: &TaskVia,
        task_ref: EntityId,
        body: &TaskVerbBody,
        attempt: Option<&AttemptHandle>,
    ) -> MemoryResult<Fence> {
        let standing = self
            .vault()
            .task_standing_in(txn, task_ref)?
            .ok_or_else(not_found)?;
        let lane = lane_of(body.assignee);
        if lane != Lane::Runner {
            require_assignee(&standing, self.actor())?;
        }
        require_live_standard(body, &standing)?;
        let generation = self
            .vault()
            .actor_binding_generation_in_txn(txn, self.actor())?;
        let task_hex = task_ref.to_hex();
        match (lane, via) {
            (Lane::Runner, TaskVia::Wire) => Err(invalid_state(
                "the engine's runner reports this task through its host binding",
                "Report from the attempt that realizes the task.",
            )),
            (Lane::Runner, TaskVia::Host(binding)) => {
                Ok(
                    match host_fence_in(self.vault(), txn, binding, &task_hex)? {
                        // The runner settles its own try; the report moves the
                        // TASK alone.
                        HostFence::Held(record) => Fence::Held {
                            lane,
                            attempt: None,
                            lease_owner: None,
                            team: crate::agent_dispatch::attempt_team_stamp(&record)?,
                        },
                        HostFence::Stale => Fence::Stale,
                        HostFence::Missing => Fence::WrongNode,
                    },
                )
            }
            (Lane::Human, _) => Ok(
                if standing.taker.is_some_and(|taker| {
                    taker.actor == self.actor() && taker.generation == generation
                }) {
                    Fence::Held {
                        lane,
                        attempt: None,
                        lease_owner: None,
                        team: None,
                    }
                } else {
                    Fence::Stale
                },
            ),
            (Lane::External, _) => {
                let handle = attempt.ok_or_else(|| {
                    MemoryError::bad_request(
                        "an external report names the attempt handle its accept returned",
                    )
                })?;
                if handle.task_ref != task_ref {
                    return Err(MemoryError::bad_request(
                        "the attempt handle names another task",
                    ));
                }
                if let (Some(named), Some(local)) =
                    (handle.node_ref, local_node_in(self.vault(), txn)?)
                    && named != local
                {
                    return Ok(Fence::WrongNode);
                }
                let Some(record) =
                    AttemptQueue::new(self.vault()).get_in_txn(txn, handle.attempt_ref)?
                else {
                    return Ok(Fence::WrongNode);
                };
                if record.task_ref.as_deref() != Some(task_hex.as_str())
                    || record.kind != TASK_EXTERNAL_ATTEMPT_KIND
                {
                    return Err(MemoryError::bad_request(
                        "the attempt handle names another task's try",
                    ));
                }
                let lease_owner = lease_owner_for(self.actor(), generation.as_ref());
                let same_try = record.attempt_count == handle.attempt_count;
                Ok(match record.state {
                    AttemptState::Leased | AttemptState::Landing
                        if same_try
                            && record.lease_owner.as_deref() == Some(lease_owner.as_str()) =>
                    {
                        // An external try carries a brief stamp, never a
                        // dispatch payload, so it names no team run.
                        Fence::Held {
                            lane,
                            attempt: Some(record),
                            lease_owner: Some(lease_owner),
                            team: None,
                        }
                    }
                    AttemptState::Completed | AttemptState::Failed
                        if same_try
                            && standing
                                .taker
                                .is_some_and(|taker| taker.actor == self.actor()) =>
                    {
                        Fence::Settled
                    }
                    _ => Fence::Stale,
                })
            }
        }
    }

    /// One read a report makes: in its own read transaction, or in the
    /// runner's write.
    fn report_read<T>(
        &self,
        rt: &ReportTxn<'_, '_>,
        read: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        match rt.txn.as_deref() {
            Some(txn) => read(&**txn),
            None => {
                let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
                read(&txn)
            }
        }
    }

    /// A report's typed ref must still name a live entity.
    fn report_resolved(&self, rt: &ReportTxn<'_, '_>, entity_ref: EntityId) -> MemoryResult<()> {
        self.report_read(rt, |txn| {
            if self
                .vault()
                .get_entity_type_in_txn(txn, &entity_ref)?
                .is_some()
            {
                Ok(())
            } else {
                Err(MemoryError::from(Error::EntityNotFound))
            }
        })
    }

    /// Opens one ask a report raises. On a wire or host call it runs in its
    /// own transaction and a refusal fails the report, as it always has. In
    /// a runner's write, admission's read-only rules run first: a refusal
    /// there opens no ask and is kept for the receipt. `continuation`, when
    /// the ask holds a block, is written beside a first admission.
    fn report_ask(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        spec: &TaskAskSpec,
        continuation: Option<(&BlockContinuation, &str)>,
    ) -> MemoryResult<Option<TaskAskHandle>> {
        match rt.txn.as_deref_mut() {
            None => Ok(Some(
                self.tasks_ask_with_txn_effect(spec, |txn, group| {
                    self.continuation_effect(txn, group, continuation)
                })?
                .handle,
            )),
            Some(txn) => {
                if let Err(refusal) = self.ask_admits_in(txn, spec) {
                    rt.refused.push(refusal.message);
                    return Ok(None);
                }
                Ok(Some(
                    self.tasks_ask_in_txn(txn, spec, |txn, group| {
                        self.continuation_effect(txn, group, continuation)
                    })?
                    .handle,
                ))
            }
        }
    }

    /// The effect a block's ask admits with: its continuation, beside it.
    fn continuation_effect(
        &self,
        txn: &mut heed::RwTxn<'_>,
        group: EntityId,
        continuation: Option<(&BlockContinuation, &str)>,
    ) -> MemoryResult<()> {
        if let Some((continuation, label)) = continuation {
            self.put_block_question_in_txn(txn, group, continuation, label)?;
        }
        Ok(())
    }

    /// An ask's status, settling it when due: in its own transactions, or
    /// in the runner's write.
    fn report_ask_status(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        group_ref: EntityId,
    ) -> MemoryResult<TaskAskStatus> {
        let handle = TaskAskHandle { group_ref };
        match rt.txn.as_deref_mut() {
            None => self.tasks_ask_status(handle),
            Some(txn) => self.tasks_ask_status_in_txn(txn, handle),
        }
    }

    /// The owner ask an engine block owes when it would otherwise leave
    /// nobody to ask (R3). On a wire or host call it opens in a transaction
    /// of its own, so any refusal leaves nothing behind; in a runner's
    /// write, admission's read-only rules refuse first. A refusal opens no
    /// ask and is named in the receipt; the TASK still blocks as it did.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door and receipt, the TASK and its brief, and the block's continuation"
    )]
    fn owner_block_ask(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        lifecycle: &mut TaskLifecycleRecord,
        task_ref: EntityId,
        brief: &StoredBrief,
        continuation: &BlockContinuation,
        key: &str,
        note: Option<&str>,
    ) -> MemoryResult<Option<TaskAskHandle>> {
        let opened = match rt.txn.as_deref_mut() {
            None => self
                .with_verified_actor_write_txn(|txn| {
                    self.open_block_ask_in_txn(txn, task_ref, brief, continuation, key, note)
                })
                .and_then(|opened| opened),
            Some(txn) => {
                self.open_block_ask_in_txn(txn, task_ref, brief, continuation, key, note)?
            }
        };
        Ok(match opened {
            Ok(handle) => {
                lifecycle
                    .fields
                    .insert("owner_ask".to_owned(), handle.group_ref.to_hex());
                Some(handle)
            }
            Err(refusal) => {
                lifecycle
                    .fields
                    .insert("owner_ask_refused".to_owned(), refusal.message);
                None
            }
        })
    }

    /// The TASK, when it already completed with `result_ref` and this actor
    /// is the one it was addressed to (or its owner, on a runner lane).
    fn settled_by(
        &self,
        rt: &ReportTxn<'_, '_>,
        task_ref: EntityId,
        result_ref: EntityId,
    ) -> MemoryResult<Option<TaskVerbBody>> {
        self.report_read(rt, |txn| {
            let body = task_body_in_txn(self.vault(), txn, task_ref)?;
            let completed = body.terminal().is_some_and(|terminal| {
                terminal.disposition == TaskTerminalDisposition::Completed
                    && terminal.result_ref == Some(result_ref)
            });
            if !completed {
                return Ok(None);
            }
            let standing = self
                .vault()
                .task_standing_in(txn, task_ref)?
                .ok_or_else(not_found)?;
            if standing.assignee != Some(self.actor()) && standing.owner != self.actor() {
                return Err(not_found());
            }
            Ok(Some(body))
        })
    }

    /// The fence, read before any ask or question.
    fn fence_now(
        &self,
        rt: &ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
    ) -> MemoryResult<(TaskVerbBody, Fence)> {
        self.report_read(rt, |txn| {
            let body = task_body_in_txn(self.vault(), txn, task_ref)?;
            let fence = self.report_fence_in(txn, via, task_ref, &body, attempt)?;
            Ok((body, fence))
        })
    }

    /// A receipt for a report the fence refused.
    fn fenced_out(
        task_ref: EntityId,
        outcome: TaskOutcome,
        mut lifecycle: TaskLifecycleRecord,
        late_result: Option<EntityId>,
    ) -> TaskCallReceipt {
        lifecycle.outcome = match outcome {
            TaskOutcome::WrongNode => "wrong_node",
            _ => "stale_fence",
        }
        .to_owned();
        if let Some(result_ref) = late_result {
            lifecycle
                .fields
                .insert("late_result".to_owned(), result_ref.to_hex());
        }
        TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: Vec::new(),
            outcome,
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        }
    }

    /// A replayed Done: the first terminal answers it.
    fn replayed_done(
        task_ref: EntityId,
        settled: &TaskVerbBody,
        mut lifecycle: TaskLifecycleRecord,
    ) -> TaskCallReceipt {
        stamp_fields(&mut lifecycle.fields, settled.brief.as_ref());
        lifecycle.outcome = "replayed".to_owned();
        TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: Vec::new(),
            outcome: TaskOutcome::Reported {
                phase: phase_of(settled),
            },
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: true,
        }
    }

    /// The five work reports, each: fence, any question or ask outside the
    /// write, then one write transaction that re-checks the fence and moves
    /// the try and the TASK together.
    #[expect(
        clippy::too_many_arguments,
        reason = "one report's door, identity, fence handle, body, decisions and receipt"
    )]
    fn report_work(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        attempt: Option<AttemptHandle>,
        body: TaskReportBody,
        decisions: Option<&TaskDecisions<'_>>,
        mut lifecycle: TaskLifecycleRecord,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        let late_result = match &body {
            TaskReportBody::Done { result_ref, .. } => Some(*result_ref),
            _ => None,
        };
        // A replayed Done answers the first terminal; a new key never
        // overwrites one. Checked before the fence, which refuses a
        // terminal task.
        if let Some(result_ref) = late_result
            && let Some(settled) = self.settled_by(rt, task_ref, result_ref)?
        {
            return Ok(Self::replayed_done(task_ref, &settled, lifecycle));
        }
        let (current, fence) = self.fence_now(rt, via, task_ref, attempt.as_ref())?;
        stamp_fields(&mut lifecycle.fields, current.brief.as_ref());
        // OF-540: the realizing attempt's frozen team run, never the
        // project's current pattern.
        if let Fence::Held {
            team: Some(team), ..
        } = &fence
        {
            crate::receipt::append_team_receipt_fields(&mut lifecycle.fields, team);
        }
        if let Some(outcome) = fence.outcome() {
            return Ok(Self::fenced_out(task_ref, outcome, lifecycle, late_result));
        }
        match body {
            TaskReportBody::Progress {
                evidence_refs,
                renew_lease,
            } => {
                for evidence in &evidence_refs {
                    self.report_resolved(rt, *evidence)?;
                }
                lifecycle.fields.insert(
                    "evidence".to_owned(),
                    evidence_refs
                        .iter()
                        .map(EntityId::to_hex)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                lifecycle
                    .fields
                    .insert("renewed".to_owned(), renew_lease.to_string());
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    Vec::new(),
                    now,
                    |queue, wtxn, body, held| {
                        if renew_lease {
                            let Some((record, lease_owner)) = held_try(held) else {
                                return Err(MemoryError::bad_request(
                                    "only an external try's lease renews through a report",
                                ));
                            };
                            queue.renew_lease_in_txn(
                                wtxn,
                                record.id,
                                lease_owner,
                                record.attempt_count,
                                now,
                            )?;
                        }
                        if matches!(
                            body.state,
                            None | Some(
                                TaskExecutionState::Queued | TaskExecutionState::Blocked { .. }
                            )
                        ) {
                            body.state = Some(TaskExecutionState::Working { started_at: now });
                        }
                        Ok(false)
                    },
                )
            }
            TaskReportBody::Blocked {
                on,
                note,
                ask: wanted,
            } => {
                let mut waits: Vec<EntityId> = on.iter().map(handle_entity).collect();
                let mut related = Vec::new();
                let continuation =
                    block_continuation(via, task_ref, attempt.as_ref(), BlockPurpose::Blocked);
                let opened = match wanted {
                    // The agent's own ask: its Progress is its exit.
                    Some(spec) => {
                        let mut spec = *spec;
                        spec.task_ref = Some(task_ref);
                        self.report_ask(rt, &spec, None)?
                    }
                    None => match self.escalate(
                        rt,
                        EscalationTrigger::Blocked,
                        task_ref,
                        key,
                        current.brief.as_ref(),
                        decisions,
                        &waits,
                        Some(&continuation),
                    )? {
                        Escalation::Asked(handle) => Some(handle),
                        Escalation::Default(default) => {
                            // No question to ask with: the rule's default is
                            // the agent's own act, never anyone's answer.
                            lifecycle
                                .fields
                                .insert("default_taken".to_owned(), format!("{default:?}"));
                            // AskMe with no question to ask with: the engine
                            // asks the owner, so the block has an exit.
                            match current.brief.as_ref() {
                                Some(brief)
                                    if default == TaskAskDefault::AskMe
                                        && brief.brief.escalation.question_ref.is_none() =>
                                {
                                    self.owner_block_ask(
                                        rt,
                                        &mut lifecycle,
                                        task_ref,
                                        brief,
                                        &continuation,
                                        key,
                                        note.as_deref(),
                                    )?
                                }
                                _ => None,
                            }
                        }
                        Escalation::NotListed | Escalation::Declined => None,
                    },
                };
                if let Some(note) = note {
                    lifecycle.fields.insert("note".to_owned(), note);
                }
                if let Some(handle) = opened {
                    waits.push(handle.group_ref);
                    related.push(TaskHandle::Ask {
                        group_ref: handle.group_ref,
                    });
                    lifecycle
                        .fields
                        .insert("ask".to_owned(), handle.group_ref.to_hex());
                }
                lifecycle.fields.insert(
                    "on".to_owned(),
                    waits
                        .iter()
                        .map(EntityId::to_hex)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    now,
                    |_, _, body, _| {
                        block(body, &waits, now);
                        Ok(false)
                    },
                )
            }
            TaskReportBody::Done {
                result_ref,
                confession,
            } => self.report_done(
                rt,
                via,
                task_ref,
                key,
                attempt,
                (result_ref, confession),
                &current,
                decisions,
                lifecycle,
                now,
            ),
            TaskReportBody::Failed {
                error,
                retryable,
                result_ref,
            } => {
                if error.trim().is_empty() {
                    return Err(MemoryError::bad_request("a failure names its error"));
                }
                if let Some(result_ref) = result_ref {
                    self.report_resolved(rt, result_ref)?;
                    lifecycle
                        .fields
                        .insert("result_ref".to_owned(), result_ref.to_hex());
                }
                lifecycle.fields.insert("error".to_owned(), error.clone());
                lifecycle
                    .fields
                    .insert("retry".to_owned(), retryable.to_string());
                let mut related = Vec::new();
                if retryable
                    && let Escalation::Asked(handle) = self.escalate(
                        rt,
                        EscalationTrigger::RetryRequested,
                        task_ref,
                        key,
                        current.brief.as_ref(),
                        decisions,
                        &[],
                        None,
                    )?
                {
                    related.push(TaskHandle::Ask {
                        group_ref: handle.group_ref,
                    });
                }
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    now,
                    |queue, wtxn, body, held| {
                        if retryable {
                            if let Some((record, lease_owner)) = held_try(held) {
                                queue.retry_in_txn(
                                    wtxn,
                                    RetryAttempt {
                                        id: record.id,
                                        lease_owner: lease_owner.to_owned(),
                                        attempt_count: record.attempt_count,
                                        backoff_until: now,
                                        last_error: Some(error.clone()),
                                        now,
                                    },
                                )?;
                            }
                            requeue(body);
                            Ok(false)
                        } else {
                            fail_final_in(
                                queue,
                                wtxn,
                                body,
                                held_try(held),
                                &error,
                                result_ref,
                                now,
                            )?;
                            Ok(true)
                        }
                    },
                )
            }
            TaskReportBody::Release { reason } => {
                if reason.trim().is_empty() {
                    return Err(MemoryError::bad_request("a release names its reason"));
                }
                lifecycle.fields.insert("reason".to_owned(), reason.clone());
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    Vec::new(),
                    now,
                    |queue, wtxn, body, held| {
                        if let Some((record, lease_owner)) = held_try(held) {
                            // The same try goes back to the queue as a fresh one,
                            // ready at once: a release is not a failure to back
                            // off from.
                            queue.retry_in_txn(
                                wtxn,
                                RetryAttempt {
                                    id: record.id,
                                    lease_owner: lease_owner.to_owned(),
                                    attempt_count: record.attempt_count,
                                    backoff_until: now,
                                    last_error: Some(reason.clone()),
                                    now,
                                },
                            )?;
                        }
                        requeue(body);
                        Ok(false)
                    },
                )
            }
            TaskReportBody::Ack | TaskReportBody::Brief(_) => Err(MemoryError::bad_request(
                "an acknowledgement or brief revision is not a work report",
            )),
        }
    }

    /// Done: the verdict, then the one write it calls for. Held with a brief
    /// that names no question opens the owner's ask (R3), so a parked result
    /// has an exit.
    #[expect(
        clippy::too_many_arguments,
        reason = "one Done's door, identity, fence handle, result, TASK, decisions and receipt"
    )]
    fn report_done(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        attempt: Option<AttemptHandle>,
        (result_ref, confession): (EntityId, Option<String>),
        current: &TaskVerbBody,
        decisions: Option<&TaskDecisions<'_>>,
        mut lifecycle: TaskLifecycleRecord,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        self.report_resolved(rt, result_ref)?;
        lifecycle
            .fields
            .insert("result_ref".to_owned(), result_ref.to_hex());
        if let Some(confession) = confession {
            lifecycle.fields.insert("confession".to_owned(), confession);
        }
        let continuation = block_continuation(
            via,
            task_ref,
            attempt.as_ref(),
            BlockPurpose::Done {
                result_ref,
                brief_rev: current.brief.as_ref().map_or(0, |brief| brief.rev),
            },
        );
        let verdict = self.done_verdict(
            rt,
            task_ref,
            key,
            current,
            result_ref,
            decisions,
            &continuation,
        )?;
        // Reading a settled ask may already have landed this result.
        if matches!(verdict, DoneVerdict::Met)
            && let Some(settled) = self.settled_by(rt, task_ref, result_ref)?
        {
            return Ok(Self::replayed_done(task_ref, &settled, lifecycle));
        }
        let mut related = Vec::new();
        match verdict {
            DoneVerdict::Met => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "met".to_owned());
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    now,
                    |queue, wtxn, body, held| {
                        land_done_in(queue, wtxn, body, held_try(held), result_ref, now)?;
                        Ok(true)
                    },
                )
            }
            DoneVerdict::Unmet => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "unmet".to_owned());
                if let Escalation::Asked(handle) = self.escalate(
                    rt,
                    EscalationTrigger::CriteriaUnmet,
                    task_ref,
                    key,
                    current.brief.as_ref(),
                    decisions,
                    &[result_ref],
                    None,
                )? {
                    related.push(TaskHandle::Ask {
                        group_ref: handle.group_ref,
                    });
                }
                self.commit_report(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    now,
                    |queue, wtxn, body, held| {
                        fail_unmet_in(queue, wtxn, body, held_try(held), now)?;
                        Ok(false)
                    },
                )
            }
            DoneVerdict::AskedUp(handle) => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "asked_up".to_owned());
                self.commit_asked_up(
                    rt,
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    result_ref,
                    handle,
                    now,
                )
            }
            DoneVerdict::Held => {
                lifecycle
                    .fields
                    .insert("criteria_verdict".to_owned(), "held".to_owned());
                let asked = match current.brief.as_ref() {
                    Some(brief) if brief.brief.escalation.question_ref.is_none() => self
                        .owner_block_ask(
                            rt,
                            &mut lifecycle,
                            task_ref,
                            brief,
                            &continuation,
                            key,
                            None,
                        )?,
                    _ => None,
                };
                match asked {
                    Some(handle) => self.commit_asked_up(
                        rt,
                        via,
                        task_ref,
                        attempt.as_ref(),
                        lifecycle,
                        result_ref,
                        handle,
                        now,
                    ),
                    None => self.commit_report(
                        rt,
                        via,
                        task_ref,
                        attempt.as_ref(),
                        lifecycle,
                        related,
                        now,
                        |_, _, body, _| {
                            block(body, &[result_ref], now);
                            Ok(false)
                        },
                    ),
                }
            }
        }
    }

    /// A Done parked on an ask: the TASK blocks on its result and the ask,
    /// and the receipt hands the ask back.
    #[expect(
        clippy::too_many_arguments,
        reason = "one Done's door, identity, fence handle, receipt, result and ask"
    )]
    fn commit_asked_up(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
        mut lifecycle: TaskLifecycleRecord,
        result_ref: EntityId,
        handle: TaskAskHandle,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        lifecycle
            .fields
            .insert("ask".to_owned(), handle.group_ref.to_hex());
        let waits = [result_ref, handle.group_ref];
        let mut receipt = self.commit_report(
            rt,
            via,
            task_ref,
            attempt,
            lifecycle,
            vec![TaskHandle::Ask {
                group_ref: handle.group_ref,
            }],
            now,
            |_, _, body, _| {
                block(body, &waits, now);
                Ok(false)
            },
        )?;
        if matches!(receipt.outcome, TaskOutcome::Reported { .. }) {
            receipt.outcome = TaskOutcome::AskedUp { ask: handle };
        }
        Ok(receipt)
    }

    /// One report's write: re-check the fence in the committing
    /// transaction, apply `apply` to the try and the TASK, write the TASK,
    /// and, when the TASK settled on a call of its own, signal its waiters
    /// after commit. In a runner's write the caller's commit announces it.
    #[expect(
        clippy::too_many_arguments,
        reason = "one report's door, identity, fence handle, receipt and its one write"
    )]
    fn commit_report(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
        mut lifecycle: TaskLifecycleRecord,
        related: Vec<TaskHandle>,
        now: u64,
        apply: impl FnOnce(
            &AttemptQueue<'_>,
            &mut heed::RwTxn<'_>,
            &mut TaskVerbBody,
            &(Lane, Option<AttemptRecord>, Option<String>),
        ) -> MemoryResult<bool>,
    ) -> MemoryResult<TaskCallReceipt> {
        if !rt.refused.is_empty() {
            lifecycle
                .fields
                .insert("ask_refused".to_owned(), rt.refused.join("; "));
        }
        let own = rt.txn.is_none();
        let committed = match rt.txn.as_deref_mut() {
            None => self.with_verified_actor_write_txn(|wtxn| {
                self.commit_report_in_txn(wtxn, via, task_ref, attempt, now, apply)
            })?,
            Some(wtxn) => self.commit_report_in_txn(wtxn, via, task_ref, attempt, now, apply)?,
        };
        let (phase, settled) = match committed {
            Ok(committed) => committed,
            Err(fence) => {
                let outcome = fence.outcome().unwrap_or(TaskOutcome::StaleFence);
                let late = lifecycle
                    .fields
                    .get("result_ref")
                    .and_then(|hex| EntityId::from_hex(hex).ok());
                return Ok(Self::fenced_out(task_ref, outcome, lifecycle, late));
            }
        };
        if own {
            self.vault().store.notify_attempt_observers();
            self.vault().store.notify_task_updates([task_ref]);
            if settled {
                // The terminal record committed before the signal goes out; a
                // crash in this gap is replayed from the local binding index.
                crate::llm::send_peer_result_signal(self.vault(), task_ref, now)?;
                crate::llm::reconcile_peer_result_signals(self.vault(), now)?;
            }
        }
        lifecycle.outcome = match &phase {
            TaskPhase::Terminal { disposition } => disposition.as_str(),
            TaskPhase::Blocked { .. } => "blocked",
            TaskPhase::Queued => "queued",
            TaskPhase::Working { .. } => "working",
            TaskPhase::Proposed { .. }
            | TaskPhase::Rejected
            | TaskPhase::Interrupted
            | TaskPhase::Asked { .. } => "reported",
        }
        .to_owned();
        Ok(TaskCallReceipt {
            handle: attempt.map_or(TaskHandle::Task { task_ref }, |attempt| {
                TaskHandle::Attempt(*attempt)
            }),
            related,
            outcome: TaskOutcome::Reported { phase },
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// The body of one report's write, in `wtxn`: the fence again, the
    /// try and the TASK moved together, the TASK written. `Err` carries
    /// the fence that refused, with nothing written.
    fn commit_report_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
        now: u64,
        apply: impl FnOnce(
            &AttemptQueue<'_>,
            &mut heed::RwTxn<'_>,
            &mut TaskVerbBody,
            &(Lane, Option<AttemptRecord>, Option<String>),
        ) -> MemoryResult<bool>,
    ) -> MemoryResult<Result<(TaskPhase, bool), Fence>> {
        let queue = AttemptQueue::new(self.vault());
        let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
        let fence = self.report_fence_in(&*wtxn, via, task_ref, &body, attempt)?;
        let Some(held) = fence.held() else {
            return Ok(Err(fence));
        };
        let settled = apply(&queue, wtxn, &mut body, &held)?;
        let phase = phase_of(&body);
        self.rewrite_task_in_txn(wtxn, task_ref, body, now)?;
        Ok(Ok((phase, settled)))
    }

    /// Done means met? A parked Done whose ask settled answers from the ask;
    /// otherwise the surface question is asked, and asking up opens the
    /// escalation ask, or takes the rule's default when no ask can be opened.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door, the TASK and its result, the surface's decisions and the block's continuation"
    )]
    fn done_verdict(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        task_ref: EntityId,
        key: &str,
        current: &TaskVerbBody,
        result_ref: EntityId,
        decisions: Option<&TaskDecisions<'_>>,
        continuation: &BlockContinuation,
    ) -> MemoryResult<DoneVerdict> {
        for wait in blocked_on(current) {
            let Ok(status) = self.report_ask_status(rt, wait) else {
                continue;
            };
            return Ok(match status {
                TaskAskStatus::Settled(result) => match selected_task_ask_option(&result) {
                    Some(option) if option.as_str() == DONE_MET_OPTION => DoneVerdict::Met,
                    Some(_) => DoneVerdict::Unmet,
                    None if matches!(result.decision, TaskAskDecision::No) => DoneVerdict::Unmet,
                    None => DoneVerdict::Held,
                },
                TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. } => {
                    DoneVerdict::AskedUp(TaskAskHandle { group_ref: wait })
                }
            });
        }
        let Some(brief) = current.brief.as_ref() else {
            return Ok(DoneVerdict::Met);
        };
        let success = &brief.brief.success;
        let mut evidence = vec![task_ref, result_ref];
        evidence.extend(brief.brief.settled.iter().copied());
        evidence.extend(
            success
                .yes_if_all
                .iter()
                .chain(&success.no_if_any)
                .filter_map(|criterion| criterion.evidence_ref),
        );
        let state = serde_json::json!({
            "objective": brief.brief.objective,
            "question": success.question,
            "yes_if_all": success.yes_if_all.iter().map(|c| c.text.as_str()).collect::<Vec<_>>(),
            "no_if_any": success.no_if_any.iter().map(|c| c.text.as_str()).collect::<Vec<_>>(),
            "result_ref": result_ref.to_hex(),
        });
        let principal = self
            .report_read(rt, |txn| {
                Ok(self.vault().task_authority_state_in(txn, task_ref)?)
            })?
            .map_or(self.actor(), |state| state.owner_ref);
        match ask(
            decisions,
            TaskQuestion::DoneMet,
            principal,
            &evidence,
            &state,
            brief.brief.escalation.reversibility,
        ) {
            PortAnswer::Yes => Ok(DoneVerdict::Met),
            PortAnswer::No => Ok(DoneVerdict::Unmet),
            PortAnswer::AskUp => {
                match self.open_escalation_ask(
                    rt,
                    task_ref,
                    key,
                    brief,
                    EscalationTrigger::CriteriaUnmet,
                    true,
                    Some(continuation),
                )? {
                    Some(handle) => Ok(DoneVerdict::AskedUp(handle)),
                    None => Ok(match brief.brief.escalation.default {
                        // The default branch is the agent's own act, never
                        // anyone's answer.
                        TaskAskDefault::Proceed => DoneVerdict::Met,
                        TaskAskDefault::Hold | TaskAskDefault::AskMe => DoneVerdict::Held,
                    }),
                }
            }
        }
    }

    /// Ask up now? On a trigger the brief lists, the surface question is
    /// asked; a yes (or no ladder) opens the escalation ask.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door, the trigger, the task and its brief, the surface's decisions and the block's continuation"
    )]
    fn escalate(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        trigger: EscalationTrigger,
        task_ref: EntityId,
        key: &str,
        brief: Option<&StoredBrief>,
        decisions: Option<&TaskDecisions<'_>>,
        evidence: &[EntityId],
        continuation: Option<&BlockContinuation>,
    ) -> MemoryResult<Escalation> {
        let Some(brief) = brief else {
            return Ok(Escalation::NotListed);
        };
        if !brief.brief.escalation.triggers.contains(&trigger) {
            return Ok(Escalation::NotListed);
        }
        let mut cited = vec![task_ref];
        cited.extend_from_slice(evidence);
        let state = serde_json::json!({
            "trigger": trigger.as_str(),
            "objective": brief.brief.objective,
            "need": brief.brief.intent.need,
        });
        match ask(
            decisions,
            TaskQuestion::AskUp,
            self.actor(),
            &cited,
            &state,
            brief.brief.escalation.reversibility,
        ) {
            PortAnswer::No => Ok(Escalation::Declined),
            PortAnswer::Yes | PortAnswer::AskUp => Ok(
                match self.open_escalation_ask(
                    rt,
                    task_ref,
                    key,
                    brief,
                    trigger,
                    false,
                    continuation,
                )? {
                    Some(handle) => Escalation::Asked(handle),
                    None => Escalation::Default(brief.brief.escalation.default),
                },
            ),
        }
    }

    /// Opens the escalation ask to the rule's target, keyed by the task, the
    /// trigger and the report key, so a re-issued report finds the same ask.
    /// An ask that holds a block carries its continuation beside it.
    /// `None` when the brief names no question to ask with.
    #[expect(
        clippy::too_many_arguments,
        reason = "the report's door, the task and its brief, the trigger and the block's continuation"
    )]
    fn open_escalation_ask(
        &self,
        rt: &mut ReportTxn<'_, '_>,
        task_ref: EntityId,
        key: &str,
        brief: &StoredBrief,
        trigger: EscalationTrigger,
        done: bool,
        continuation: Option<&BlockContinuation>,
    ) -> MemoryResult<Option<TaskAskHandle>> {
        let rule = &brief.brief.escalation;
        let Some(reference) = rule.question_ref else {
            return Ok(None);
        };
        let mut question = TaskAskQuestion::new(reference);
        let (yes, no) = if done {
            (
                (DONE_MET_OPTION, "Done means met"),
                (DONE_UNMET_OPTION, "Done means not met"),
            )
        } else {
            (("proceed", "Proceed"), ("hold", "Hold"))
        };
        for (option, text) in [yes, no] {
            question
                .options
                .insert(TaskAskOptionId::new(option)?, text.to_owned());
        }
        if done {
            question.outcome_binding = brief.brief.success.outcome_binding.clone();
        }
        let mut spec =
            TaskAskSpec::shorthand(Some(rule.to.clone()), question, rule.until, rule.default);
        spec.intent_key = format!(
            "tasks.escalate/{}/{}/{}",
            task_ref.to_hex(),
            trigger.as_str(),
            short_digest(key)
        );
        spec.task_ref = Some(task_ref);
        let label = continuation.map(|continuation| {
            super::highway_block::block_question_label(brief, &continuation.purpose, None)
        });
        self.report_ask(rt, &spec, continuation.zip(label.as_deref()))
    }
}
