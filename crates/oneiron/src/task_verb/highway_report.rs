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
use super::create_validation::{require_resolved_entity, task_body_in_txn};
use super::decision_port::{PortAnswer, TaskDecisions, TaskQuestion, ask};
use super::highway::{
    invalid_state, lease_owner_for, local_node_in, not_found, phase_of, qualified_key, stamp_fields,
};
use super::highway_accept::{
    HostFence, Lane, host_fence_in, lane_of, require_assignee, require_live_standard,
};
use super::highway_types::{
    AttemptHandle, TaskCallReceipt, TaskHandle, TaskLifecycleRecord, TaskOutcome, TaskPhase,
    TaskReport, TaskReportBody, TaskVia,
};
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::wire_decode::task_verb_body;

/// The option an escalated done-means ask settles on for "met".
const DONE_MET_OPTION: &str = "met";
/// The option an escalated done-means ask settles on for "not met".
const DONE_UNMET_OPTION: &str = "unmet";
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
fn requeue(body: &mut TaskVerbBody) {
    body.state = Some(TaskExecutionState::Queued);
}

fn short_digest(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().as_str()[..16].to_owned()
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
                let mut lifecycle = self.lifecycle_record(
                    via,
                    "report",
                    body.as_str(),
                    Some(task_ref),
                    report.attempt.map(|attempt| attempt.attempt_ref),
                    now,
                );
                lifecycle
                    .fields
                    .insert("report_key".to_owned(), key.clone());
                lifecycle
                    .fields
                    .insert("body".to_owned(), body.as_str().to_owned());
                let attempt = report.attempt;
                self.report_work(
                    via, task_ref, &key, attempt, body, decisions, lifecycle, now,
                )
            }
        }
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
                        HostFence::Held(_) => Fence::Held {
                            lane,
                            attempt: None,
                            lease_owner: None,
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
                        Fence::Held {
                            lane,
                            attempt: Some(record),
                            lease_owner: Some(lease_owner),
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

    /// The TASK, when it already completed with `result_ref` and this actor
    /// is the one it was addressed to (or its owner, on a runner lane).
    fn settled_by(
        &self,
        task_ref: EntityId,
        result_ref: EntityId,
    ) -> MemoryResult<Option<TaskVerbBody>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let body = task_body_in_txn(self.vault(), &txn, task_ref)?;
        let completed = body.terminal().is_some_and(|terminal| {
            terminal.disposition == TaskTerminalDisposition::Completed
                && terminal.result_ref == Some(result_ref)
        });
        if !completed {
            return Ok(None);
        }
        let standing = self
            .vault()
            .task_standing_in(&txn, task_ref)?
            .ok_or_else(not_found)?;
        if standing.assignee != Some(self.actor()) && standing.owner != self.actor() {
            return Err(not_found());
        }
        Ok(Some(body))
    }

    /// The fence, read before any ask or question.
    fn fence_now(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        attempt: Option<&AttemptHandle>,
    ) -> MemoryResult<(TaskVerbBody, Fence)> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let body = task_body_in_txn(self.vault(), &txn, task_ref)?;
        let fence = self.report_fence_in(&txn, via, task_ref, &body, attempt)?;
        Ok((body, fence))
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

    /// The five work reports, each: fence, any question or ask outside the
    /// write, then one write transaction that re-checks the fence and moves
    /// the try and the TASK together.
    #[expect(
        clippy::too_many_arguments,
        reason = "one report's identity, fence handle, body, decisions and receipt"
    )]
    fn report_work(
        &self,
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
            && let Some(settled) = self.settled_by(task_ref, result_ref)?
        {
            stamp_fields(&mut lifecycle.fields, settled.brief.as_ref());
            lifecycle.outcome = "replayed".to_owned();
            return Ok(TaskCallReceipt {
                handle: TaskHandle::Task { task_ref },
                related: Vec::new(),
                outcome: TaskOutcome::Reported {
                    phase: phase_of(&settled),
                },
                receipt_ref: None,
                lifecycle: Some(lifecycle),
                idempotent_replay: true,
            });
        }
        let (current, fence) = self.fence_now(via, task_ref, attempt.as_ref())?;
        stamp_fields(&mut lifecycle.fields, current.brief.as_ref());
        if let Some(outcome) = fence.outcome() {
            return Ok(Self::fenced_out(task_ref, outcome, lifecycle, late_result));
        }
        match body {
            TaskReportBody::Progress {
                evidence_refs,
                renew_lease,
            } => {
                for evidence in &evidence_refs {
                    require_resolved_entity(self.vault(), *evidence)?;
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
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    Vec::new(),
                    now,
                    |queue, wtxn, body, held| {
                        if renew_lease {
                            let (Some(record), Some(lease_owner)) =
                                (held.1.as_ref(), held.2.as_deref())
                            else {
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
                if let Some(note) = note {
                    lifecycle.fields.insert("note".to_owned(), note);
                }
                let opened = match wanted {
                    Some(spec) => {
                        let mut spec = *spec;
                        spec.task_ref = Some(task_ref);
                        Some(self.tasks_ask(&spec)?.handle)
                    }
                    None => match self.escalate(
                        EscalationTrigger::Blocked,
                        task_ref,
                        key,
                        current.brief.as_ref(),
                        decisions,
                        &waits,
                        false,
                    )? {
                        Escalation::Asked(handle) => Some(handle),
                        Escalation::Default(default) => {
                            // No question to ask with: the rule's default is
                            // the agent's own act, never anyone's answer.
                            lifecycle
                                .fields
                                .insert("default_taken".to_owned(), format!("{default:?}"));
                            None
                        }
                        Escalation::NotListed | Escalation::Declined => None,
                    },
                };
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
            } => {
                require_resolved_entity(self.vault(), result_ref)?;
                lifecycle
                    .fields
                    .insert("result_ref".to_owned(), result_ref.to_hex());
                if let Some(confession) = confession {
                    lifecycle.fields.insert("confession".to_owned(), confession);
                }
                let verdict = self.done_verdict(task_ref, key, &current, result_ref, decisions)?;
                let mut related = Vec::new();
                match verdict {
                    DoneVerdict::Met => {
                        lifecycle
                            .fields
                            .insert("criteria_verdict".to_owned(), "met".to_owned());
                        self.commit_report(
                            via,
                            task_ref,
                            attempt.as_ref(),
                            lifecycle,
                            related,
                            now,
                            |queue, wtxn, body, held| {
                                if let (Some(record), Some(lease_owner)) =
                                    (held.1.as_ref(), held.2.as_ref())
                                {
                                    queue.set_result_in_txn(
                                        wtxn,
                                        SetAttemptResult {
                                            id: record.id,
                                            lease_owner: lease_owner.clone(),
                                            attempt_count: record.attempt_count,
                                            result_ref: AttemptResultRef::new(result_ref.to_hex())?,
                                            now,
                                        },
                                    )?;
                                    queue.complete_in_txn(
                                        wtxn,
                                        CompleteAttempt {
                                            id: record.id,
                                            lease_owner: lease_owner.clone(),
                                            attempt_count: record.attempt_count,
                                            now,
                                        },
                                    )?;
                                }
                                body.state =
                                    Some(TaskExecutionState::Terminal(TaskTerminalRecord {
                                        disposition: TaskTerminalDisposition::Completed,
                                        result_ref: Some(result_ref),
                                        summary: None,
                                        finished_at: now,
                                        ladder: None,
                                        counter_task_ref: None,
                                    }));
                                Ok(true)
                            },
                        )
                    }
                    DoneVerdict::Unmet => {
                        lifecycle
                            .fields
                            .insert("criteria_verdict".to_owned(), "unmet".to_owned());
                        if let Escalation::Asked(handle) = self.escalate(
                            EscalationTrigger::CriteriaUnmet,
                            task_ref,
                            key,
                            current.brief.as_ref(),
                            decisions,
                            &[result_ref],
                            false,
                        )? {
                            related.push(TaskHandle::Ask {
                                group_ref: handle.group_ref,
                            });
                        }
                        self.commit_report(
                            via,
                            task_ref,
                            attempt.as_ref(),
                            lifecycle,
                            related,
                            now,
                            |queue, wtxn, body, held| {
                                if let (Some(record), Some(lease_owner)) =
                                    (held.1.as_ref(), held.2.as_ref())
                                {
                                    queue.fail_in_txn(
                                        wtxn,
                                        FailAttempt {
                                            id: record.id,
                                            lease_owner: lease_owner.clone(),
                                            attempt_count: record.attempt_count,
                                            reason: CRITERIA_UNMET_REASON.to_owned(),
                                            now,
                                        },
                                    )?;
                                }
                                requeue(body);
                                Ok(false)
                            },
                        )
                    }
                    DoneVerdict::AskedUp(handle) => {
                        lifecycle
                            .fields
                            .insert("criteria_verdict".to_owned(), "asked_up".to_owned());
                        lifecycle
                            .fields
                            .insert("ask".to_owned(), handle.group_ref.to_hex());
                        let waits = [result_ref, handle.group_ref];
                        let mut receipt = self.commit_report(
                            via,
                            task_ref,
                            attempt.as_ref(),
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
                    DoneVerdict::Held => {
                        lifecycle
                            .fields
                            .insert("criteria_verdict".to_owned(), "held".to_owned());
                        self.commit_report(
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
                        )
                    }
                }
            }
            TaskReportBody::Failed {
                error,
                retryable,
                result_ref,
            } => {
                if error.trim().is_empty() {
                    return Err(MemoryError::bad_request("a failure names its error"));
                }
                if let Some(result_ref) = result_ref {
                    require_resolved_entity(self.vault(), result_ref)?;
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
                        EscalationTrigger::RetryRequested,
                        task_ref,
                        key,
                        current.brief.as_ref(),
                        decisions,
                        &[],
                        false,
                    )?
                {
                    related.push(TaskHandle::Ask {
                        group_ref: handle.group_ref,
                    });
                }
                self.commit_report(
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    related,
                    now,
                    |queue, wtxn, body, held| {
                        if let (Some(record), Some(lease_owner)) =
                            (held.1.as_ref(), held.2.as_ref())
                        {
                            if retryable {
                                queue.retry_in_txn(
                                    wtxn,
                                    RetryAttempt {
                                        id: record.id,
                                        lease_owner: lease_owner.clone(),
                                        attempt_count: record.attempt_count,
                                        backoff_until: now,
                                        last_error: Some(error.clone()),
                                        now,
                                    },
                                )?;
                            } else {
                                if let Some(result_ref) = result_ref {
                                    queue.set_result_in_txn(
                                        wtxn,
                                        SetAttemptResult {
                                            id: record.id,
                                            lease_owner: lease_owner.clone(),
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
                                        lease_owner: lease_owner.clone(),
                                        attempt_count: record.attempt_count,
                                        reason: error.clone(),
                                        now,
                                    },
                                )?;
                            }
                        }
                        if retryable {
                            requeue(body);
                            Ok(false)
                        } else {
                            body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
                                disposition: TaskTerminalDisposition::Failed,
                                result_ref,
                                summary: None,
                                finished_at: now,
                                ladder: None,
                                counter_task_ref: None,
                            }));
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
                    via,
                    task_ref,
                    attempt.as_ref(),
                    lifecycle,
                    Vec::new(),
                    now,
                    |queue, wtxn, body, held| {
                        if let (Some(record), Some(lease_owner)) =
                            (held.1.as_ref(), held.2.as_ref())
                        {
                            // The same try goes back to the queue as a fresh one,
                            // ready at once: a release is not a failure to back
                            // off from.
                            queue.retry_in_txn(
                                wtxn,
                                RetryAttempt {
                                    id: record.id,
                                    lease_owner: lease_owner.clone(),
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

    /// One report's write: re-check the fence in the committing
    /// transaction, apply `apply` to the try and the TASK, write the TASK,
    /// and, when the TASK settled, signal its waiters after commit.
    #[expect(
        clippy::too_many_arguments,
        reason = "one report's identity, fence handle, receipt and its one write"
    )]
    fn commit_report(
        &self,
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
        let queue = AttemptQueue::new(self.vault());
        let committed = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            let fence = self.report_fence_in(&*wtxn, via, task_ref, &body, attempt)?;
            let Some(held) = fence.held() else {
                return Ok(Err(fence));
            };
            let settled = apply(&queue, wtxn, &mut body, &held)?;
            let phase = phase_of(&body);
            self.rewrite_task_in_txn(wtxn, task_ref, body, now)?;
            Ok(Ok((phase, settled)))
        })?;
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
        self.vault().store.notify_attempt_observers();
        self.vault().store.notify_task_updates([task_ref]);
        if settled {
            // The terminal record committed before the signal goes out; a
            // crash in this gap is replayed from the local binding index.
            crate::llm::send_peer_result_signal(self.vault(), task_ref, now)?;
            crate::llm::reconcile_peer_result_signals(self.vault(), now)?;
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

    /// Done means met? A parked Done whose ask settled answers from the ask;
    /// otherwise the surface question is asked, and asking up opens the
    /// escalation ask, or takes the rule's default when no ask can be opened.
    fn done_verdict(
        &self,
        task_ref: EntityId,
        key: &str,
        current: &TaskVerbBody,
        result_ref: EntityId,
        decisions: Option<&TaskDecisions<'_>>,
    ) -> MemoryResult<DoneVerdict> {
        for wait in blocked_on(current) {
            let Ok(status) = self.tasks_ask_status(TaskAskHandle { group_ref: wait }) else {
                continue;
            };
            return Ok(match status {
                TaskAskStatus::Settled(result) => match &result.decision {
                    TaskAskDecision::Answer(option) if option.as_str() == DONE_MET_OPTION => {
                        DoneVerdict::Met
                    }
                    TaskAskDecision::Answer(_) | TaskAskDecision::No => DoneVerdict::Unmet,
                    _ => DoneVerdict::Held,
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
            .vault()
            .task_authority_state(task_ref)?
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
                    task_ref,
                    key,
                    brief,
                    EscalationTrigger::CriteriaUnmet,
                    true,
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
        reason = "the trigger, the task and its brief, and the surface's decisions"
    )]
    fn escalate(
        &self,
        trigger: EscalationTrigger,
        task_ref: EntityId,
        key: &str,
        brief: Option<&StoredBrief>,
        decisions: Option<&TaskDecisions<'_>>,
        evidence: &[EntityId],
        done: bool,
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
                match self.open_escalation_ask(task_ref, key, brief, trigger, done)? {
                    Some(handle) => Escalation::Asked(handle),
                    None => Escalation::Default(brief.brief.escalation.default),
                },
            ),
        }
    }

    /// Opens the escalation ask to the rule's target, keyed by the task, the
    /// trigger and the report key, so a re-issued report finds the same ask.
    /// `None` when the brief names no question to ask with.
    fn open_escalation_ask(
        &self,
        task_ref: EntityId,
        key: &str,
        brief: &StoredBrief,
        trigger: EscalationTrigger,
        done: bool,
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
        Ok(Some(self.tasks_ask(&spec)?.handle))
    }
}
