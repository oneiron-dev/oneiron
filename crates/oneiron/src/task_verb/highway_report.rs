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
//!
//! A report that names its try is journaled with its receipt in the
//! committing transaction ([`report_journal`]); the same report again is
//! answered from the journal before anything else runs.
//!
//! Entry: `Memory::highway_report`.
//! Receipt/work/done methods live in children; shared report types stay here.

use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState, CompleteAttempt, FailAttempt,
    RetryAttempt, SetAttemptResult,
};
use crate::authority::TaskActorVerb;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::ask_effect::AskEffect;
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
use super::highway_accept::{HostFence, Lane, lane_of, require_live_standard};
use super::highway_block;
use super::highway_block::{BlockContinuation, BlockPurpose, selected_task_ask_option};
use super::highway_types::{
    AttemptHandle, TaskCallReceipt, TaskHandle, TaskLifecycleRecord, TaskOutcome, TaskPhase,
    TaskReport, TaskReportBody, TaskVia,
};
use super::lifecycle_receipt;
use super::report_journal::{self, ReportIdentity};
use super::runner_done::RunnerDoneAnswer;
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::wire_decode::task_verb_body;

mod done;
mod receipt;
mod work;

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
    /// The runner's own answer to "Done means met?", asked before its write.
    judged: Option<RunnerDoneAnswer>,
    /// The report's journal identity, when it names a try.
    journal: Option<ReportIdentity>,
    /// The id this report keeps its lifecycle receipt under when its write
    /// applies; `None` in a session that keeps no record.
    receipt_id: Option<String>,
    /// What the report's decisions returned beside their answers (FIX
    /// 10179, 10183): each ladder receipt and each settled ask's binding,
    /// as lifecycle fields its commit keeps.
    decisions: Vec<(String, String)>,
}

impl ReportTxn<'_, '_> {
    /// A wire or host call: every read, ask and the commit opens its own.
    pub(super) const fn own() -> Self {
        Self {
            txn: None,
            refused: Vec::new(),
            judged: None,
            journal: None,
            receipt_id: None,
            decisions: Vec::new(),
        }
    }
}

impl<'a, 't> ReportTxn<'a, 't> {
    /// A runner's report, inside the write transaction it holds, with the
    /// Done answer it brought.
    pub(super) const fn runner(
        txn: &'a mut heed::RwTxn<'t>,
        judged: Option<RunnerDoneAnswer>,
    ) -> Self {
        Self {
            txn: Some(txn),
            refused: Vec::new(),
            judged,
            journal: None,
            receipt_id: None,
            decisions: Vec::new(),
        }
    }

    /// Keeps `value` under `field` in the lifecycle this report commits.
    fn note_decision(&mut self, field: &str, value: String) {
        self.decisions.push((field.to_owned(), value));
    }

    /// This report, journaled under `journal` when it names a try.
    fn journaled(mut self, journal: Option<ReportIdentity>) -> Self {
        self.journal = journal;
        self
    }

    /// This report, keeping its lifecycle receipt under `receipt_id` when
    /// its write applies.
    fn receipted(mut self, receipt_id: Option<String>) -> Self {
        self.receipt_id = receipt_id;
        self
    }
}

/// What one report's write did: the receipt it answers with, whether the
/// TASK settled, and whether this call applied it (not a replay or a fence
/// refusal).
struct ReportCommit {
    receipt: TaskCallReceipt,
    settled: bool,
    applied: bool,
}

/// What one report's write commits: its door, TASK, fence handle and
/// journal identity, the receipt it answers with, and the id its lifecycle
/// receipt is kept under.
struct StagedReport<'r> {
    via: &'r TaskVia,
    task_ref: EntityId,
    attempt: Option<&'r AttemptHandle>,
    journal: Option<&'r ReportIdentity>,
    receipt_id: Option<String>,
    lifecycle: TaskLifecycleRecord,
    related: Vec<TaskHandle>,
    asked_up: Option<TaskAskHandle>,
    now: u64,
}

fn handle_entity(handle: &TaskHandle) -> EntityId {
    match handle {
        TaskHandle::Proposed { proposal_ref } => *proposal_ref,
        TaskHandle::Task { task_ref } => *task_ref,
        TaskHandle::Attempt(attempt) => attempt.task_ref,
        TaskHandle::Ask { group_ref } => *group_ref,
    }
}

/// What "Done means met?" is asked over: the TASK, its result, the brief's
/// settled inputs and each criterion's evidence, and the criteria as the
/// call's `state.criteria`, the triple every rung maps (OF-506).
pub(super) fn done_question_inputs(
    task_ref: EntityId,
    result_ref: EntityId,
    brief: &StoredBrief,
) -> (Vec<EntityId>, serde_json::Value) {
    let success = &brief.brief.success;
    let mut evidence = vec![task_ref, result_ref];
    evidence.extend(brief.brief.settled.iter().copied());
    evidence.extend(success.criteria_evidence());
    let state = serde_json::json!({
        "objective": brief.brief.objective,
        "question": success.question,
        "criteria": success.question_criteria(),
        "result_ref": result_ref.to_hex(),
    });
    (evidence, state)
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
        let journal = match report.body {
            TaskReportBody::Ack | TaskReportBody::Brief(_) | TaskReportBody::Edit { .. } => None,
            _ => report_journal::identity(self.actor(), via, &report, &key)?,
        };
        match report.body {
            TaskReportBody::Ack => self.report_ack(via, task_ref, &key, now),
            TaskReportBody::Brief(next) => self.report_brief(via, task_ref, &key, *next, now),
            TaskReportBody::Edit {
                expected_revision,
                title,
            } => self.report_edit(via, task_ref, &key, expected_revision, title, now),
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
                let receipt_id = self.report_receipt_id(task_ref, &key, now)?;
                self.report_work(
                    &mut ReportTxn::own().journaled(journal).receipted(receipt_id),
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
        judged: Option<RunnerDoneAnswer>,
    ) -> MemoryResult<TaskCallReceipt> {
        self.report_in_runner_txn_noting(wtxn, via, report, judged, None)
    }

    /// [`Self::report_in_runner_txn`] with one more field, `note`, on its
    /// lifecycle receipt: a workflow run's settlement names there how its
    /// binder's right stood (FIX 5349).
    pub(super) fn report_in_runner_txn_noting(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        via: &TaskVia,
        report: TaskReport,
        judged: Option<RunnerDoneAnswer>,
        note: Option<(&str, &str)>,
    ) -> MemoryResult<TaskCallReceipt> {
        let key = qualified_key(via, &report.report_key, "report key")?;
        let task_ref = report.task_ref;
        let now = self.vault().now_recorded_at();
        if matches!(
            report.body,
            TaskReportBody::Ack | TaskReportBody::Brief(_) | TaskReportBody::Edit { .. }
        ) {
            return Err(MemoryError::bad_request(
                "an acknowledgement, brief revision or title edit is not a runner report",
            ));
        }
        let journal = report_journal::identity(self.actor(), via, &report, &key)?;
        let mut lifecycle = self.work_lifecycle(
            via,
            task_ref,
            &key,
            report.attempt.as_ref(),
            &report.body,
            now,
        );
        if let Some((field, value)) = note {
            lifecycle.fields.insert(field.to_owned(), value.to_owned());
        }
        let receipt_id = self.report_receipt_id(task_ref, &key, now)?;
        self.report_work(
            &mut ReportTxn::runner(wtxn, judged)
                .journaled(journal)
                .receipted(receipt_id),
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
}
