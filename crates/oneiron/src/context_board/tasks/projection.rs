//! Typed TASKS state: board status, intent and job presence, the ladder projection, and the overflow footer.

use super::authority_state::TaskRenderState;
use super::render::{bare_job_row, intent_row};
use crate::consult_ladder::LadderTerminalDisposition;
use crate::outbound::ConnectorSendTask;
use crate::run_tree::{RunTreeNode, RunTreeStatus};
use crate::task_verb::{ConsultResultPresence, TaskKind, TaskTerminalDisposition};
use crate::{EntityId, Result, Vault};

/// Maximum concrete TASKS rows rendered before the additive overflow footer.
///
/// ARCH-0067 §3 sheds TASKS "to counts" under the board cap, so the section
/// needs a row bound of its own. This one bounds TOKENS; `task_verb`'s
/// `TASK_PRESENCE_SCAN_CAP` bounds WORK. Collapsing the two would let a
/// malformed or filtered prefix starve the visible board unpredictably.
///
/// Re-exported crate-wide as [`TasksSection::RENDER_ROW_CAP`].
pub(super) const TASKS_RENDER_ROW_CAP: usize = 100;

const _: () = assert!(TASKS_RENDER_ROW_CAP > 0);

/// TASKS board status axis (08b §3): running / scheduled / queued / done /
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskBoardStatus {
    Running,
    Scheduled,
    Queued,
    Done,
    Failed,
}

impl TaskBoardStatus {
    /// Stable structural token for the status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Scheduled => "scheduled",
            Self::Queued => "queued",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

/// ONE-1896 §1: a running realization keeps REFUSING to stop.
///
/// The soft rung is a request, so refusing it is legitimate — once. Repeated
/// refusal is the one cancel outcome no automated rung can resolve: nothing
/// below the owner's hard rung can stop a worker that will not land, so the
/// evidence has to reach the owner's own surface rather than a tracing span.
/// Typed, not prose: the count, the threshold it crossed, and the worker's own
/// last status are what an owner needs to decide between waiting and forcing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRejectionPathology {
    /// The realizing ATTEMPT that is refusing, so the owner can address it.
    pub attempt_id: String,
    /// Soft requests this attempt has refused.
    pub rejections: u32,
    /// The count at which refusal became a pathology signal
    /// ([`crate::attempt_queue::SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`]).
    pub threshold: u32,
    /// The worker's own last refusal status/reason line, one-line bounded.
    pub last_status: Option<String>,
}

impl CancelRejectionPathology {
    /// The board token: bounded, structural, and never the worker's prose.
    #[must_use]
    pub fn token(&self) -> String {
        format!("cancel-refused={}/{}", self.rejections, self.threshold)
    }
}

/// One collapsed TASKS row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    pub id: String,
    pub line: String,
    pub status: TaskBoardStatus,
    pub is_intent: bool,
    pub folded_job_count: usize,
    /// `None` is the landed standard-task default.
    pub kind: Option<TaskKind>,
    pub assignee: Option<String>,
    pub terminal_disposition: Option<TaskTerminalDisposition>,
    pub result_ref: Option<String>,
    /// ONE-1888 ladder outcome, when the row carries one. It NARROWS the
    /// ONE-1699 axis (approved vs overridden on `done`, rejected-with-counter
    /// on the failed lane) rather than replacing it.
    pub ladder_disposition: Option<LadderTerminalDisposition>,
    /// The counter TASK that replaced this one.
    pub counter_task_ref: Option<String>,
    /// ONE-1896: the realizing job that keeps refusing to stop, when one does.
    /// `None` is the ordinary case and leaves every existing row byte-identical.
    pub cancel_pathology: Option<CancelRejectionPathology>,
}

impl TaskRow {
    /// Collapses one intent into its row. Delegation columns ride along from
    /// the presence, so a caller never restates them.
    #[must_use]
    pub fn from_intent(intent: &TaskIntentPresence, line: String) -> Self {
        Self {
            id: intent.id.clone(),
            line,
            status: intent.status,
            is_intent: true,
            folded_job_count: intent.realizing_jobs.len(),
            kind: intent.kind,
            assignee: intent.assignee.clone(),
            terminal_disposition: intent.terminal_disposition,
            result_ref: intent.result_ref.clone(),
            ladder_disposition: intent.ladder_disposition,
            counter_task_ref: intent.counter_task_ref.clone(),
            cancel_pathology: intent_cancel_pathology(intent),
        }
    }
}

/// The refusal an owner must answer for, folded up from the intent's realizing
/// jobs: the WORST one, because the decision the signal exists for (wait, or
/// force) is made about the most stuck job, and a bounded row cannot carry N.
pub(super) fn intent_cancel_pathology(
    intent: &TaskIntentPresence,
) -> Option<CancelRejectionPathology> {
    intent
        .realizing_jobs
        .iter()
        .filter_map(|job| job.cancel_pathology.as_ref())
        .max_by_key(|pathology| pathology.rejections)
        .cloned()
}

/// The pinned board lane and cause tokens for one ladder outcome.
///
/// Crate-internal on purpose: consumers read the rendered row and
/// `TaskRow::ladder_disposition`, so the table has exactly one caller and the
/// shared `context_board` re-export chokepoint stays untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LadderBoardProjection {
    pub(crate) status: TaskBoardStatus,
    pub(crate) tokens: Vec<&'static str>,
}

/// Projects one ladder outcome onto the board's FIVE-value axis plus cause
/// tokens (ONE-1888).
///
/// The axis is unchanged and deliberately distinct from the A2A base states.
/// `Rejected` and `Failed` both land in the failed lane but keep distinct
/// cause tokens; `Countered` reads as the rejection it is; `Escalated` is not
/// terminal at all, so it stays on the queued lane and says so.
#[must_use]
pub(super) fn ladder_board_projection(
    disposition: LadderTerminalDisposition,
) -> LadderBoardProjection {
    let (status, tokens) = match disposition {
        LadderTerminalDisposition::Approved => (TaskBoardStatus::Done, vec!["approved"]),
        LadderTerminalDisposition::Overridden => (TaskBoardStatus::Done, vec!["overridden"]),
        LadderTerminalDisposition::Rejected => (TaskBoardStatus::Failed, vec!["rejected"]),
        LadderTerminalDisposition::Failed => (TaskBoardStatus::Failed, vec!["failed"]),
        LadderTerminalDisposition::Abandoned => (TaskBoardStatus::Failed, vec!["abandoned"]),
        // The OLD side of a counter: an immutable rejected row that names its
        // successor. The NEW counter TASK renders independently.
        LadderTerminalDisposition::Countered => {
            (TaskBoardStatus::Failed, vec!["rejected", "countered"])
        }
        // Non-terminal: the case is with its follow-on assignee.
        LadderTerminalDisposition::Escalated => {
            (TaskBoardStatus::Queued, vec!["interrupted", "escalated"])
        }
    };
    LadderBoardProjection { status, tokens }
}

/// The structural TASKS footer: what the board did NOT show.
///
/// Deliberately not a [`TaskRow`] — it carries no task id, status, intent
/// flag, or folded-job count, so nothing downstream can mistake the footer for
/// work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TasksOverflow {
    /// Concrete rows already projected but omitted by the render row cap.
    pub known_omitted_rows: usize,
    /// True only when the TASK type-index source was fully exhausted, i.e.
    /// `known_omitted_rows` is an exact census rather than a lower bound.
    pub source_exhausted: bool,
}

impl TasksOverflow {
    /// The ARCH-0067 §8 additive footer line — "overflow counts stay additive
    /// and take the keyed form" — or `None` when the board showed everything
    /// there is.
    #[must_use]
    pub fn line(self) -> Option<String> {
        match (self.known_omitted_rows, self.source_exhausted) {
            (0, true) => None,
            (omitted, true) => Some(format!("tasks: +{omitted} more")),
            // A capped scan never learned how many rows it skipped, so it
            // states the fact rather than a false exact `+0`.
            (0, false) => Some("tasks: more rows may exist (scan capped)".to_owned()),
            (omitted, false) => Some(format!("tasks: +{omitted} more (at least; scan capped)")),
        }
    }
}

/// Collapsed TASKS section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TasksSection {
    pub rows: Vec<TaskRow>,
    /// Structural footer; never represented as a [`TaskRow`].
    pub overflow: Option<TasksOverflow>,
}

impl TasksSection {
    /// `TASKS_RENDER_ROW_CAP`, reachable outside this module.
    ///
    /// `context_board`'s re-export list is a shared chokepoint this ticket does
    /// not claim, and `mod tasks` is private — an associated const travels with
    /// the already re-exported type, so `task_verb` can pin its own scan cap
    /// against this one at compile time.
    pub const RENDER_ROW_CAP: usize = TASKS_RENDER_ROW_CAP;

    /// Renders presence into collapsed rows under the render cap, carrying the
    /// bounded scan's honesty bit into the footer.
    ///
    /// `source_exhausted` is `false` when the caller's TASK scan stopped at its
    /// own cap: the omitted-row count is then a lower bound, never a census.
    #[must_use]
    pub fn render_bounded(
        intents: &[TaskIntentPresence],
        bare_jobs: &[JobPresence],
        source_exhausted: bool,
    ) -> Self {
        Self::render_with_cap(intents, bare_jobs, source_exhausted, Self::RENDER_ROW_CAP)
    }

    /// Testable body: production uses [`Self::RENDER_ROW_CAP`]; tests inject a
    /// small cap so overflow behaviour is exercised without a 100-row fixture.
    pub(crate) fn render_with_cap(
        intents: &[TaskIntentPresence],
        bare_jobs: &[JobPresence],
        source_exhausted: bool,
        row_cap: usize,
    ) -> Self {
        let mut rows = Vec::with_capacity(intents.len() + bare_jobs.len());
        rows.extend(
            intents
                .iter()
                .filter(|intent| !intent.is_acked_failure())
                .map(intent_row),
        );
        rows.extend(bare_jobs.iter().map(bare_job_row));
        // The cap applies AFTER filtering and ordering, so the count names rows
        // that really would have rendered.
        let known_omitted_rows = rows.len().saturating_sub(row_cap);
        rows.truncate(row_cap);
        let overflow = (known_omitted_rows > 0 || !source_exhausted).then_some(TasksOverflow {
            known_omitted_rows,
            source_exhausted,
        });
        Self { rows, overflow }
    }
}

/// One non-agent-dispatch JobQueue job projected for the board — a bare
/// system job row, or a realizing job folded under its owning intent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobPresence {
    pub id: String,
    pub kind: String,
    pub status: TaskBoardStatus,
    /// ONE-1896: set only when this job has crossed the repeated-refusal
    /// threshold. Additive and `None` for every ordinary job.
    pub cancel_pathology: Option<CancelRejectionPathology>,
}

impl JobPresence {
    /// Projects one SURF-005 observed run-tree node onto the board axis.
    /// Row identity and normalized worker kind come from the observe surface.
    /// Returns `None` for agent-dispatch attempts, which belong to AGENTS.
    /// Returns `None` for cancelled rows: the axis has no token for withdrawn
    /// work, so it leaves the board.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<JobPresence> {
        if node.worker_kind == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }

        Some(JobPresence {
            id: node.attempt_id.clone(),
            kind: node.worker_kind.clone(),
            status: run_tree_board_status(node.status)?,
            cancel_pathology: None,
        })
    }

    /// Attaches the owner-visible refusal signal read off the durable ATTEMPT
    /// row. Separate from [`Self::from_run_tree_node`] because the run tree
    /// carries lifecycle, not the cancel protocol's evidence.
    #[must_use]
    pub fn with_cancel_pathology(mut self, pathology: Option<CancelRejectionPathology>) -> Self {
        self.cancel_pathology = pathology;
        self
    }
}

/// Folds a task's realizing-job statuses into the owning task's board status
/// (ONE-1695 · 08b §3). Precedence is the L0-ruled working-document order:
/// Running > Failed > Scheduled > Queued > Done. Returns `None` for no jobs.
#[must_use]
pub fn fold_up_status(jobs: &[JobPresence]) -> Option<TaskBoardStatus> {
    jobs.iter()
        .map(|job| job.status)
        .max_by_key(|status| task_status_precedence_rank(*status))
}

pub(super) const fn task_status_precedence_rank(status: TaskBoardStatus) -> u8 {
    match status {
        TaskBoardStatus::Running => 5,
        TaskBoardStatus::Failed => 4,
        TaskBoardStatus::Scheduled => 3,
        TaskBoardStatus::Queued => 2,
        TaskBoardStatus::Done => 1,
    }
}

/// Maps the SURF-005 lifecycle onto the board status axis. `Paused` reads as
/// scheduled (deferred, not eligible to run now); `Cancelled` has no axis
/// token and leaves the board.
pub(super) const fn run_tree_board_status(status: RunTreeStatus) -> Option<TaskBoardStatus> {
    match status {
        RunTreeStatus::Queued => Some(TaskBoardStatus::Queued),
        RunTreeStatus::Running => Some(TaskBoardStatus::Running),
        RunTreeStatus::Paused => Some(TaskBoardStatus::Scheduled),
        RunTreeStatus::Completed => Some(TaskBoardStatus::Done),
        RunTreeStatus::Failed => Some(TaskBoardStatus::Failed),
        RunTreeStatus::Cancelled => None,
        // Leaves the board on the `Cancelled` precedent. The axis holds live
        // work, and no executor will ever advance an abandoned row again;
        // rendering it `Failed` would assert a fault nobody observed, and a
        // re-dispatch mints a fresh row that re-enters as queued work.
        RunTreeStatus::Abandoned => None,
    }
}

/// One intent TASK entity projected for the board (08b §3 two-layer /
/// one-surface: the intent row carries its realizing JobQueue jobs folded
/// under it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskIntentPresence {
    pub id: String,
    pub status: TaskBoardStatus,
    pub label: Option<String>,
    pub acked: bool,
    pub realizing_jobs: Vec<JobPresence>,
    /// Additive delegation projection (ONE-1699). `None` throughout is the
    /// landed standard-task default.
    pub kind: Option<TaskKind>,
    /// Resolved DISPLAY handle for the assignee; storage stays actor-addressed.
    pub assignee: Option<String>,
    pub terminal_disposition: Option<TaskTerminalDisposition>,
    pub result_ref: Option<String>,
    pub consult_result: Option<ConsultResultPresence>,
    /// ONE-1888 ladder projection. `None` throughout is the ONE-1699 default.
    pub ladder_disposition: Option<LadderTerminalDisposition>,
    /// The persisted TASK state is `Interrupted`: progress is durably paused.
    pub interrupted: bool,
    pub counter_task_ref: Option<String>,
}

impl TaskIntentPresence {
    /// The pre-delegation construction surface, unchanged. Additive projection
    /// fields start absent and are set by the projector that knows them.
    #[must_use]
    pub fn new(
        id: String,
        status: TaskBoardStatus,
        label: Option<String>,
        acked: bool,
        realizing_jobs: Vec<JobPresence>,
    ) -> Self {
        Self {
            id,
            status,
            label,
            acked,
            realizing_jobs,
            kind: None,
            assignee: None,
            terminal_disposition: None,
            result_ref: None,
            consult_result: None,
            ladder_disposition: None,
            interrupted: false,
            counter_task_ref: None,
        }
    }

    /// Projects the connector-send TASK read (the one realized TASK subkind
    /// today). Board status arrives from the observe projection — the
    /// job→task fold-up derivation is ONE-1695 — and `acked` starts false
    /// because ack state is only written by the ONE-1696 verb surface.
    #[must_use]
    pub fn from_connector_send_task(
        task: &ConnectorSendTask,
        status: TaskBoardStatus,
        realizing_jobs: Vec<JobPresence>,
    ) -> TaskIntentPresence {
        Self::from_connector_send_task_with_ack(task, status, realizing_jobs, false)
    }

    /// Projects a connector-send TASK with the persisted render-tier ack bit.
    #[must_use]
    pub(crate) fn from_connector_send_task_with_ack(
        task: &ConnectorSendTask,
        status: TaskBoardStatus,
        realizing_jobs: Vec<JobPresence>,
        acked: bool,
    ) -> TaskIntentPresence {
        Self::new(
            task.task_ref.to_hex(),
            status,
            Some(task.intent.verb.clone()),
            acked,
            realizing_jobs,
        )
    }

    /// Failed rows stay surfaced until acked (08b §3); an acked failure has
    /// left the board surface.
    #[must_use]
    pub fn is_acked_failure(&self) -> bool {
        self.status == TaskBoardStatus::Failed && self.acked
    }

    /// Reads both render-tier state bits for one TASK through a caller-owned
    /// read transaction, so assembling one board page costs ONE render-state
    /// transaction instead of two per TASK.
    ///
    /// Both bits come from the TASK's own replicated authority facts, so a
    /// cancellation or acknowledgement made on one device renders the same way
    /// on every other one — no node-local `vault_meta` bit decides what a peer
    /// sees. Cancellation is read INDEPENDENTLY of the owner proof: a cancel
    /// that really happened hides the row whether or not the task also carries
    /// an Owner fact.
    ///
    /// The FOLD stays STRICT and the board CALL SITES degrade. A companion
    /// fact set that will not read — an owner fork, a malformed fact body, a
    /// fact re-pointed at a subject it does not name — returns `Err` here, and
    /// `Vault::task_authority_state` keeps failing closed on it so the cancel /
    /// force-cancel doors refuse that task. The board never asks who the owner
    /// is, so its readers map that same `Err` to a per-row outcome instead:
    /// `task_verb::presence_scan` skips the poisoned row inside the page loop
    /// (P2 F8 — one bad row must never abort `tasks.check`, and these rows
    /// replicate), and the by-id door answers `Ok(None)`. The degrade is a
    /// SKIP, never a render with false bits, because a row whose facts cannot
    /// be read may really be cancelled.
    ///
    /// Hung off the presence type rather than standing as a free function
    /// because `context_board`'s re-export list is a shared chokepoint this
    /// ticket does not claim; an associated item travels with the type that is
    /// already re-exported.
    pub(crate) fn render_state_in(
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<TaskRenderState> {
        let facts = vault.task_authority_facts_in(rtxn, task_ref)?;
        Ok(TaskRenderState {
            acked: facts.acked,
            cancelled: facts.cancelled,
        })
    }
}
