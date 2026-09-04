//! TASKS section projections — intent rows, realizing jobs, and the
//! render-tier ack/cancel state helpers behind the `tasks.*` verb surface.
//!
//! Ack and cancel state is READ from, and WRITTEN as, the TASK's replicated
//! authority facts (`task_authority`). The UI tier never parses a fact body or
//! walks an edge: it reads these two bits and the stable
//! `TaskIntentPresence.acked` lens, exactly as it did when they were
//! node-local `vault_meta` rows.

use super::one_line_token;
use crate::consult_ladder::LadderTerminalDisposition;
use crate::outbound::ConnectorSendTask;
use crate::run_tree::{RunTreeNode, RunTreeStatus};
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
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
const TASKS_RENDER_ROW_CAP: usize = 100;

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
fn intent_cancel_pathology(intent: &TaskIntentPresence) -> Option<CancelRejectionPathology> {
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
pub(crate) struct LadderBoardProjection {
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
pub(crate) fn ladder_board_projection(
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

const fn task_status_precedence_rank(status: TaskBoardStatus) -> u8 {
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
const fn run_tree_board_status(status: RunTreeStatus) -> Option<TaskBoardStatus> {
    match status {
        RunTreeStatus::Queued => Some(TaskBoardStatus::Queued),
        RunTreeStatus::Running => Some(TaskBoardStatus::Running),
        RunTreeStatus::Paused => Some(TaskBoardStatus::Scheduled),
        RunTreeStatus::Completed => Some(TaskBoardStatus::Done),
        RunTreeStatus::Failed => Some(TaskBoardStatus::Failed),
        RunTreeStatus::Cancelled => None,
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
fn task_render_state(vault: &Vault, task_ref: EntityId) -> Result<TaskRenderState> {
    let rtxn = vault.store.env.read_txn()?;
    TaskIntentPresence::render_state_in(vault, &rtxn, task_ref)
}

/// Renders provided task presence into stable, collapsed rows — intent rows
/// first with realizing jobs folded under them, then bare system jobs as-is.
/// Acked failures have left the surface.
///
/// Compatibility door for callers that already hold a COMPLETE in-memory set;
/// a caller whose TASK scan was bounded must use
/// [`TasksSection::render_bounded`] so the footer can stay honest.
#[must_use]
pub fn render_tasks_section(
    intents: &[TaskIntentPresence],
    bare_jobs: &[JobPresence],
) -> TasksSection {
    TasksSection::render_bounded(intents, bare_jobs, true)
}

/// The failed lane of a rendered TASKS section. Acked failures were already
/// dropped at render time, so the lane is every surfaced failed row.
#[must_use]
pub fn failed_lane(section: &TasksSection) -> Vec<&TaskRow> {
    section
        .rows
        .iter()
        .filter(|row| row.status == TaskBoardStatus::Failed)
        .collect()
}

/// Unfolds one intent's realizing jobs under its row — the engine seam
/// behind `board.expand tasks.<id>`; the verb dispatch surface is ONE-1696.
/// Line order: the collapsed intent row first, then its realizing jobs in
/// presence order, indented one level.
#[must_use]
pub fn expand_task(intent: &TaskIntentPresence) -> Vec<String> {
    let mut lines = Vec::with_capacity(2 + intent.realizing_jobs.len());
    lines.push(intent_row(intent).line);
    lines.extend(
        intent
            .realizing_jobs
            .iter()
            .map(|job| format!("  {}", bare_job_row(job).line)),
    );
    if let Some(detail) = delegation_detail_line(intent) {
        lines.push(format!("  {detail}"));
    }
    lines
}

/// Typed refs only: an expanded consult says WHERE the result lives and what
/// SHAPE it has, never what it says.
fn delegation_detail_line(intent: &TaskIntentPresence) -> Option<String> {
    let mut tokens = Vec::new();
    if let Some(result_ref) = intent.result_ref.as_deref() {
        tokens.push(format!("result={}", single_token(result_ref)));
    }
    // The counter's own row renders independently; this only says WHERE the
    // successor is, so a reader never mistakes the immutable old row for it.
    if let Some(counter_task_ref) = intent.counter_task_ref.as_deref() {
        tokens.push(format!("counter={}", single_token(counter_task_ref)));
    }
    match &intent.consult_result {
        Some(ConsultResultPresence::Answer {
            evidence_ref_count, ..
        }) => {
            tokens.push("answer".to_owned());
            tokens.push(format!("evidence={evidence_ref_count}"));
        }
        Some(ConsultResultPresence::Abstained { reason_ref, .. }) => {
            tokens.push("abstained".to_owned());
            tokens.push(format!("reason={}", single_token(reason_ref)));
        }
        None => {}
    }
    (!tokens.is_empty()).then(|| tokens.join(" "))
}

/// One structural token. `one_line_token` already keeps a value on one physical
/// line; collapsing the remaining whitespace also stops a handle or ref from
/// splitting into a second token that would read as board structure.
fn single_token(value: &str) -> String {
    one_line_token(value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
}

fn intent_row(intent: &TaskIntentPresence) -> TaskRow {
    let folded_job_count = intent.realizing_jobs.len();
    let mut tokens = vec![one_line_token(&intent.id)];
    if let Some(label) = intent.label.as_deref() {
        tokens.push(one_line_token(label));
    }
    if let Some(assignee) = intent.assignee.as_deref() {
        tokens.push(format!("assignee={}", single_token(assignee)));
    }
    tokens.push(intent.status.as_str().to_owned());
    tokens.extend(cause_tokens(intent));
    if folded_job_count > 0 {
        tokens.push(format!("jobs={folded_job_count}"));
    }
    // ONE-1896: the refusal signal rides BESIDE the status, exactly like a
    // cause token — the row still says `running`, because the worker IS
    // running; what the owner learns is that it will not stop when asked.
    if let Some(pathology) = intent_cancel_pathology(intent) {
        tokens.push(pathology.token());
    }
    TaskRow::from_intent(intent, tokens.join(" "))
}

/// The cause tokens that ride BESIDE the status token, never inside it, and
/// only where they NARROW the axis.
///
/// A ladder outcome supersedes the raw ONE-1699 disposition here: it is the
/// finer vocabulary over the same terminal, so rendering both would duplicate
/// the cause. A token identical to the status is dropped for the same reason.
fn cause_tokens(intent: &TaskIntentPresence) -> Vec<String> {
    if let Some(disposition) = intent.ladder_disposition {
        return ladder_board_projection(disposition)
            .tokens
            .into_iter()
            .filter(|token| *token != intent.status.as_str())
            .map(str::to_owned)
            .collect();
    }
    // A durably interrupted row is not terminal, so it has no disposition to
    // narrow with — the pause itself is the cause worth surfacing.
    if intent.interrupted {
        return vec!["interrupted".to_owned()];
    }
    // The failed lane folds rejected/failed/expired/abandoned/cancelled and
    // must stay distinguishable, while `done` has a single cause and
    // `running`/`queued`/`scheduled` are not terminal at all.
    match intent.terminal_disposition {
        Some(disposition)
            if intent.status == TaskBoardStatus::Failed
                && disposition.as_str() != intent.status.as_str() =>
        {
            vec![disposition.as_str().to_owned()]
        }
        _ => Vec::new(),
    }
}

fn bare_job_row(job: &JobPresence) -> TaskRow {
    let mut line = format!(
        "{} {} {}",
        one_line_token(&job.id),
        one_line_token(&job.kind),
        job.status.as_str()
    );
    if let Some(pathology) = job.cancel_pathology.as_ref() {
        line.push(' ');
        line.push_str(&pathology.token());
    }
    TaskRow {
        id: job.id.clone(),
        line,
        status: job.status,
        is_intent: false,
        folded_job_count: 0,
        kind: None,
        assignee: None,
        terminal_disposition: None,
        result_ref: None,
        ladder_disposition: None,
        counter_task_ref: None,
        cancel_pathology: job.cancel_pathology.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::run_tree_node_with_worker_kind;
    use super::*;
    use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
    use crate::edge::EdgeActorClass;
    use crate::entity_id::EntityId;
    use crate::outbound::OutboundIntent;

    fn intent(id: &str, status: TaskBoardStatus) -> TaskIntentPresence {
        TaskIntentPresence::new(id.to_owned(), status, None, false, Vec::new())
    }

    fn job(id: &str, status: TaskBoardStatus) -> JobPresence {
        JobPresence {
            id: id.to_owned(),
            kind: "sync".to_owned(),
            status,
            cancel_pathology: None,
        }
    }

    #[test]
    fn fold_up_status_uses_total_precedence() {
        let cases = [
            (
                [TaskBoardStatus::Done, TaskBoardStatus::Running],
                TaskBoardStatus::Running,
            ),
            (
                [TaskBoardStatus::Done, TaskBoardStatus::Done],
                TaskBoardStatus::Done,
            ),
            (
                [TaskBoardStatus::Done, TaskBoardStatus::Failed],
                TaskBoardStatus::Failed,
            ),
            (
                [TaskBoardStatus::Running, TaskBoardStatus::Failed],
                TaskBoardStatus::Running,
            ),
            (
                [TaskBoardStatus::Scheduled, TaskBoardStatus::Queued],
                TaskBoardStatus::Scheduled,
            ),
            (
                [TaskBoardStatus::Queued, TaskBoardStatus::Done],
                TaskBoardStatus::Queued,
            ),
        ];

        for (index, (statuses, expected)) in cases.into_iter().enumerate() {
            let jobs = [job("first", statuses[0]), job("second", statuses[1])];
            assert_eq!(fold_up_status(&jobs), Some(expected), "case {index}");
        }
    }

    #[test]
    fn fold_up_status_handles_empty_and_single_job() {
        assert_eq!(fold_up_status(&[]), None);
        for status in [
            TaskBoardStatus::Running,
            TaskBoardStatus::Failed,
            TaskBoardStatus::Scheduled,
            TaskBoardStatus::Queued,
            TaskBoardStatus::Done,
        ] {
            assert_eq!(fold_up_status(&[job("only", status)]), Some(status));
        }
    }

    fn connector_send_task() -> ConnectorSendTask {
        ConnectorSendTask {
            task_ref: EntityId::from_bytes([0x51; 16]).expect("task ref from 16 bytes"),
            assignee_ref: EntityId::from_bytes([0x52; 16]).expect("assignee ref from 16 bytes"),
            actor_ref: EntityId::from_bytes([0x53; 16]).expect("actor ref from 16 bytes"),
            actor_class: EdgeActorClass::Agent,
            intent: OutboundIntent {
                actor: "actor_a".to_owned(),
                on_behalf_of: None,
                verb: "send".to_owned(),
                channel: "channel_a".to_owned(),
                target: "target_a".to_owned(),
                content_ref: None,
                idempotency_key: None,
                dedupe_key: None,
                intent_source: "commitment".to_owned(),
                trigger_ref: "tr_1".to_owned(),
                job_ref: None,
            },
            originating_session_ref: None,
            attempt_started_node_id: None,
            outcome: None,
            // ONE-1768 hydrated clock authority. This board fixture is a
            // hostless send: absent everywhere, which is exactly what a
            // pre-change TASK body decodes to.
            utc_offset_minutes: None,
            iana_timezone: None,
            human_explicit_instant: false,
            apns_interruption_level: None,
            resolved_level: None,
            // Not a calendar invite, so no CAL-04 frozen body rides this TASK.
            calendar_invite: None,
            occurred_at: 1,
        }
    }

    #[test]
    fn renders_tasks_section_as_one_line_rows_over_intents_and_bare_jobs() {
        let mut tk_a = intent("tk_a", TaskBoardStatus::Running);
        tk_a.realizing_jobs = vec![
            job("jb_1", TaskBoardStatus::Running),
            job("jb_2", TaskBoardStatus::Queued),
        ];
        let intents = [
            tk_a,
            intent("tk_b", TaskBoardStatus::Scheduled),
            intent("tk_q", TaskBoardStatus::Queued),
            intent("tk_d", TaskBoardStatus::Done),
        ];
        let bare_jobs = [job("jb_c", TaskBoardStatus::Running)];

        let section = render_tasks_section(&intents, &bare_jobs);

        assert_eq!(section.rows.len(), 5);
        let one_line_rows = section
            .rows
            .iter()
            .filter(|row| !row.line.is_empty() && row.line.lines().count() == 1)
            .count();
        assert_eq!(one_line_rows, 5);
        assert_eq!(section.rows.iter().filter(|row| row.is_intent).count(), 4);
        for (id, status, line) in [
            ("tk_b", TaskBoardStatus::Scheduled, "tk_b scheduled"),
            ("tk_q", TaskBoardStatus::Queued, "tk_q queued"),
            ("tk_d", TaskBoardStatus::Done, "tk_d done"),
        ] {
            let row = section
                .rows
                .iter()
                .find(|row| row.id == id)
                .unwrap_or_else(|| panic!("{id} row must be rendered"));
            assert_eq!(row.status, status);
            assert!(row.is_intent);
            assert_eq!(row.folded_job_count, 0);
            assert_eq!(row.line, line);
        }
        let tk_a_row = section
            .rows
            .iter()
            .find(|row| row.id == "tk_a")
            .expect("tk_a row must be rendered");
        assert_eq!(tk_a_row.status, TaskBoardStatus::Running);
        assert!(tk_a_row.is_intent);
        assert_eq!(tk_a_row.folded_job_count, 2);
        assert_eq!(tk_a_row.line, "tk_a running jobs=2");
        let jb_c_row = section
            .rows
            .iter()
            .find(|row| row.id == "jb_c")
            .expect("jb_c row must be rendered");
        assert_eq!(jb_c_row.status, TaskBoardStatus::Running);
        assert!(!jb_c_row.is_intent);
        assert_eq!(jb_c_row.folded_job_count, 0);
        assert_eq!(jb_c_row.line, "jb_c sync running");
    }

    #[test]
    fn bridges_discriminate_bare_jobs_from_intent_rows() {
        let bare_node = run_tree_node_with_worker_kind(
            "11111111111111111111111111111111",
            None,
            RunTreeStatus::Running,
            "sync",
        );
        let bare = JobPresence::from_run_tree_node(&bare_node)
            .expect("running observed job must reach the board");
        assert_eq!(bare.id, "11111111111111111111111111111111");
        assert_eq!(bare.kind, "sync");
        assert_eq!(bare.status, TaskBoardStatus::Running);
        let cancelled_node = run_tree_node_with_worker_kind(
            "31313131313131313131313131313131",
            None,
            RunTreeStatus::Cancelled,
            "sync",
        );
        assert_eq!(JobPresence::from_run_tree_node(&cancelled_node), None);

        let completed_node = run_tree_node_with_worker_kind(
            "21212121212121212121212121212121",
            None,
            RunTreeStatus::Completed,
            "sync",
        );
        let running_node = run_tree_node_with_worker_kind(
            "22222222222222222222222222222222",
            None,
            RunTreeStatus::Running,
            "sync",
        );
        let realizing_jobs = vec![
            JobPresence::from_run_tree_node(&completed_node)
                .expect("completed observed job must reach the board"),
            JobPresence::from_run_tree_node(&running_node)
                .expect("running observed job must reach the board"),
        ];
        let connector_task = connector_send_task();
        let intent_read = TaskIntentPresence::from_connector_send_task(
            &connector_task,
            TaskBoardStatus::Running,
            realizing_jobs,
        );
        assert_eq!(intent_read.id, connector_task.task_ref.to_hex());
        assert_eq!(
            intent_read.label.as_deref(),
            Some(connector_task.intent.verb.as_str())
        );
        assert!(!intent_read.acked);
        assert_eq!(intent_read.realizing_jobs.len(), 2);

        let section = render_tasks_section(&[intent_read], &[bare]);

        assert_eq!(section.rows.len(), 2);
        assert_eq!(section.rows.iter().filter(|row| row.is_intent).count(), 1);
        assert!(section.rows[0].is_intent);
        assert_eq!(section.rows[0].folded_job_count, 2);
        assert!(!section.rows[1].is_intent);
        assert_eq!(section.rows[1].folded_job_count, 0);
        assert_eq!(section.rows[1].status, TaskBoardStatus::Running);
        assert_eq!(section.rows[1].line.matches("sync").count(), 1);
        assert_eq!(section.rows[1].line.matches("running").count(), 1);
    }

    #[test]
    fn agent_dispatch_attempt_never_projects_into_tasks_jobs() {
        let node = run_tree_node_with_worker_kind(
            "agent_attempt",
            Some("researcher"),
            RunTreeStatus::Running,
            AGENT_DISPATCH_ATTEMPT_TYPE,
        );

        assert_eq!(JobPresence::from_run_tree_node(&node), None);
        let projected_jobs: Vec<JobPresence> = [node]
            .iter()
            .filter_map(JobPresence::from_run_tree_node)
            .collect();
        assert_eq!(projected_jobs.len(), 0);

        let section = render_tasks_section(&[], &projected_jobs);
        assert_eq!(section.rows.len(), 0);
    }

    #[test]
    fn bare_job_bridge_renders_observed_dreamer_worker_kind() {
        let observed_node = run_tree_node_with_worker_kind(
            "jb_dreamer",
            None,
            RunTreeStatus::Running,
            "dreamer.consolidate",
        );

        let bare = JobPresence::from_run_tree_node(&observed_node)
            .expect("running observed dreamer job must reach the board");
        assert_eq!(bare.kind, "dreamer.consolidate");

        let section = render_tasks_section(&[], &[bare]);

        assert_eq!(section.rows.len(), 1);
        assert_eq!(
            section.rows[0].line,
            "jb_dreamer dreamer.consolidate running"
        );
        let raw_runner_tokens = section.rows[0]
            .line
            .split_whitespace()
            .filter(|token| *token == crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND)
            .count();
        assert_eq!(raw_runner_tokens, 0);
    }

    #[test]
    fn failed_lane_surfaces_only_unacked_failures() {
        let unacked = intent("tk_failed_unacked", TaskBoardStatus::Failed);
        let mut acked = intent("tk_failed_acked", TaskBoardStatus::Failed);
        acked.acked = true;
        let mut done_acked = intent("tk_done_acked", TaskBoardStatus::Done);
        done_acked.acked = true;

        let section =
            render_tasks_section(&[unacked.clone(), acked.clone(), done_acked.clone()], &[]);

        assert_eq!(section.rows.len(), 2);
        let lane = failed_lane(&section);
        assert_eq!(lane.len(), 1);
        assert_eq!(lane[0].id, "tk_failed_unacked");
        assert_eq!(lane[0].status, TaskBoardStatus::Failed);

        let mut now_acked = unacked;
        now_acked.acked = true;
        let mut now_unacked = acked;
        now_unacked.acked = false;

        let flipped = render_tasks_section(&[now_acked, now_unacked, done_acked], &[]);

        assert_eq!(flipped.rows.len(), 2);
        let flipped_lane = failed_lane(&flipped);
        assert_eq!(flipped_lane.len(), 1);
        assert_eq!(flipped_lane[0].id, "tk_failed_acked");
        assert_eq!(flipped_lane[0].status, TaskBoardStatus::Failed);
    }

    #[test]
    fn expand_unfolds_realizing_jobs_in_order() {
        let mut tk_a = intent("tk_a", TaskBoardStatus::Running);
        tk_a.realizing_jobs = vec![
            job("jb_1", TaskBoardStatus::Running),
            job("jb_2", TaskBoardStatus::Queued),
        ];

        let lines = expand_task(&tk_a);

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "tk_a running jobs=2");
        assert_eq!(lines[1], "  jb_1 sync running");
        assert_eq!(lines[2], "  jb_2 sync queued");
        let job_lines = lines.iter().filter(|line| line.contains("jb_")).count();
        assert_eq!(job_lines, 2);
        let one_line_rows = lines
            .iter()
            .filter(|line| line.lines().count() == 1)
            .count();
        assert_eq!(one_line_rows, 3);
    }

    /// A hostile peer handle cannot split a row or mint a token that reads as
    /// board structure. Control characters collapse and the remaining spacing
    /// is folded, so the handle stays exactly ONE token.
    #[test]
    fn hostile_handles_cannot_split_rows_or_mint_board_structure() {
        let mut hostile = intent("tk_hostile", TaskBoardStatus::Queued);
        hostile.label = Some("ship\u{7}it".to_owned());
        hostile.assignee = Some("cc\nsecond done jobs=9".to_owned());
        hostile.result_ref = Some("tn_dead\u{9}beef ghost".to_owned());
        hostile.consult_result = Some(ConsultResultPresence::Abstained {
            result_ref: "tn_1".to_owned(),
            reason_ref: "cl_a\nb running".to_owned(),
        });

        let section = render_tasks_section(&[hostile.clone()], &[]);
        let expanded = expand_task(&hostile);

        assert_eq!(section.rows.len(), 1);
        let row = &section.rows[0];
        assert_eq!(row.line.lines().count(), 1);
        // The status axis is not forgeable from a handle.
        assert_eq!(
            row.line
                .split_whitespace()
                .filter(|token| *token == "queued")
                .count(),
            1
        );
        assert_eq!(
            row.line
                .split_whitespace()
                .filter(|token| *token == "done" || *token == "jobs=9")
                .count(),
            0
        );
        assert_eq!(
            row.line
                .split_whitespace()
                .filter(|token| token.starts_with("assignee="))
                .count(),
            1
        );
        for line in &expanded {
            assert_eq!(line.lines().count(), 1);
        }
        assert_eq!(
            expanded
                .iter()
                .flat_map(|line| line.split_whitespace())
                .filter(|token| *token == "running" || *token == "ghost")
                .count(),
            0
        );
    }

    /// An expired consult reads `failed` on the axis and `expired` as its
    /// cause, and its expansion names WHERE the result lives without
    /// interpolating any result body.
    #[test]
    fn expired_consult_row_names_its_cause_and_result_ref() {
        let mut expired = intent("tk_consult", TaskBoardStatus::Failed);
        expired.kind = Some(TaskKind::Consult);
        expired.assignee = Some("cc-second".to_owned());
        expired.terminal_disposition = Some(TaskTerminalDisposition::Expired);
        expired.result_ref = Some("aa00".to_owned());
        let mut answered = intent("tk_answered", TaskBoardStatus::Done);
        answered.kind = Some(TaskKind::Consult);
        answered.assignee = Some("cc-second".to_owned());
        answered.terminal_disposition = Some(TaskTerminalDisposition::Completed);
        answered.result_ref = Some("bb11".to_owned());
        answered.consult_result = Some(ConsultResultPresence::Answer {
            result_ref: "bb11".to_owned(),
            evidence_ref_count: 2,
        });

        let section = render_tasks_section(&[expired.clone(), answered.clone()], &[]);
        let lane = failed_lane(&section);
        let expired_expand = expand_task(&expired);
        let answered_expand = expand_task(&answered);

        assert_eq!(lane.len(), 1);
        assert_eq!(lane[0].id, "tk_consult");
        assert_eq!(lane[0].kind, Some(TaskKind::Consult));
        assert_eq!(
            lane[0].terminal_disposition,
            Some(TaskTerminalDisposition::Expired)
        );
        assert_eq!(lane[0].result_ref.as_deref(), Some("aa00"));
        assert_eq!(lane[0].line, "tk_consult assignee=cc-second failed expired");
        // `done` has exactly one cause, so a `completed` token would narrow
        // nothing; the answer's shape lives in the expansion instead.
        let answered_row = section
            .rows
            .iter()
            .find(|row| row.id == "tk_answered")
            .expect("answered consult row");
        assert_eq!(answered_row.line, "tk_answered assignee=cc-second done");
        assert_eq!(expired_expand.len(), 2);
        assert_eq!(expired_expand[1], "  result=aa00");
        assert_eq!(answered_expand.len(), 2);
        assert_eq!(answered_expand[1], "  result=bb11 answer evidence=2");
    }

    /// The pinned ONE-1888 ladder table. The board axis stays ONE-1699's five
    /// values — deliberately distinct from the A2A base states — and the
    /// ladder outcome rides beside it as cause tokens.
    #[test]
    fn ladder_outcomes_project_onto_the_pinned_board_lanes_and_tokens() {
        let table = [
            (
                LadderTerminalDisposition::Approved,
                TaskBoardStatus::Done,
                vec!["approved"],
            ),
            (
                LadderTerminalDisposition::Overridden,
                TaskBoardStatus::Done,
                vec!["overridden"],
            ),
            (
                LadderTerminalDisposition::Rejected,
                TaskBoardStatus::Failed,
                vec!["rejected"],
            ),
            (
                LadderTerminalDisposition::Failed,
                TaskBoardStatus::Failed,
                vec!["failed"],
            ),
            (
                LadderTerminalDisposition::Escalated,
                TaskBoardStatus::Queued,
                vec!["interrupted", "escalated"],
            ),
            (
                LadderTerminalDisposition::Countered,
                TaskBoardStatus::Failed,
                vec!["rejected", "countered"],
            ),
            (
                LadderTerminalDisposition::Abandoned,
                TaskBoardStatus::Failed,
                vec!["abandoned"],
            ),
        ];

        for (disposition, status, tokens) in table {
            let projection = ladder_board_projection(disposition);
            assert_eq!(projection.status, status, "{}", disposition.as_str());
            assert_eq!(projection.tokens, tokens, "{}", disposition.as_str());
        }
        // A rejection never reads as the failed CAUSE, and vice versa.
        assert_ne!(
            ladder_board_projection(LadderTerminalDisposition::Rejected).tokens,
            ladder_board_projection(LadderTerminalDisposition::Failed).tokens
        );
    }

    /// The row renders the ladder cause beside the status, never inside it,
    /// and never duplicates a token the status already carries.
    #[test]
    fn ladder_rows_render_their_cause_without_duplicating_the_status() {
        let mut approved = intent("tk_approved", TaskBoardStatus::Done);
        approved.terminal_disposition = Some(TaskTerminalDisposition::Completed);
        approved.ladder_disposition = Some(LadderTerminalDisposition::Approved);
        let mut overridden = intent("tk_overridden", TaskBoardStatus::Done);
        overridden.terminal_disposition = Some(TaskTerminalDisposition::Completed);
        overridden.ladder_disposition = Some(LadderTerminalDisposition::Overridden);
        overridden.result_ref = Some("rc_1".to_owned());
        let mut ladder_failed = intent("tk_failed", TaskBoardStatus::Failed);
        ladder_failed.terminal_disposition = Some(TaskTerminalDisposition::Failed);
        ladder_failed.ladder_disposition = Some(LadderTerminalDisposition::Failed);
        let mut escalated = intent("tk_escalated", TaskBoardStatus::Queued);
        escalated.interrupted = true;

        let section = render_tasks_section(
            &[approved, overridden.clone(), ladder_failed, escalated],
            &[],
        );

        let line = |id: &str| {
            section
                .rows
                .iter()
                .find(|row| row.id == id)
                .unwrap_or_else(|| panic!("{id} renders"))
                .line
                .clone()
        };
        assert_eq!(line("tk_approved"), "tk_approved done approved");
        assert_eq!(line("tk_overridden"), "tk_overridden done overridden");
        // `failed` is already the status token, so the cause adds nothing.
        assert_eq!(line("tk_failed"), "tk_failed failed");
        // A durably interrupted row is not terminal; the pause is the cause.
        assert_eq!(line("tk_escalated"), "tk_escalated queued interrupted");
        // The override receipt is named in the expansion, never interpolated.
        assert_eq!(expand_task(&overridden)[1], "  result=rc_1");
    }

    /// A countered original renders as the immutable rejected row it is, and
    /// its expansion names the successor rather than pretending to be it.
    #[test]
    fn a_countered_row_reads_as_rejected_and_names_its_successor() {
        let mut countered = intent("tk_countered", TaskBoardStatus::Failed);
        countered.kind = Some(TaskKind::Consult);
        countered.terminal_disposition = Some(TaskTerminalDisposition::Rejected);
        countered.ladder_disposition = Some(LadderTerminalDisposition::Countered);
        countered.result_ref = Some("rc_2".to_owned());
        countered.counter_task_ref = Some("tk_new".to_owned());

        let section = render_tasks_section(&[countered.clone()], &[]);
        let lane = failed_lane(&section);
        let expanded = expand_task(&countered);

        assert_eq!(lane.len(), 1);
        assert_eq!(lane[0].line, "tk_countered failed rejected countered");
        assert_eq!(lane[0].counter_task_ref.as_deref(), Some("tk_new"));
        assert_eq!(expanded[1], "  result=rc_2 counter=tk_new");
        // Distinct causes stay distinct on the shared failed lane.
        assert!(
            !lane[0]
                .line
                .split_whitespace()
                .any(|token| token == "abandoned" || token == "expired")
        );
    }

    // ── ONE-1873: bounded render + shared render-state read ─────────────

    fn intents(count: usize) -> Vec<TaskIntentPresence> {
        (0..count)
            .map(|index| intent(&format!("tk_{index:03}"), TaskBoardStatus::Queued))
            .collect()
    }

    /// The pinned ARCH-0067 §8 additive grammar. An exact census and a
    /// scan-capped lower bound must never read the same.
    #[test]
    fn overflow_line_follows_the_additive_grammar() {
        let line = |known_omitted_rows, source_exhausted| {
            TasksOverflow {
                known_omitted_rows,
                source_exhausted,
            }
            .line()
        };

        assert_eq!(line(0, true), None);
        assert_eq!(line(4, true).as_deref(), Some("tasks: +4 more"));
        assert_eq!(
            line(0, false).as_deref(),
            Some("tasks: more rows may exist (scan capped)")
        );
        assert_eq!(
            line(4, false).as_deref(),
            Some("tasks: +4 more (at least; scan capped)")
        );
        // A lower bound is never presentable as the exact count.
        assert_ne!(line(4, false), line(4, true));
    }

    /// An exhausted scan knows exactly what it dropped, so the footer is an
    /// exact additive count and the concrete rows stop at the cap.
    #[test]
    fn exhausted_render_caps_rows_and_reports_an_exact_additive_count() {
        let section = TasksSection::render_with_cap(&intents(5), &[], true, 2);

        assert_eq!(section.rows.len(), 2);
        assert_eq!(section.rows[0].id, "tk_000");
        assert_eq!(section.rows[1].id, "tk_001");
        let overflow = section.overflow.expect("capped rows carry a footer");
        assert_eq!(overflow.known_omitted_rows, 3);
        assert!(overflow.source_exhausted);
        assert_eq!(overflow.line().as_deref(), Some("tasks: +3 more"));
    }

    /// The same omission count under a truncated scan is explicitly a LOWER
    /// bound: entities the scan never inspected may add more.
    #[test]
    fn scan_capped_render_marks_the_count_as_a_lower_bound() {
        let section = TasksSection::render_with_cap(&intents(5), &[], false, 2);

        assert_eq!(section.rows.len(), 2);
        let overflow = section.overflow.expect("capped rows carry a footer");
        assert_eq!(overflow.known_omitted_rows, 3);
        assert!(!overflow.source_exhausted);
        assert_eq!(
            overflow.line().as_deref(),
            Some("tasks: +3 more (at least; scan capped)")
        );
    }

    /// A truncated scan whose visible prefix fits under the render cap must
    /// not print a false exact `+0`; it says what it actually knows.
    #[test]
    fn scan_capped_render_without_omitted_rows_never_prints_a_false_zero() {
        let section = TasksSection::render_with_cap(&intents(1), &[], false, 5);

        assert_eq!(section.rows.len(), 1);
        let overflow = section
            .overflow
            .expect("an unexhausted scan always says so");
        assert_eq!(overflow.known_omitted_rows, 0);
        let line = overflow.line().expect("unexhausted scans render a footer");
        assert_eq!(line, "tasks: more rows may exist (scan capped)");
        assert!(!line.contains("+0"));
    }

    /// Nothing omitted and nothing unscanned means no footer at all — the
    /// landed complete-set render is byte-identical to before.
    #[test]
    fn exhausted_render_under_the_cap_has_no_footer() {
        let section = TasksSection::render_with_cap(&intents(3), &[], true, 5);

        assert_eq!(section.rows.len(), 3);
        assert_eq!(section.overflow, None);
        assert_eq!(render_tasks_section(&intents(3), &[]), section);
    }

    /// Page-boundary arithmetic: the cap is an exact row bound at, below, and
    /// above the boundary, and a zero cap sheds the whole section to a count.
    #[test]
    fn render_cap_boundaries_hold_exactly() {
        for (rows, cap, expected_rows, expected_omitted) in
            [(4, 5, 4, 0), (5, 5, 5, 0), (6, 5, 5, 1), (3, 0, 0, 3)]
        {
            let section = TasksSection::render_with_cap(&intents(rows), &[], true, cap);
            assert_eq!(section.rows.len(), expected_rows, "{rows} rows / cap {cap}");
            assert_eq!(
                section
                    .overflow
                    .map_or(0, |overflow| overflow.known_omitted_rows),
                expected_omitted,
                "{rows} rows / cap {cap}"
            );
        }
        // Empty input under any cap is an empty, footer-free section.
        assert_eq!(
            TasksSection::render_with_cap(&[], &[], true, 5),
            TasksSection {
                rows: Vec::new(),
                overflow: None,
            }
        );
    }

    /// The footer is structural, never work: it has no id, status, intent
    /// flag, or folded-job count, and it can never appear as a `TaskRow`.
    #[test]
    fn the_overflow_footer_is_never_a_task_row() {
        let bare = [job("jb_1", TaskBoardStatus::Running)];
        let section = TasksSection::render_with_cap(&intents(4), &bare, false, 2);

        assert_eq!(section.rows.len(), 2);
        let line = section
            .overflow
            .expect("footer")
            .line()
            .expect("footer line");
        assert!(section.rows.iter().all(|row| row.line != line));
        assert!(section.rows.iter().all(|row| row.id != line));
        // One physical line, like every other renderer-owned line.
        assert_eq!(line.lines().count(), 1);
        // The acked-failure filter still runs BEFORE the cap, so a dropped row
        // is never counted as omitted-but-real.
        let mut acked_failure = intent("tk_gone", TaskBoardStatus::Failed);
        acked_failure.acked = true;
        let filtered = TasksSection::render_with_cap(&[acked_failure], &[], true, 1);
        assert_eq!(filtered.rows.len(), 0);
        assert_eq!(filtered.overflow, None);
    }

    /// The shared page read and the single-key wrappers must agree with each
    /// other AND with the state the write verbs actually persisted.
    #[test]
    fn task_render_state_page_read_matches_legacy_wrappers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault =
            Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("open vault");
        let actor = EntityId::from_bytes([0xC1; 16]).expect("actor id");
        // acked-only, cancelled-only, both, neither.
        let rows: Vec<(EntityId, bool, bool)> = [
            (0xA1, true, false),
            (0xA2, false, true),
            (0xA3, true, true),
            (0xA4, false, false),
        ]
        .into_iter()
        .map(|(seed, acked, cancelled)| {
            (
                EntityId::from_bytes([seed; 16]).expect("task id"),
                acked,
                cancelled,
            )
        })
        .collect();
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        for (task_ref, acked, cancelled) in &rows {
            // Ack FIRST wherever both apply: an acknowledgement that merged in
            // before a cancellation must not read as "not cancelled".
            if *acked {
                ack_task_in_txn(&vault, &mut wtxn, *task_ref, actor, 100).expect("ack");
            }
            if *cancelled {
                cancel_task_in_txn(&vault, &mut wtxn, *task_ref, actor, 101).expect("cancel");
            }
        }
        wtxn.commit().expect("commit render state");

        // ONE transaction for the whole page, exactly as the board scan does.
        let shared: Vec<TaskRenderState> = {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            rows.iter()
                .map(|(task_ref, _, _)| {
                    TaskIntentPresence::render_state_in(&vault, &rtxn, *task_ref)
                        .expect("shared page read")
                })
                .collect()
        };

        for (state, (task_ref, acked, cancelled)) in shared.iter().zip(&rows) {
            // Ground truth first, so a swapped key prefix cannot hide behind
            // two readers that share the same mistake.
            assert_eq!(state.acked, *acked, "{}", task_ref.to_hex());
            assert_eq!(state.cancelled, *cancelled, "{}", task_ref.to_hex());
            assert_eq!(
                *state,
                TaskRenderState {
                    acked: task_is_acked(&vault, *task_ref).expect("wrapper ack"),
                    cancelled: task_is_cancelled(&vault, *task_ref).expect("wrapper cancel"),
                }
            );
        }
    }

    /// Cancel-wins is a property of the FACT SET, not of arrival order: the
    /// same two facts in either order leave the same render state, and the
    /// acknowledgement never clears the cancellation.
    #[test]
    fn cancel_wins_under_both_ack_cancel_orders() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault =
            Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("open vault");
        let actor = EntityId::from_bytes([0xC2; 16]).expect("actor id");
        let ack_first = EntityId::from_bytes([0xB1; 16]).expect("ack-first task id");
        let cancel_first = EntityId::from_bytes([0xB2; 16]).expect("cancel-first task id");

        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        ack_task_in_txn(&vault, &mut wtxn, ack_first, actor, 10).expect("ack");
        cancel_task_in_txn(&vault, &mut wtxn, ack_first, actor, 11).expect("cancel");
        cancel_task_in_txn(&vault, &mut wtxn, cancel_first, actor, 10).expect("cancel");
        ack_task_in_txn(&vault, &mut wtxn, cancel_first, actor, 11).expect("ack");
        wtxn.commit().expect("commit facts");

        for task_ref in [ack_first, cancel_first] {
            let state = task_render_state(&vault, task_ref).expect("render state");
            assert_eq!(
                state,
                TaskRenderState {
                    acked: true,
                    cancelled: true,
                },
                "{}",
                task_ref.to_hex()
            );
        }
    }

    #[test]
    fn run_tree_status_maps_onto_board_status_axis() {
        let statuses = [
            (RunTreeStatus::Queued, Some(TaskBoardStatus::Queued)),
            (RunTreeStatus::Running, Some(TaskBoardStatus::Running)),
            (RunTreeStatus::Paused, Some(TaskBoardStatus::Scheduled)),
            (RunTreeStatus::Completed, Some(TaskBoardStatus::Done)),
            (RunTreeStatus::Failed, Some(TaskBoardStatus::Failed)),
            (RunTreeStatus::Cancelled, None),
        ];
        for (status, board_status) in statuses {
            assert_eq!(run_tree_board_status(status), board_status);
        }
    }
}
