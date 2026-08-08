//! TASKS section projections — intent rows, realizing jobs, and the
//! render-tier ack/cancel state helpers behind the `tasks.*` verb surface.

use super::one_line_token;
use crate::outbound::ConnectorSendTask;
use crate::run_tree::{RunTreeNode, RunTreeStatus};
use crate::task_verb::{ConsultResultPresence, TaskKind, TaskTerminalDisposition};
use crate::{EntityId, Error, Result, Vault};

const TASK_ACK_KEY_PREFIX: &[u8] = b"context_board.task.ack.v1\0";
const TASK_CANCELLED_KEY_PREFIX: &[u8] = b"context_board.task.cancelled.v1\0";

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
        }
    }
}

/// Collapsed TASKS section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TasksSection {
    pub rows: Vec<TaskRow>,
}

/// One non-agent-dispatch JobQueue job projected for the board — a bare
/// system job row, or a realizing job folded under its owning intent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobPresence {
    pub id: String,
    pub kind: String,
    pub status: TaskBoardStatus,
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
        })
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
}

pub(crate) fn task_is_acked(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    task_state(vault, TASK_ACK_KEY_PREFIX, task_ref)
}

pub(crate) fn ack_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
) -> Result<()> {
    set_task_state_in_txn(vault, wtxn, TASK_ACK_KEY_PREFIX, task_ref)
}

pub(crate) fn task_is_cancelled(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    task_state(vault, TASK_CANCELLED_KEY_PREFIX, task_ref)
}

pub(crate) fn cancel_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
) -> Result<()> {
    set_task_state_in_txn(vault, wtxn, TASK_CANCELLED_KEY_PREFIX, task_ref)
}

fn task_state(vault: &Vault, prefix: &[u8], task_ref: EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    match vault
        .store
        .vault_meta
        .get(&rtxn, task_state_key(prefix, task_ref).as_slice())?
    {
        None => Ok(false),
        Some(value) if *value == [1] => Ok(true),
        Some(_) => Err(Error::InvariantViolation("context_board.task.state")),
    }
}

fn set_task_state_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    prefix: &[u8],
    task_ref: EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(wtxn, task_state_key(prefix, task_ref).as_slice(), &[1])?;
    Ok(())
}

fn task_state_key(prefix: &[u8], task_ref: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + task_ref.as_bytes().len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(task_ref.as_bytes());
    key
}

/// Renders provided task presence into stable, collapsed rows — intent rows
/// first with realizing jobs folded under them, then bare system jobs as-is.
/// Acked failures have left the surface.
#[must_use]
pub fn render_tasks_section(
    intents: &[TaskIntentPresence],
    bare_jobs: &[JobPresence],
) -> TasksSection {
    let mut rows = Vec::with_capacity(intents.len() + bare_jobs.len());
    rows.extend(
        intents
            .iter()
            .filter(|intent| !intent.is_acked_failure())
            .map(intent_row),
    );
    rows.extend(bare_jobs.iter().map(bare_job_row));
    TasksSection { rows }
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
    // The exact cause rides BESIDE the status token, never inside it: the
    // asker's failed lane must read `expired` distinctly from `failed`. A
    // disposition whose token already equals the status adds nothing.
    if let Some(disposition) = intent.terminal_disposition
        && disposition.as_str() != intent.status.as_str()
    {
        tokens.push(disposition.as_str().to_owned());
    }
    if folded_job_count > 0 {
        tokens.push(format!("jobs={folded_job_count}"));
    }
    TaskRow::from_intent(intent, tokens.join(" "))
}

fn bare_job_row(job: &JobPresence) -> TaskRow {
    TaskRow {
        id: job.id.clone(),
        line: format!(
            "{} {} {}",
            one_line_token(&job.id),
            one_line_token(&job.kind),
            job.status.as_str()
        ),
        status: job.status,
        is_intent: false,
        folded_job_count: 0,
        kind: None,
        assignee: None,
        terminal_disposition: None,
        result_ref: None,
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
