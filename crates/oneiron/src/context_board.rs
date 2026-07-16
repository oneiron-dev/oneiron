//! Typed Context Board render projections.

use crate::outbound::ConnectorSendTask;
use crate::run_tree::{RunTreeNode, RunTreeStatus};

/// AGENTS row lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentLane {
    Child,
    Peer,
}

impl AgentLane {
    /// Stable structural token for the lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Child => "child",
            Self::Peer => "peer",
        }
    }
}

/// One collapsed AGENTS row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    pub id: String,
    pub lane: AgentLane,
    pub line: String,
    pub harness_label: Option<String>,
}

/// Collapsed AGENTS section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentsSection {
    pub rows: Vec<AgentRow>,
}

/// One present child agent projected from M8 driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildAgentPresence {
    pub id: String,
    pub status: RunTreeStatus,
    pub label: Option<String>,
}

impl ChildAgentPresence {
    /// Presents a running M8 agent-dispatch subagent; row identity is its per-spawn
    /// attempt id, while its AgentDefinition label (`agent_id`) is optional display text.
    /// Returns `None` for non-agent-dispatch attempts and terminal nodes because the
    /// section shows children working here now.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<ChildAgentPresence> {
        if node.worker_kind != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }

        match node.status {
            RunTreeStatus::Completed | RunTreeStatus::Failed | RunTreeStatus::Cancelled => None,
            RunTreeStatus::Queued | RunTreeStatus::Running | RunTreeStatus::Paused => {
                Some(ChildAgentPresence {
                    id: node.attempt_id.clone(),
                    status: node.status,
                    label: node
                        .agent_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|label| !label.is_empty())
                        .map(str::to_owned),
                })
            }
        }
    }
}

/// Registry-populated peer-presence view; identity and registry storage remain upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPresence {
    pub actor_handle: String,
    pub harness_label: String,
    pub last_seen: Option<u64>,
}

/// Renders provided agent presence into stable, collapsed rows.
#[must_use]
pub fn render_agents_section(
    children: &[ChildAgentPresence],
    peers: &[PeerPresence],
) -> AgentsSection {
    let mut rows = Vec::with_capacity(children.len() + peers.len());

    rows.extend(children.iter().map(|child| AgentRow {
        id: child.id.clone(),
        lane: AgentLane::Child,
        line: match child.label.as_deref() {
            Some(label) => format!(
                "{} {} {}",
                one_line_token(&child.id),
                one_line_token(label),
                one_line_token(status_token(child.status))
            ),
            None => format!(
                "{} {}",
                one_line_token(&child.id),
                one_line_token(status_token(child.status))
            ),
        },
        harness_label: None,
    }));
    rows.extend(peers.iter().map(|peer| AgentRow {
        id: peer.actor_handle.clone(),
        lane: AgentLane::Peer,
        line: format!(
            "{} {}",
            one_line_token(&peer.actor_handle),
            one_line_token(&peer.harness_label)
        ),
        harness_label: Some(peer.harness_label.clone()),
    }));

    AgentsSection { rows }
}

/// Collapse control characters so a rendered row is always one physical line.
fn one_line_token(s: &str) -> String {
    s.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

const fn status_token(status: RunTreeStatus) -> &'static str {
    match status {
        RunTreeStatus::Queued => "queued",
        RunTreeStatus::Running => "running",
        RunTreeStatus::Paused => "paused",
        RunTreeStatus::Completed => "completed",
        RunTreeStatus::Failed => "failed",
        RunTreeStatus::Cancelled => "cancelled",
    }
}

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
}

impl TaskIntentPresence {
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
        TaskIntentPresence {
            id: task.task_ref.to_hex(),
            status,
            label: Some(task.intent.verb.clone()),
            acked: false,
            realizing_jobs,
        }
    }

    /// Failed rows stay surfaced until acked (08b §3); an acked failure has
    /// left the board surface.
    #[must_use]
    pub fn is_acked_failure(&self) -> bool {
        self.status == TaskBoardStatus::Failed && self.acked
    }
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
    let mut lines = Vec::with_capacity(1 + intent.realizing_jobs.len());
    lines.push(intent_row(intent).line);
    lines.extend(
        intent
            .realizing_jobs
            .iter()
            .map(|job| format!("  {}", bare_job_row(job).line)),
    );
    lines
}

fn intent_row(intent: &TaskIntentPresence) -> TaskRow {
    let folded_job_count = intent.realizing_jobs.len();
    let mut tokens = vec![one_line_token(&intent.id)];
    if let Some(label) = intent.label.as_deref() {
        tokens.push(one_line_token(label));
    }
    tokens.push(intent.status.as_str().to_owned());
    if folded_job_count > 0 {
        tokens.push(format!("jobs={folded_job_count}"));
    }
    TaskRow {
        id: intent.id.clone(),
        line: tokens.join(" "),
        status: intent.status,
        is_intent: true,
        folded_job_count,
    }
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
    }
}

/// Header tokens of the block envelope (08b §0 shape:
/// `[CONTEXT_BOARD epoch=47 scope=WorldSet(...)]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardBlockHeader {
    pub epoch: u64,
    pub scope: String,
}

/// One assembled block section: a name token over one-line rows. TASKS and
/// AGENTS rows come from their typed section renders; other sections pass
/// whatever one-line rows their renderers produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardSection {
    pub name: String,
    pub rows: Vec<String>,
}

/// Assembles the full Context Board block: one `[CONTEXT_BOARD …]` open-tag
/// line, each section's name and one-line rows, one `[/CONTEXT_BOARD]`
/// close-tag line. Every embedded token rides [`one_line_token`], so an
/// injected control character can never mint or split a physical line; the
/// block is render output only — no code path parses it back into state
/// (08b §0 keystone).
#[must_use]
pub fn render_board_block(header: &BoardBlockHeader, sections: &[BoardSection]) -> String {
    let row_count: usize = sections.iter().map(|section| 1 + section.rows.len()).sum();
    let mut lines = Vec::with_capacity(2 + row_count);
    lines.push(format!(
        "[CONTEXT_BOARD epoch={} scope={}]",
        header.epoch,
        one_line_token(&header.scope)
    ));
    for section in sections {
        lines.push(one_line_token(&section.name));
        lines.extend(section.rows.iter().map(|row| one_line_token(row)));
    }
    lines.push("[/CONTEXT_BOARD]".to_owned());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
    use crate::edge::EdgeActorClass;
    use crate::entity_id::EntityId;
    use crate::outbound::OutboundIntent;
    use crate::run_tree::{RunTreeStatus, RunTreeTimestamps};

    fn child(id: &str) -> ChildAgentPresence {
        ChildAgentPresence {
            id: id.to_owned(),
            status: RunTreeStatus::Running,
            label: None,
        }
    }

    fn peer(actor_handle: &str) -> PeerPresence {
        PeerPresence {
            actor_handle: actor_handle.to_owned(),
            harness_label: "claude-code".to_owned(),
            last_seen: Some(1),
        }
    }

    fn run_tree_node(
        attempt_id: &str,
        agent_id: Option<&str>,
        status: RunTreeStatus,
    ) -> RunTreeNode {
        run_tree_node_with_worker_kind(attempt_id, agent_id, status, AGENT_DISPATCH_ATTEMPT_TYPE)
    }

    fn run_tree_node_with_worker_kind(
        attempt_id: &str,
        agent_id: Option<&str>,
        status: RunTreeStatus,
        worker_kind: &str,
    ) -> RunTreeNode {
        RunTreeNode {
            attempt_id: attempt_id.to_owned(),
            run_id: None,
            parent_id: None,
            worker_kind: worker_kind.to_owned(),
            agent_id: agent_id.map(str::to_owned),
            status,
            timestamps: RunTreeTimestamps {
                created_at: 1,
                updated_at: 2,
            },
            failure: None,
            events: Vec::new(),
            children: Vec::new(),
        }
    }

    #[test]
    fn renders_children_and_peers_as_one_line_rows() {
        let children = [child("child_a"), child("child_b")];
        let peers = [peer("cc-main"), peer("cc-second")];

        let section = render_agents_section(&children, &peers);

        assert_eq!(section.rows.len(), 4);
        let non_empty_lines = section
            .rows
            .iter()
            .filter(|row| !row.line.is_empty())
            .count();
        assert_eq!(non_empty_lines, 4);
        let one_line_rows = section
            .rows
            .iter()
            .filter(|row| row.line.lines().count() == 1)
            .count();
        assert_eq!(one_line_rows, 4);

        let child_rows: Vec<&AgentRow> = section
            .rows
            .iter()
            .filter(|row| row.lane == AgentLane::Child)
            .collect();
        assert_eq!(child_rows.len(), 2);
        let mut child_ids: Vec<&str> = child_rows.iter().map(|row| row.id.as_str()).collect();
        child_ids.sort_unstable();
        assert_eq!(child_ids, ["child_a", "child_b"]);
        let children_without_labels = children
            .iter()
            .filter(|child| child.label.is_none())
            .count();
        assert_eq!(children_without_labels, 2);
        let child_rows_without_labels = child_rows
            .iter()
            .filter(|row| row.harness_label.is_none())
            .count();
        assert_eq!(child_rows_without_labels, 2);
        let child_a = child_rows
            .iter()
            .find(|row| row.id == "child_a")
            .expect("child_a row must be rendered");
        assert_eq!(child_a.line, "child_a running");
        let child_b = child_rows
            .iter()
            .find(|row| row.id == "child_b")
            .expect("child_b row must be rendered");
        assert_eq!(child_b.line, "child_b running");

        let peer_rows: Vec<&AgentRow> = section
            .rows
            .iter()
            .filter(|row| row.lane == AgentLane::Peer)
            .collect();
        assert_eq!(peer_rows.len(), 2);
        let mut peer_ids: Vec<&str> = peer_rows.iter().map(|row| row.id.as_str()).collect();
        peer_ids.sort_unstable();
        assert_eq!(peer_ids, ["cc-main", "cc-second"]);
        let peer_rows_with_labels = peer_rows
            .iter()
            .filter(|row| row.harness_label.as_deref() == Some("claude-code"))
            .count();
        assert_eq!(peer_rows_with_labels, 2);
        let cc_main = peer_rows
            .iter()
            .find(|row| row.id == "cc-main")
            .expect("cc-main row must be rendered");
        assert_eq!(cc_main.line, "cc-main claude-code");
        let cc_second = peer_rows
            .iter()
            .find(|row| row.id == "cc-second")
            .expect("cc-second row must be rendered");
        assert_eq!(cc_second.line, "cc-second claude-code");
    }

    #[test]
    fn control_characters_cannot_split_rendered_rows() {
        let children = [child("child_a\nspoof")];
        let peers = [PeerPresence {
            actor_handle: "cc-main\rspoof".to_owned(),
            harness_label: "claude\ncode".to_owned(),
            last_seen: Some(1),
        }];

        let section = render_agents_section(&children, &peers);

        assert_eq!(section.rows.len(), 2);
        let non_empty_rows = section
            .rows
            .iter()
            .filter(|row| !row.line.is_empty())
            .count();
        assert_eq!(non_empty_rows, 2);
        let one_line_rows = section
            .rows
            .iter()
            .filter(|row| row.line.lines().count() == 1)
            .count();
        assert_eq!(one_line_rows, 2);
        assert_eq!(section.rows[0].id, "child_a\nspoof");
        assert_eq!(section.rows[0].harness_label, None);
        assert_eq!(section.rows[0].line, "child_a spoof running");
        assert_eq!(section.rows[1].id, "cc-main\rspoof");
        assert_eq!(
            section.rows[1].harness_label.as_deref(),
            Some("claude\ncode")
        );
        assert_eq!(section.rows[1].line, "cc-main spoof claude code");
    }

    #[test]
    fn peer_identity_is_connection_keyed() {
        let section = render_agents_section(&[], &[peer("cc-main"), peer("cc-second")]);

        assert_eq!(section.rows.len(), 2);
        assert_ne!(section.rows[0].id, section.rows[1].id);
        let exact_labels = section
            .rows
            .iter()
            .filter(|row| row.harness_label.as_deref() == Some("claude-code"))
            .count();
        assert_eq!(exact_labels, 2);
    }

    #[test]
    fn bridge_discriminates_driver_state() {
        let queued = run_tree_node("attempt_q", Some("child_q"), RunTreeStatus::Queued);
        let running = run_tree_node("attempt_a", Some("child_a"), RunTreeStatus::Running);
        let paused = run_tree_node("attempt_p", Some("child_p"), RunTreeStatus::Paused);
        let completed = run_tree_node("attempt_b", Some("child_b"), RunTreeStatus::Completed);
        let failed = run_tree_node("attempt_f", Some("child_f"), RunTreeStatus::Failed);
        let cancelled = run_tree_node("attempt_c", Some("child_c"), RunTreeStatus::Cancelled);

        let presence = ChildAgentPresence::from_run_tree_node(&running);
        assert_eq!(
            presence.as_ref().map(|child| child.id.as_str()),
            Some("attempt_a")
        );
        assert_eq!(
            presence.as_ref().and_then(|child| child.label.as_deref()),
            Some("child_a")
        );
        assert_eq!(
            presence.as_ref().map(|child| child.status),
            Some(RunTreeStatus::Running)
        );
        assert_eq!(ChildAgentPresence::from_run_tree_node(&completed), None);

        let lifecycle_presences = [
            ChildAgentPresence::from_run_tree_node(&queued),
            ChildAgentPresence::from_run_tree_node(&running),
            ChildAgentPresence::from_run_tree_node(&paused),
            ChildAgentPresence::from_run_tree_node(&completed),
            ChildAgentPresence::from_run_tree_node(&failed),
            ChildAgentPresence::from_run_tree_node(&cancelled),
        ];
        let present_count = lifecycle_presences
            .iter()
            .filter(|presence| presence.is_some())
            .count();
        assert_eq!(present_count, 3);
        let absent_count = lifecycle_presences
            .iter()
            .filter(|presence| presence.is_none())
            .count();
        assert_eq!(absent_count, 3);
        let present_children: Vec<(&str, Option<&str>, RunTreeStatus)> = lifecycle_presences
            .iter()
            .filter_map(|presence| presence.as_ref())
            .map(|child| (child.id.as_str(), child.label.as_deref(), child.status))
            .collect();
        assert_eq!(
            present_children,
            [
                ("attempt_q", Some("child_q"), RunTreeStatus::Queued),
                ("attempt_a", Some("child_a"), RunTreeStatus::Running),
                ("attempt_p", Some("child_p"), RunTreeStatus::Paused),
            ]
        );
        assert_eq!(lifecycle_presences[3], None);
        assert_eq!(lifecycle_presences[4], None);
        assert_eq!(lifecycle_presences[5], None);

        let non_agent = run_tree_node_with_worker_kind(
            "attempt_fake",
            Some("fake_child"),
            RunTreeStatus::Running,
            "dreamer",
        );
        assert_eq!(ChildAgentPresence::from_run_tree_node(&non_agent), None);

        let missing_label = run_tree_node("attempt_missing", None, RunTreeStatus::Running);
        let missing_label_presence = ChildAgentPresence::from_run_tree_node(&missing_label);
        assert_eq!(
            missing_label_presence
                .as_ref()
                .map(|child| child.id.as_str()),
            Some("attempt_missing")
        );
        assert_eq!(
            missing_label_presence
                .as_ref()
                .and_then(|child| child.label.as_deref()),
            None
        );

        let blank_label = run_tree_node("attempt_blank", Some("   "), RunTreeStatus::Running);
        let blank_label_presence = ChildAgentPresence::from_run_tree_node(&blank_label);
        assert_eq!(
            blank_label_presence.as_ref().map(|child| child.id.as_str()),
            Some("attempt_blank")
        );
        assert_eq!(
            blank_label_presence
                .as_ref()
                .and_then(|child| child.label.as_deref()),
            None
        );
    }

    #[test]
    fn child_identity_is_per_spawn_not_definition_label() {
        let nodes = [
            run_tree_node("attempt_1", Some("researcher"), RunTreeStatus::Running),
            run_tree_node("attempt_2", Some("researcher"), RunTreeStatus::Running),
        ];
        let presences: Vec<ChildAgentPresence> = nodes
            .iter()
            .filter_map(ChildAgentPresence::from_run_tree_node)
            .collect();

        assert_eq!(presences.len(), 2);
        let ids: Vec<&str> = presences.iter().map(|child| child.id.as_str()).collect();
        assert_eq!(ids, ["attempt_1", "attempt_2"]);
        assert_ne!(ids[0], ids[1]);
        let mut distinct_ids = ids.clone();
        distinct_ids.sort_unstable();
        distinct_ids.dedup();
        assert_eq!(distinct_ids.len(), 2);
        let labels: Vec<Option<&str>> = presences
            .iter()
            .map(|child| child.label.as_deref())
            .collect();
        assert_eq!(labels, [Some("researcher"), Some("researcher")]);

        let section = render_agents_section(&presences, &[]);

        assert_eq!(section.rows.len(), 2);
        let rendered_ids: Vec<&str> = section.rows.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(rendered_ids, ["attempt_1", "attempt_2"]);
        let rendered_lines: Vec<&str> = section.rows.iter().map(|row| row.line.as_str()).collect();
        assert_eq!(
            rendered_lines,
            [
                "attempt_1 researcher running",
                "attempt_2 researcher running"
            ]
        );
        let mut distinct_lines = rendered_lines.clone();
        distinct_lines.sort_unstable();
        distinct_lines.dedup();
        assert_eq!(distinct_lines.len(), 2);
    }

    #[test]
    fn empty_inputs_render_empty_section() {
        let section = render_agents_section(&[], &[]);

        assert_eq!(section.rows.len(), 0);
    }

    fn intent(id: &str, status: TaskBoardStatus) -> TaskIntentPresence {
        TaskIntentPresence {
            id: id.to_owned(),
            status,
            label: None,
            acked: false,
            realizing_jobs: Vec::new(),
        }
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
    fn board_block_envelope_is_exactly_one_open_one_close() {
        let header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(wd_1)".to_owned(),
        };
        let sections = [
            BoardSection {
                name: "WORLDS".to_owned(),
                rows: vec!["wd_1 active".to_owned()],
            },
            BoardSection {
                name: "MEMORIES".to_owned(),
                rows: vec!["cl_1 pinned".to_owned()],
            },
            BoardSection {
                name: "TASKS".to_owned(),
                rows: vec!["tk_a running".to_owned()],
            },
        ];

        let text = render_board_block(&header, &sections);

        let first_line = text.lines().next().expect("block must have a first line");
        assert!(
            first_line
                .strip_prefix("[CONTEXT_BOARD ")
                .and_then(|rest| rest.strip_suffix(']'))
                .is_some()
        );
        assert_eq!(first_line, "[CONTEXT_BOARD epoch=47 scope=WorldSet(wd_1)]");
        assert_eq!(text.matches("[CONTEXT_BOARD ").count(), 1);
        assert_eq!(text.matches("[/CONTEXT_BOARD]").count(), 1);
        assert_eq!(text.matches("MEMORY_BOARD").count(), 0);
        assert_eq!(text.lines().count(), 8);

        let hostile_header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(\nwd_1)".to_owned(),
        };
        let hostile_sections = [
            BoardSection {
                name: "WORLDS\nSPOOF".to_owned(),
                rows: vec!["wd_1\ractive".to_owned()],
            },
            BoardSection {
                name: "MEMORIES".to_owned(),
                rows: vec!["cl_1 pinned".to_owned()],
            },
            BoardSection {
                name: "TASKS".to_owned(),
                rows: vec!["tk_a\nrunning".to_owned()],
            },
        ];

        let hostile = render_board_block(&hostile_header, &hostile_sections);

        assert_eq!(hostile.lines().count(), text.lines().count());
        assert_eq!(hostile.matches("[CONTEXT_BOARD ").count(), 1);
        assert_eq!(hostile.matches("[/CONTEXT_BOARD]").count(), 1);
        assert_eq!(hostile.matches("MEMORY_BOARD").count(), 0);
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
