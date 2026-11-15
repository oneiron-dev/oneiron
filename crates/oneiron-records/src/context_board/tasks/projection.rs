//! Moved from `crates/oneiron/src/context_board/tasks/projection.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::attempt_queue::run_tree_view::RunTreeStatus;
pub use oneiron_verb_wire::context_board::tasks::projection::ConsultWidening;

/// Maximum concrete TASKS rows rendered before the additive overflow footer.
///
/// ARCH-0067 §3 sheds TASKS "to counts" under the board cap, so the section
/// needs a row bound of its own. This one bounds TOKENS; `task_verb`'s board
/// scan reads every TASK row (rule 5), so no malformed or filtered prefix
/// starves the visible board.
///
/// Re-exported crate-wide as [`TasksSection::RENDER_ROW_CAP`].
pub const TASKS_RENDER_ROW_CAP: usize = 100;

const _: () = assert!(TASKS_RENDER_ROW_CAP > 0);

/// TASKS board status axis (08b §3): running / scheduled / queued / done /
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CancelRejectionPathology {
    /// The realizing ATTEMPT that is refusing, so the owner can address it.
    pub attempt_id: String,
    /// Soft requests this attempt has refused.
    pub rejections: u32,
    /// The count at which refusal became a pathology signal
    /// ([`oneiron_verb_wire::attempt_queue::cancel::types::SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`]).
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

/// The structural TASKS footer: what the board did NOT show.
///
/// Deliberately not a [`TaskRow`] — it carries no task id, status, intent
/// flag, or folded-job count, so nothing downstream can mistake the footer for
/// work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Most persons one TASKS row names under `fits:`.
pub const TASK_FITS_CAP: usize = 3;

/// A live child's run state on the TASKS axis.
pub const fn child_board_status(
    status: oneiron_verb_wire::context_board::agent_run_status::AgentRunStatus,
) -> TaskBoardStatus {
    use oneiron_verb_wire::context_board::agent_run_status::AgentRunStatus;
    match status {
        AgentRunStatus::Spawned => TaskBoardStatus::Queued,
        AgentRunStatus::Working | AgentRunStatus::NeedsInput => TaskBoardStatus::Running,
        AgentRunStatus::Delivered | AgentRunStatus::Archived => TaskBoardStatus::Done,
        AgentRunStatus::Failed | AgentRunStatus::Abandoned | AgentRunStatus::Cancelled => {
            TaskBoardStatus::Failed
        }
    }
}

/// Maps the SURF-005 lifecycle onto the board status axis. `Paused` reads as
/// scheduled (deferred, not eligible to run now); `Cancelled` has no axis
/// token and leaves the board.
pub const fn run_tree_board_status(status: RunTreeStatus) -> Option<TaskBoardStatus> {
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
