use crate::attempt_queue::AttemptId;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::run_tree::RunTreeStatus;

use super::terminal_state::TaskTerminalDisposition;

/// The lanes `TASK.assignee` routes over: three pluggable EXECUTION lanes, plus
/// the human lane, which executes nothing at all (ONE-1708).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRouteLane {
    Dreamer,
    AgentDefinition,
    PeerActor,
    /// A person was asked. Nothing realizes the task; the Dreamer follows up.
    HumanAssignee,
}

/// What routing one created TASK actually did. The peer variant naming zero
/// attempts is the point: the synced entity IS the transport. The human variant
/// names zero attempts for a different reason — a person is not a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRouteOutcome {
    DreamerAttempt {
        attempt_ref: AttemptId,
    },
    AgentDispatch {
        attempt_ref: AttemptId,
        agent_def_ref: EntityId,
    },
    PeerSyncedOnly {
        actor_ref: EntityId,
    },
    HumanFollowup {
        actor_ref: EntityId,
    },
}

impl TaskRouteOutcome {
    /// The lane this outcome came from.
    #[must_use]
    pub const fn lane(self) -> TaskRouteLane {
        match self {
            Self::DreamerAttempt { .. } => TaskRouteLane::Dreamer,
            Self::AgentDispatch { .. } => TaskRouteLane::AgentDefinition,
            Self::PeerSyncedOnly { .. } => TaskRouteLane::PeerActor,
            Self::HumanFollowup { .. } => TaskRouteLane::HumanAssignee,
        }
    }

    /// The local realizing attempt, or `None` on the peer and human lanes.
    #[must_use]
    pub const fn local_attempt(self) -> Option<AttemptId> {
        match self {
            Self::DreamerAttempt { attempt_ref } | Self::AgentDispatch { attempt_ref, .. } => {
                Some(attempt_ref)
            }
            Self::PeerSyncedOnly { .. } | Self::HumanFollowup { .. } => None,
        }
    }
}

/// Result of one `tasks.create` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCreateReceipt {
    pub task_ref: Option<EntityId>,
    pub proposal_ref: Option<EntityId>,
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
    /// The lane the created TASK routed to. `None` when nothing was created —
    /// a parked proposal has not routed anywhere yet.
    pub route: Option<TaskRouteOutcome>,
}

/// Receipt for stamping the authoritative `started_at` fact on a TASK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStartedReceipt {
    pub task_ref: EntityId,
    pub started_at: u64,
    pub idempotent_replay: bool,
}

/// Input to the general terminal writer. Every terminal transition carries a
/// `result_ref` — including `Abandoned`, whose durable outputs are exactly what
/// makes an abandoned run reviewable rather than lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskResultInput {
    pub result_ref: EntityId,
    pub disposition: TaskTerminalDisposition,
    pub finished_at: u64,
}

/// Vocabulary over the existing two-state approval ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCancelMode {
    Auto,
    FullAccess,
    Manual,
}

impl TaskCancelMode {
    /// All ladder vocabulary tokens in protocol sort order.
    pub const ALL: [Self; 3] = [Self::Auto, Self::FullAccess, Self::Manual];

    /// Stable vocabulary token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::FullAccess => "full-access",
            Self::Manual => "manual",
        }
    }

    pub(super) const fn ceiling(self) -> PolicyApprovalCeiling {
        match self {
            Self::Auto | Self::FullAccess => PolicyApprovalCeiling::Auto,
            Self::Manual => PolicyApprovalCeiling::Proposed,
        }
    }
}

/// Default ladder vocabulary for own-task and own-spawn cancellation.
pub const DEFAULT_TASK_CANCEL_MODE: TaskCancelMode = TaskCancelMode::Auto;

/// A TASK entity or agent-dispatch spawn addressed by `tasks.cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCancelTarget {
    Task(EntityId),
    Spawn(AttemptId),
}

/// Result of one `tasks.cancel` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCancelReceipt {
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
    pub proposal_ref: Option<EntityId>,
    pub gate_decision_ref: Option<String>,
    pub status: Option<RunTreeStatus>,
    /// ONE-1896: a RUNNING realization was asked to land rather than killed.
    /// Deliberately not folded into `effected`, which stays the honest "work
    /// actually stopped" bit — a request is a question, and the worker may
    /// still refuse it.
    pub cancel_requested: bool,
    /// ONE-1896 rung 2: a verified owner took the nonrefusable path and the
    /// runtime authored terminal cancellation receipts. Always false for the
    /// cooperative verb, which cannot force by construction.
    pub forced: bool,
}

/// Result of persisting one render-tier task acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAckReceipt {
    pub task_ref: EntityId,
    pub acked: bool,
}
