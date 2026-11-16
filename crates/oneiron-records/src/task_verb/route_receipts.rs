//! Moved from `crates/oneiron/src/task_verb/route_receipts.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::attempt_queue::run_tree_view::RunTreeStatus;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;

/// The lanes `TASK.assignee` routes over: three pluggable EXECUTION lanes, plus
/// the human lane, which executes nothing at all (ONE-1708).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRouteLane {
    Dreamer,
    AgentDefinition,
    PeerActor,
    ChildActor,
    /// A person was asked. Nothing realizes the task; the Dreamer follows up.
    HumanAssignee,
    /// A watch TASK (FIX 22121). Nothing realizes it: the hooks on its due
    /// tick do its work, and that tick settles it.
    Watch,
}

/// What routing one created TASK actually did. The peer variant naming zero
/// attempts is the point: the synced entity IS the transport. The human variant
/// names zero attempts for a different reason — a person is not a worker. The
/// watch variant names none because its due tick's hooks do the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    ChildAddressed {
        actor_ref: EntityId,
    },
    HumanFollowup {
        actor_ref: EntityId,
    },
    /// A watch TASK queued no work; its tick at `due_at` (Unix seconds)
    /// runs its hooks and settles it (FIX 22121).
    WatchTick {
        due_at: u64,
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
            Self::ChildAddressed { .. } => TaskRouteLane::ChildActor,
            Self::WatchTick { .. } => TaskRouteLane::Watch,
        }
    }

    /// The local realizing attempt, or `None` on the peer, human and watch
    /// lanes.
    #[must_use]
    pub const fn local_attempt(self) -> Option<AttemptId> {
        match self {
            Self::DreamerAttempt { attempt_ref } | Self::AgentDispatch { attempt_ref, .. } => {
                Some(attempt_ref)
            }
            Self::PeerSyncedOnly { .. }
            | Self::ChildAddressed { .. }
            | Self::HumanFollowup { .. }
            | Self::WatchTick { .. } => None,
        }
    }
}

/// Result of one `cancel` invocation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
