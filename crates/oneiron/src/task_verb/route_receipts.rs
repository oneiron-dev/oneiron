//! TASK execution lanes and the receipts each transition answers with.
//! Entry [`TaskRouteLane`]; driven by `lifecycle_facade` through dispatch.
//! Owned by `task_verb`; assignee kinds resolve via `verb_kind`, never here.
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimApprovalStatus;
use crate::context_board::TasksSection;
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::lens::RecordRef;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TASK};

use super::terminal_state::TaskTerminalDisposition;

#[doc(hidden)]
pub use oneiron_records::task_verb::route_receipts::{
    TaskCancelReceipt, TaskRouteLane, TaskRouteOutcome,
};

/// Result of one `tasks.create` invocation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskCreateReceipt {
    pub task_ref: Option<EntityId>,
    pub proposal_ref: Option<EntityId>,
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
    /// The lane the created TASK routed to. `None` when nothing was created —
    /// a parked proposal has not routed anywhere yet.
    pub route: Option<TaskRouteOutcome>,
    /// The created TASK as a typed record ref (OF-063), built from its id
    /// with no read. `None` when no TASK was created.
    #[serde(default)]
    pub task_record: Option<RecordRef>,
    /// The parked proposal CLAIM as a typed record ref, built the same way.
    #[serde(default)]
    pub proposal_record: Option<RecordRef>,
}

impl TaskCreateReceipt {
    /// This receipt with its typed refs named from the ids it holds.
    #[must_use]
    pub(super) fn with_record_refs(mut self) -> Self {
        self.task_record = self
            .task_ref
            .map(|id| RecordRef::from_id(ENTITY_TYPE_TASK, &id, None));
        self.proposal_record = self
            .proposal_ref
            .map(|id| RecordRef::from_id(ENTITY_TYPE_CLAIM, &id, None));
        self
    }
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

/// A TASK entity or agent-dispatch spawn addressed by `cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCancelTarget {
    Task(EntityId),
    Spawn(AttemptId),
}

/// Result of one `tasks.update`. Without a report it records the
/// acknowledgement of a failed task, and leaves any other task as it was;
/// with one, `report` is the task highway's answer unchanged, an asked-up,
/// stale-fence or wrong-node outcome included.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TaskUpdateReceipt {
    pub task_ref: EntityId,
    pub acked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<super::TaskCallReceipt>,
}

/// What `describe` returns: the TASKS section when no task is named, the
/// named task's card, the vault's shape card, or a highway handle's status.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum TaskDescription {
    #[serde(rename = "tasks_section")]
    Section(TasksSection),
    #[serde(rename = "task_card")]
    Card { lines: Vec<String> },
    /// A host-bound `describe(self)` call returns the same tail card as the
    /// context assembly path. No prefix replacement occurs mid-run.
    #[serde(rename = "self_card")]
    SelfCard { tail: String },
    /// `describe(vault)`: the vault's shape card.
    #[serde(rename = "vault_card")]
    VaultCard { card: crate::vault_shape::ShapeCard },
    /// `describe({handle, after})` (OF-220): the highway's status answer for
    /// one handle, or its poll.
    #[serde(rename = "task_status")]
    Status { receipt: super::TaskCallReceipt },
}
