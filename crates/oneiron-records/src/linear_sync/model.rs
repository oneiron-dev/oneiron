//! Moved from `crates/oneiron/src/linear_sync/model.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::linear_sync::model::LinearFieldConflict;
pub use oneiron_verb_wire::linear_sync::model::LinearIssueRef;

/// Bidirectional field: issue title.
pub const LINEAR_FIELD_TITLE: &str = "title";

/// Bidirectional field: issue description / TASK body.
pub const LINEAR_FIELD_DESCRIPTION: &str = "description";

/// Bidirectional field: issue priority.
pub const LINEAR_FIELD_PRIORITY: &str = "priority";

/// Bidirectional field: assignee reference.
pub const LINEAR_FIELD_ASSIGNEE_REF: &str = "assignee_ref";

/// Bidirectional field: workflow status.
pub const LINEAR_FIELD_STATUS: &str = "status";

/// Every bidirectional field, in stable (sorted) order.
pub const LINEAR_MIRRORED_FIELDS: [&str; 5] = [
    LINEAR_FIELD_ASSIGNEE_REF,
    LINEAR_FIELD_DESCRIPTION,
    LINEAR_FIELD_PRIORITY,
    LINEAR_FIELD_STATUS,
    LINEAR_FIELD_TITLE,
];

pub const ERR_LINK_REVISION_OVERFLOW: &str = "linear_sync link revision";

/// Which way one mirror operation moved.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearSyncDirection {
    /// Engine → tracker.
    TaskToIssue,
    /// Tracker → engine.
    IssueToTask,
}

impl LinearSyncDirection {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskToIssue => "task_to_issue",
            Self::IssueToTask => "issue_to_task",
        }
    }
}

/// Outcome of one mirror operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearMirrorStatus {
    /// A new issue was created and linked to the TASK.
    Linked,
    /// Field values were written to the other side.
    Applied,
    /// Nothing to do: unchanged, already applied, or our own echo.
    Noop,
    /// Same-field concurrent edit: every conflicting field was left untouched
    /// on BOTH sides and pinned in the link. The same change's non-conflicting
    /// issue-owned fields, if any, still applied — the refusal is per field.
    Conflict,
}

impl LinearMirrorStatus {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::Applied => "applied",
            Self::Noop => "noop",
            Self::Conflict => "conflict",
        }
    }
}

/// Writer provenance stamped only by the verified TASK facade after its
/// write. Raw/replayed generic puts never receive this mark.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinearWriteActor {
    #[serde(with = "super::storage_codec::entity_ref")]
    pub actor_ref: EntityId,
    pub actor_class: u8,
}

/// The durable record of one mirror operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearMirrorReceipt {
    /// What happened.
    pub status: LinearMirrorStatus,
    /// Which way the operation moved.
    pub direction: LinearSyncDirection,
    /// Stable operation id; the idempotency handle on both sides.
    pub operation_id: [u8; 32],
    /// The mirrored TASK.
    pub task_ref: EntityId,
    /// The mirrored issue.
    pub issue: LinearIssueRef,
    /// Fields left untouched because both sides moved them.
    pub conflicts: Vec<LinearFieldConflict>,
    /// Wall-clock stamp of the operation.
    pub mirrored_at: u64,
}
