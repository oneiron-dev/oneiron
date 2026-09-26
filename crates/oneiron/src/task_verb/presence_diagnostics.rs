//! Typed per-row presence read failures for the bounded TASKS projection.

use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TaskPresenceReadStage {
    RenderState,
    PageSlot,
    Resolve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TaskPresenceReadFailure {
    pub(super) task_ref: EntityId,
    pub(super) stage: TaskPresenceReadStage,
    pub(super) kind: ErrorKind,
}

/// Retain a typed failure for the section caller to warn about, once per
/// skipped row. A corrupt peer row cannot abort the rest of the section.
pub(super) fn record_read_failure(
    failures: &mut Vec<TaskPresenceReadFailure>,
    task_ref: EntityId,
    stage: TaskPresenceReadStage,
    error: &Error,
) {
    failures.push(TaskPresenceReadFailure {
        task_ref,
        stage,
        kind: error.kind(),
    });
}
