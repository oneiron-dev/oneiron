//! Companion task payload and durable queue result values.

use super::{AttemptId, AttemptRecord};
use crate::error::Result;
use crate::write_envelope::companion_subject::{
    CompanionScope, CompanionSubject, CompanionTaskKey,
};
use crate::write_envelope::companion_task_kind::CompanionTaskKind;

/// Typed payload stored on durable companion task attempt rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionTask {
    pub kind: CompanionTaskKind,
    pub key: CompanionTaskKey,
}

impl CompanionTask {
    /// Constructs a companion task, validating the key's shape. Whether a
    /// PERSON target is live is judged at enqueue, in the admitting write.
    pub fn new(kind: CompanionTaskKind, key: CompanionTaskKey) -> Result<Self> {
        key.validate()?;
        Ok(Self { kind, key })
    }

    /// Stable advisory dedupe key for this task target.
    #[must_use]
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind.as_str(),
            companion_scope_dedupe_key(&self.key.scope),
            companion_subject_dedupe_key(&self.key.subject)
        )
    }
}

/// Decoded companion task plus its backing durable AttemptQueue row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionTaskStatus {
    pub attempt: AttemptRecord,
    pub task: CompanionTask,
}

/// Input for enqueuing a companion task through the generic AttemptQueue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueCompanionTask {
    pub task: CompanionTask,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed companion enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueCompanionTaskOutcome {
    Enqueued(CompanionTaskStatus),
    Existing(CompanionTaskStatus),
}

/// Input for claiming the next queued companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCompanionTask {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed companion claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimCompanionTaskOutcome {
    Empty,
    Claimed(Box<CompanionTaskStatus>),
}

/// Input for completing a leased companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCompanionTask {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed companion complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteCompanionTaskOutcome {
    Completed(CompanionTaskStatus),
    AlreadyCompleted(CompanionTaskStatus),
}

/// Input for terminally failing a leased companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailCompanionTask {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed companion fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailCompanionTaskOutcome {
    Failed(CompanionTaskStatus),
    AlreadyFailed(CompanionTaskStatus),
}

/// Input for requeuing a leased companion task after a retryable failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryCompanionTask {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}

/// Typed companion retry outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryCompanionTaskOutcome {
    Retried(CompanionTaskStatus),
}

fn companion_scope_dedupe_key(scope: &CompanionScope) -> String {
    match scope {
        CompanionScope::Neutral => "neutral".to_owned(),
        CompanionScope::Personal { person_ref } => format!("personal:{}", person_ref.to_hex()),
        CompanionScope::SharedVault { vault_id } => format!("shared_vault:{vault_id}"),
    }
}

fn companion_subject_dedupe_key(subject: &CompanionSubject) -> String {
    match subject {
        CompanionSubject::Person { person_ref } => format!("person:{}", person_ref.to_hex()),
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => format!(
            "relationship:{}:{}",
            source_ref.to_hex(),
            target_ref.to_hex()
        ),
    }
}
