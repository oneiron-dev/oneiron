//! Addressable scope asks: immutable membership, durable handles, and first-answer projection.

use super::ConsultPayloadRef;
use crate::consent::{ActionClass, ActionEnvelope};
use crate::entity_id::EntityId;

/// Selects a scope, never its authority holders. Holders come from live grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskAuthorityScope {
    pub class: ActionClass,
    pub envelope: ActionEnvelope,
}

/// A question is either addressed to one executor, or resolved to every
/// authority holder. There is no caller-picked authority holder allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAskTarget {
    Authority(AskAuthorityScope),
    Responder(super::TaskAssignee),
}

/// One asynchronous question. The intent key is local to the authenticated actor and device.
/// The returned handle, membership and results replicate; the creation retry
/// namespace is local, like the durable executor that emits the ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAskSpec {
    pub intent_key: String,
    pub target: TaskAskTarget,
    pub question_ref: ConsultPayloadRef,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub deadline_at: u64,
    pub label: Option<String>,
}

/// The group is an engine-authored TASK fact, not a local queue id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskAskHandle {
    pub group_ref: EntityId,
}

/// A typed explanation emitted at admission, without waiting for TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskAskHoldReason {
    /// Mailbox TASKs are queued, but no native delivery route is known now.
    NoLiveRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAskReceipt {
    pub handle: TaskAskHandle,
    pub task_refs: Vec<EntityId>,
    pub hold: Option<TaskAskHoldReason>,
    pub idempotent_replay: bool,
}

/// The winner does not replace any member's evidence or terminal register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskAskAnswer {
    pub task_ref: EntityId,
    pub actor_ref: EntityId,
    pub result_ref: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAskStatus {
    Pending {
        hold: Option<TaskAskHoldReason>,
    },
    Answered(TaskAskAnswer),
    /// All addressed tasks settled without an answer (including abstention).
    Exhausted,
}

/// This is a signal contract, not a blocking read or a polling loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAskWait {
    Ready(TaskAskStatus),
    Park(crate::code_run::SelfDurableWait),
}
