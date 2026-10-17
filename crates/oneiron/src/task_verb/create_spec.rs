use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::task_type::TaskTypeRef;

use super::consult_payload::ConsultPayload;
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};

/// One TASK intent and the node-local realizing-attempt input chosen by the engine.
///
/// The four pre-ticket fields are the compatibility surface: every additive
/// field is optional, defaults to absent, and absent means the landed standard
/// Dreamer-realized task.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskCreateSpec {
    pub spec: Value,
    pub label: Option<String>,
    pub owner_ref: Option<EntityId>,
    pub now: Option<u64>,
    pub kind: Option<TaskKind>,
    pub consult: Option<ConsultPayload>,
    pub assignee: Option<TaskAssignee>,
    pub ttl: Option<TaskTtl>,
    /// OF-543: the one task-type stamp, placed once. Absent means the
    /// create path places it (unsure uses the root) — a landed TASK and
    /// its receipts always carry one; see [`Self::resolved_type_ref`].
    pub type_ref: Option<TaskTypeRef>,
    /// OF-220: a typed brief. A create that carries one, with its intent
    /// key, is a post and runs through the task highway.
    pub brief: Option<super::brief::QueueTaskBrief>,
    /// The caller's idempotency key for a briefed create.
    pub intent_key: Option<String>,
}

impl TaskCreateSpec {
    /// The pre-ticket construction surface, unchanged.
    #[must_use]
    pub const fn new(
        spec: Value,
        label: Option<String>,
        owner_ref: Option<EntityId>,
        now: Option<u64>,
    ) -> Self {
        Self {
            spec,
            label,
            owner_ref,
            now,
            kind: None,
            consult: None,
            assignee: None,
            ttl: None,
            type_ref: None,
            brief: None,
            intent_key: None,
        }
    }

    /// Makes this create a post: one typed brief under one intent key.
    #[must_use]
    pub fn with_brief(
        mut self,
        intent_key: impl Into<String>,
        brief: super::brief::QueueTaskBrief,
    ) -> Self {
        self.intent_key = Some(intent_key.into());
        self.brief = Some(brief);
        self
    }

    #[must_use]
    pub fn with_kind(mut self, kind: TaskKind) -> Self {
        self.kind = Some(kind);
        self
    }

    #[must_use]
    pub fn with_consult(mut self, consult: ConsultPayload) -> Self {
        self.consult = Some(consult);
        self
    }

    #[must_use]
    pub const fn with_assignee(mut self, assignee: TaskAssignee) -> Self {
        self.assignee = Some(assignee);
        self
    }

    #[must_use]
    pub const fn with_ttl(mut self, ttl: TaskTtl) -> Self {
        self.ttl = Some(ttl);
        self
    }

    #[must_use]
    pub fn with_type_ref(mut self, type_ref: TaskTypeRef) -> Self {
        self.type_ref = Some(type_ref);
        self
    }

    /// The stamp this task lands with: the caller's placed ref, else the
    /// root of the tree at `tree_version` (the unsure placement).
    #[must_use]
    pub fn resolved_type_ref(&self, tree_version: u64) -> TaskTypeRef {
        self.type_ref
            .clone()
            .unwrap_or_else(|| TaskTypeRef::root(tree_version))
    }
}

/// Per-actor create quota within one node-local time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCreateRateLimit {
    pub limit: usize,
    pub window_seconds: u64,
}

impl Default for TaskCreateRateLimit {
    fn default() -> Self {
        Self {
            limit: 10,
            window_seconds: 60,
        }
    }
}
