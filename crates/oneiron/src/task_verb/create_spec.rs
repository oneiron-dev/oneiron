use rmpv::Value;

use crate::entity_id::EntityId;

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
        }
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
}

/// Per-actor create quota within one node-local time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
