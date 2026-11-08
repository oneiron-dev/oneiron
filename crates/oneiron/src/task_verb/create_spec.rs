//! One TASK intent plus its node-local realizing-attempt input.
//! Entry [`TaskCreateSpec`]; consumed by `create_facade` and `create_validation`.
//! Owned by `task_verb`; additive fields stay optional for ticket compatibility.
use rmpv::Value;

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
    /// FIX685: the hook-chosen due/deadline stamp, Unix seconds. Absent
    /// means no due annotation. It is display metadata only: never TTL
    /// expiry, never a not-before wait, and it changes no dispatch, order,
    /// readiness, status or settlement behavior. Carried by briefless creates
    /// and briefed highway posts alike. A standard TASK that carries one is
    /// also a watcher (FIX 4749, ARCH-0080): it ticks once on `schedule.tick`
    /// after this time, while it is open; the tick is a hook event and
    /// changes none of the above, unless `watch` is set.
    pub due_at: Option<u64>,
    /// FIX 22121: a watch TASK (ARCH-0080 §4 Watchers). Its work is what the
    /// hooks on its `due_at` tick enqueue: its create queues no realizing
    /// attempt and dispatches nothing, and that tick settles it Done. It
    /// needs `due_at`, and no assignee or the Dreamer. False is an ordinary
    /// TASK.
    pub watch: bool,
    /// OF-543: the one task-type stamp, placed once. Absent means the
    /// create path places it (unsure uses the root) — a landed TASK and
    /// its receipts always carry one; see [`Self::resolved_type_ref`].
    pub type_ref: Option<TaskTypeRef>,
    /// OF-220: a typed brief. A create that carries one, with its intent
    /// key, is a post and runs through the task highway.
    pub brief: Option<super::brief::QueueTaskBrief>,
    /// The caller's idempotency key for a briefed create.
    pub intent_key: Option<String>,
    /// DOOR-113: the TASK this one files under, by one checked `ChildOf`
    /// edge its landing transaction writes. The nesting matrix decides, so
    /// a Task nests under a Milestone; absent is a root.
    pub parent_ref: Option<EntityId>,
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
            due_at: None,
            watch: false,
            type_ref: None,
            brief: None,
            intent_key: None,
            parent_ref: None,
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

    /// Stamps the due/deadline annotation (FIX685); a standard TASK with one
    /// ticks once on `schedule.tick` after it (FIX 4749).
    #[must_use]
    pub const fn with_due_at(mut self, due_at: u64) -> Self {
        self.due_at = Some(due_at);
        self
    }

    /// Makes this a watch TASK when `watch` is set (FIX 22121): no work at
    /// create, and its due tick settles it.
    #[must_use]
    pub const fn with_watch(mut self, watch: bool) -> Self {
        self.watch = watch;
        self
    }

    /// Files the TASK under `parent_ref` (DOOR-113).
    #[must_use]
    pub const fn with_parent_ref(mut self, parent_ref: EntityId) -> Self {
        self.parent_ref = Some(parent_ref);
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

pub use crate::gate::consult_fanout_values::TaskCreateRateLimit;
