//! Module-level constants shared across the task-verb files.
//!
//! Consumers: schema/subkind/realize + create/cancel predicates and gate
//! knobs — `create_facade`/`query_facade`; schema versions — `wire_decode`;
//! follow-up and peer-handle prefixes — `follow_up`; settle page —
//! `consult_fanout_facade`; rate/owner prefixes — `rate_limit`.

/// Schema 2 adds the typed consult kind, the single `Option<TaskAssignee>`
/// wire field, the absolute TTL, the typed consult payload, and the one
/// execution-state/terminal register. Schema 1 rows stay readable: every added
/// key is optional and absent means the landed standard Dreamer-routed task.
pub(super) const TASK_VERB_BODY_SCHEMA_VERSION: u8 = 2;
pub(super) const TASK_VERB_BODY_SCHEMA_VERSIONS: [u8; 2] = [1, TASK_VERB_BODY_SCHEMA_VERSION];
pub(super) const TASK_VERB_BODY_SUBKIND: &str = "typed";
pub(super) const TASK_REALIZE_ATTEMPT_KIND: &str = "tasks.realize";
/// Shared task-follow-up idempotency namespace. ONE-1699 owns the
/// `consult_expired` stage; ONE-1708's human follow-up stages key the same way,
/// so one task never double-notifies across follow-up families.
pub(super) const TASK_FOLLOW_UP_KEY_PREFIX: &[u8] = b"tasks.followup.v1\0";
pub(super) const TASK_FOLLOW_UP_NAMESPACE: &str = "tasks.followup.v1";
/// The ONE-1699 follow-up stage.
pub const TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED: &str = "consult_expired";
/// Display-only peer handles, keyed by actor entity. Storage of the TASK
/// assignee stays actor-addressed; this table is read at projection time only.
pub(super) const PEER_HANDLE_KEY_PREFIX: &[u8] = b"tasks.peer.handle.v1\0";
/// Page size for the bounded TASK walk in [`MemoryFacade::settle_due_consults`](crate::facade::MemoryFacade::settle_due_consults).
pub(super) const CONSULT_SETTLE_PAGE: usize = 256;
pub(super) const TASK_CREATE_RATE_KEY_PREFIX: &[u8] = b"tasks.create.rate.v1\0";
pub(super) const TASK_CREATE_OWNER_KEY_PREFIX: &[u8] = b"tasks.create.owner.v1\0";
pub(super) const TASK_CREATE_PROPOSAL_PREDICATE: &str = "tasks.create";
pub(super) const TASK_CANCEL_PROPOSAL_PREDICATE: &str = "tasks.cancel";
pub(super) const TASK_CANCEL_GATE_CHANNEL: &str = "tasks";
pub(super) const TASK_GATE_RECEIPT_SCAN_LIMIT: usize = 512;
