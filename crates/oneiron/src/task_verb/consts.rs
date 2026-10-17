//! Module-level constants shared across the task-verb files.
//!
//! Consumers: schema/subkind/realize + create/cancel predicates and gate
//! knobs — `create_facade`/`query_facade`; schema versions — `wire_decode`;
//! follow-up and peer-handle prefixes — `follow_up`; settle page —
//! `consult_fanout_facade`; rate prefix — `rate_limit`.

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
pub(super) const TASK_FOLLOW_UP_NAMESPACE: &str = "tasks.followup.v1";
/// The ONE-1699 follow-up stage.
pub const TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED: &str = "consult_expired";
/// Page size for the bounded TASK walk in [`Memory::settle_due_consults`](crate::memory::Memory::settle_due_consults).
pub(super) const CONSULT_SETTLE_PAGE: usize = 256;
pub(super) const TASK_CREATE_PROPOSAL_PREDICATE: &str = "tasks.create";
/// The stored predicate of a cancel proposal claim. It is a storage string, not
/// the verb's name: the verb is `cancel`, and renaming it moved no stored row.
pub(super) const TASK_CANCEL_PROPOSAL_PREDICATE: &str = "tasks.cancel";
pub(super) const TASK_CANCEL_GATE_CHANNEL: &str = "tasks";
/// Mode token a refused HARD cancel records on its proposal, so a reviewer can
/// tell an unauthorized force attempt from an ordinary cooperative one.
pub(super) const TASK_CANCEL_FORCE_MODE: &str = "force";
pub(super) const TASK_GATE_RECEIPT_SCAN_LIMIT: usize = 512;
/// The stored predicate of a brief-revision proposal (OF-220). It lands as the
/// TASK's next brief revision only through settlement, never on the write.
pub(super) const TASK_BRIEF_PROPOSAL_PREDICATE: &str = "tasks.brief";
/// The ATTEMPT queue label of one external try on a TASK (OF-220).
///
/// A queue label, like the `dreamer.*`/`coach.*` kinds, and NOT a
/// [`TaskKind`](super::TaskKind): the TASK stays `Standard`. It exists so no
/// engine runner's `claim_kind("tasks.realize")` can lease a released
/// external try.
pub(crate) const TASK_EXTERNAL_ATTEMPT_KIND: &str = "tasks.external";
/// The one schema of [`QueueTaskBrief`](super::QueueTaskBrief).
pub(super) const TASK_BRIEF_SCHEMA: u8 = 1;
/// Derived TASK id of an Auto post. Parts: actor, intent key. The store-local
/// vault id is left out on purpose: every replica of one vault holds its own,
/// and one post must name one TASK on all of them.
pub(super) const TASK_POST_ID_DOMAIN: &[u8] = b"oneiron.tasks.post.v1";
/// Derived TASK id of a settled create proposal. Parts: the proposal claim id.
pub(super) const TASK_SETTLE_ID_DOMAIN: &[u8] = b"oneiron.tasks.settle.v1";
/// The proposal-value key the highway's typed post stamp rides under.
pub(super) const TASK_POST_STAMP_KEY: &str = "post";
/// The stored predicate of the question an engine block asks a TASK's owner
/// (OF-220): its label text and the typed continuation the ask's settlement
/// runs on the TASK.
pub(super) const TASK_BLOCK_QUESTION_PREDICATE: &str = "tasks.block_question";
/// Derived id of a blocked TASK's question CLAIM. Parts: the ask group, so a
/// settlement finds its continuation from the group alone.
pub(super) const TASK_BLOCK_QUESTION_ID_DOMAIN: &[u8] = b"oneiron.tasks.block_question.v1";
