//! Typed, actor-bound verbs over the Context Board TASKS section.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, EnqueueAttempt, EnqueueOutcome, InterveneAttempt,
};
use crate::batch::{
    ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    apply_ops_with_gate_mode,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::context_board::{
    JobPresence, TaskBoardStatus, TaskIntentPresence, TasksSection, ack_task_in_txn,
    cancel_task_in_txn, expand_task, fold_up_status, render_tasks_section, task_is_acked,
    task_is_cancelled,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::facade::{
    BRIDGE_OUTBOUND_ATTEMPT_KIND, FACADE_CODE_FORBIDDEN, FACADE_CODE_INVALID_STATE, FacadeError,
    FacadeResult, MemoryFacade, OutboundDraftInput, facade_provenance, verify_actor_binding,
};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles, PolicyApprovalCeiling, check_external_effect_policy,
    dispatched_agent_effective_ceiling, resolve_policy_manifest,
};
use crate::habit::TaskRole;
use crate::registry::{ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::run_tree::{RunTreeAdapter, RunTreeNode, RunTreeStatus};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{Vault, unix_seconds_now};

/// Schema 2 adds the typed consult kind, the single `Option<TaskAssignee>`
/// wire field, the absolute TTL, the typed consult payload, and the one
/// execution-state/terminal register. Schema 1 rows stay readable: every added
/// key is optional and absent means the landed standard Dreamer-routed task.
const TASK_VERB_BODY_SCHEMA_VERSION: u8 = 2;
const TASK_VERB_BODY_SCHEMA_VERSIONS: [u8; 2] = [1, TASK_VERB_BODY_SCHEMA_VERSION];
const TASK_VERB_BODY_SUBKIND: &str = "typed";
const TASK_REALIZE_ATTEMPT_KIND: &str = "tasks.realize";
/// Shared task-follow-up idempotency namespace. ONE-1699 owns the
/// `consult_expired` stage; ONE-1708's human follow-up stages key the same way,
/// so one task never double-notifies across follow-up families.
const TASK_FOLLOW_UP_KEY_PREFIX: &[u8] = b"tasks.followup.v1\0";
const TASK_FOLLOW_UP_NAMESPACE: &str = "tasks.followup.v1";
/// The ONE-1699 follow-up stage.
pub const TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED: &str = "consult_expired";
/// Display-only peer handles, keyed by actor entity. Storage of the TASK
/// assignee stays actor-addressed; this table is read at projection time only.
const PEER_HANDLE_KEY_PREFIX: &[u8] = b"tasks.peer.handle.v1\0";
/// Page size for the bounded TASK walk in [`MemoryFacade::settle_due_consults`].
const CONSULT_SETTLE_PAGE: usize = 256;
const TASK_CREATE_RATE_KEY_PREFIX: &[u8] = b"tasks.create.rate.v1\0";
const TASK_CREATE_OWNER_KEY_PREFIX: &[u8] = b"tasks.create.owner.v1\0";
const TASK_CREATE_PROPOSAL_PREDICATE: &str = "tasks.create";
const TASK_CANCEL_PROPOSAL_PREDICATE: &str = "tasks.cancel";
const TASK_CANCEL_GATE_CHANNEL: &str = "tasks";
const TASK_GATE_RECEIPT_SCAN_LIMIT: usize = 512;

/// Exact agent-visible TASKS verb family in protocol sort order.
pub const TASKS_VERBS: [&str; 5] = [
    "tasks.ack",
    "tasks.cancel",
    "tasks.check",
    "tasks.create",
    "tasks.expand",
];

/// The five typed verbs available over the TASKS section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TasksVerb {
    Ack,
    Cancel,
    Check,
    Create,
    Expand,
}

impl TasksVerb {
    /// All typed TASKS verbs in protocol sort order.
    pub const ALL: [Self; 5] = [
        Self::Ack,
        Self::Cancel,
        Self::Check,
        Self::Create,
        Self::Expand,
    ];

    /// Stable protocol identifier for this typed verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "tasks.ack",
            Self::Cancel => "tasks.cancel",
            Self::Check => "tasks.check",
            Self::Create => "tasks.create",
            Self::Expand => "tasks.expand",
        }
    }
}

/// Shape discriminator on the typed TASK body. Absent on a schema-v1 row,
/// where it means [`TaskKind::Standard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    Standard,
    Consult,
}

impl TaskKind {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Consult => "consult",
        }
    }

    fn from_token(token: &str) -> Result<Self> {
        match token {
            "standard" => Ok(Self::Standard),
            "consult" => Ok(Self::Consult),
            _ => Err(Error::InvalidTaskBody("tasks.body.kind")),
        }
    }
}

/// The single TASK assignee wire mint. ONE-1700 routes over this field and
/// ONE-1708 activates the `Human` arm; neither replaces the wire.
///
/// Identity is the ACTOR — the connection — never a vendor, harness, or machine
/// string. Two subscriptions of the same product under different config dirs
/// are two actors; the harness is a display label resolved at projection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskAssignee {
    Dreamer,
    AgentDef { agent_def_ref: EntityId },
    Peer { actor_ref: EntityId },
    Human { actor_ref: EntityId },
}

impl TaskAssignee {
    /// Stable wire token for the variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dreamer => "dreamer",
            Self::AgentDef { .. } => "agent_def",
            Self::Peer { .. } => "peer",
            Self::Human { .. } => "human",
        }
    }

    /// The addressed entity, or `None` for the local dreamer.
    #[must_use]
    pub const fn entity_ref(self) -> Option<EntityId> {
        match self {
            Self::Dreamer => None,
            Self::AgentDef { agent_def_ref } => Some(agent_def_ref),
            Self::Peer { actor_ref } | Self::Human { actor_ref } => Some(actor_ref),
        }
    }

    /// Binds the assignee to a resolved entity of the right kind. A dangling
    /// or mistyped assignee is refused here, before any write transaction.
    pub fn validate(&self, vault: &Vault) -> Result<()> {
        let Some(entity_ref) = self.entity_ref() else {
            return Ok(());
        };
        let stored = vault.get_entity_type(&entity_ref)?;
        let admitted = match self {
            // An agent definition is a typed row, so its kind is checkable.
            Self::AgentDef { .. } => stored == Some(crate::registry::ENTITY_TYPE_AGENT_DEF),
            // A peer/human actor is whatever kind the identity plane stores it
            // as (PERSON today); existence is the assertable invariant.
            Self::Dreamer | Self::Peer { .. } | Self::Human { .. } => stored.is_some(),
        };
        if admitted {
            Ok(())
        } else {
            Err(Error::EntityNotFound)
        }
    }
}

/// Absolute expiry instant. A relative duration would mean a different wall
/// time on every replica, so the caller's clock is resolved once, here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskTtl {
    pub deadline_at: u64,
}

impl TaskTtl {
    /// An already-absolute deadline.
    #[must_use]
    pub const fn at(deadline_at: u64) -> Self {
        Self { deadline_at }
    }

    /// Resolves `now + duration` to the stored absolute deadline.
    #[must_use]
    pub const fn after(now: u64, duration_seconds: u64) -> Self {
        Self {
            deadline_at: now.saturating_add(duration_seconds),
        }
    }
}

/// The only ref kinds a consult payload may carry. A consult asks ABOUT
/// durable state; it never transports the state itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsultPayloadRef {
    Claim(EntityId),
    Turn(EntityId),
}

impl ConsultPayloadRef {
    /// The referenced entity.
    #[must_use]
    pub const fn entity_ref(self) -> EntityId {
        match self {
            Self::Claim(entity_ref) | Self::Turn(entity_ref) => entity_ref,
        }
    }

    const fn entity_type(self) -> u8 {
        match self {
            Self::Claim(_) => crate::registry::ENTITY_TYPE_CLAIM,
            Self::Turn(_) => crate::registry::ENTITY_TYPE_TURN,
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Claim(_) => "cl",
            Self::Turn(_) => "tn",
        }
    }

    /// Canonical `cl_*` / `tn_*` rendering.
    #[must_use]
    pub fn short_ref(self) -> String {
        format!("{}_{}", self.prefix(), self.entity_ref().to_hex())
    }

    /// Parses one caller string into the typed enum and binds it to a RESOLVED
    /// entity of the matching kind. Unknown prefixes, malformed ids, and
    /// unresolved or mistyped targets are refused here — this is a shape
    /// guarantee established before persistence, not a scrubber run over
    /// arbitrary JSON afterwards.
    pub fn parse(vault: &Vault, value: &str) -> Result<Self> {
        let (prefix, hex) = value
            .split_once('_')
            .ok_or(Error::InvalidTaskBody("tasks.consult.ref"))?;
        let entity_ref =
            EntityId::from_hex(hex).map_err(|_| Error::InvalidTaskBody("tasks.consult.ref"))?;
        let parsed = match prefix {
            "cl" => Self::Claim(entity_ref),
            "tn" => Self::Turn(entity_ref),
            _ => return Err(Error::InvalidTaskBody("tasks.consult.ref")),
        };
        if vault.get_entity_type(&entity_ref)? != Some(parsed.entity_type()) {
            return Err(Error::InvalidTaskBody("tasks.consult.ref"));
        }
        Ok(parsed)
    }
}

/// The typed consult request. There is no arbitrary-`Value` door: a caller who
/// needs to ask about a large artifact persists it first and passes its ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultPayload {
    pub question_ref: ConsultPayloadRef,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub correlation_ref: EntityId,
}

impl ConsultPayload {
    /// Typed `cl_*`/`tn_*` entries carried by this payload.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        1 + self.context_refs.len()
    }

    /// Every carried ref is distinct. A repeated context ref (or a context ref
    /// that restates the question) is a caller bug the schema forbids, not a
    /// convenience to silently de-duplicate.
    fn validate(&self) -> Result<()> {
        let mut seen = HashSet::with_capacity(self.ref_count());
        seen.insert(self.question_ref);
        for context_ref in &self.context_refs {
            if !seen.insert(*context_ref) {
                return Err(Error::InvalidTaskBody("tasks.consult.duplicate_ref"));
            }
        }
        Ok(())
    }
}

/// Typed recovery choices offered with an expiry digest. The engine never
/// carries product copy: the consuming lens localizes "peer offline — try
/// another actor / nudge" from these tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultRecovery {
    RetryAssignee,
    NudgeAssignee,
    TryPeer(EntityId),
}

impl ConsultRecovery {
    /// Stable wire token for the choice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetryAssignee => "retry_assignee",
            Self::NudgeAssignee => "nudge_assignee",
            Self::TryPeer(_) => "try_peer",
        }
    }
}

/// Terminal outcomes for ANY executor. `Expired` (deadline passed) and
/// `Abandoned` (lease reclaimed / executor gone) stay distinct causes even
/// though both project onto the failed board lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskTerminalDisposition {
    Completed,
    Rejected,
    Failed,
    Expired,
    Abandoned,
    Cancelled,
}

impl TaskTerminalDisposition {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Abandoned => "abandoned",
            Self::Cancelled => "cancelled",
        }
    }

    fn from_token(token: &str) -> Result<Self> {
        match token {
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "abandoned" => Ok(Self::Abandoned),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Error::InvalidTaskBody("tasks.terminal.disposition")),
        }
    }
}

/// Maps a terminal disposition onto the existing five-value board axis.
/// `Expired` and `Abandoned` both read as failed; the exact cause survives
/// BESIDE the status, never folded into it.
#[must_use]
pub const fn board_status_for_disposition(
    disposition: TaskTerminalDisposition,
) -> TaskBoardStatus {
    match disposition {
        TaskTerminalDisposition::Completed => TaskBoardStatus::Done,
        TaskTerminalDisposition::Rejected
        | TaskTerminalDisposition::Failed
        | TaskTerminalDisposition::Expired
        | TaskTerminalDisposition::Abandoned
        | TaskTerminalDisposition::Cancelled => TaskBoardStatus::Failed,
    }
}

/// The small typed summary a terminal consult keeps for board projection and
/// resume logic. Evidence and abstention are mutually exclusive BY
/// CONSTRUCTION — there is no runtime field convention to violate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultSummary {
    Answer { evidence_refs: Vec<ConsultPayloadRef> },
    Abstained { reason_ref: ConsultPayloadRef },
}

/// Board-projected consult outcome: canonical short refs, never result bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultPresence {
    Answer {
        result_ref: String,
        evidence_ref_count: usize,
    },
    Abstained {
        result_ref: String,
        reason_ref: String,
    },
}

/// The ONE terminal register value. Disposition, `result_ref`, summary, and
/// `finished_at` merge atomically as this single value — never as independently
/// mergeable fields, which could otherwise converge to a record no replica ever
/// wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTerminalRecord {
    pub disposition: TaskTerminalDisposition,
    /// Compatibility decoders may read `None` from an old row; every new
    /// terminal transition writes `Some`.
    pub result_ref: Option<EntityId>,
    pub summary: Option<ConsultResultSummary>,
    pub finished_at: u64,
}

/// CRDT merge for the one terminal register. Later `finished_at` wins;
/// `Completed` dominates every other disposition on an exact tie (an answer
/// that landed at the deadline instant beats the expiry sweep); any remaining
/// tie falls to canonical serialized bytes so both replicas pick the same
/// winner in either merge order.
#[must_use]
pub fn merge_task_terminal_register(
    left: Option<&TaskTerminalRecord>,
    right: Option<&TaskTerminalRecord>,
) -> Option<TaskTerminalRecord> {
    match (left, right) {
        (None, None) => None,
        (Some(only), None) | (None, Some(only)) => Some(only.clone()),
        (Some(left), Some(right)) => Some(
            if terminal_register_order(left) >= terminal_register_order(right) {
                left.clone()
            } else {
                right.clone()
            },
        ),
    }
}

fn terminal_register_order(record: &TaskTerminalRecord) -> (u64, u8, Vec<u8>) {
    (
        record.finished_at,
        u8::from(record.disposition == TaskTerminalDisposition::Completed),
        canonical_bytes(&task_terminal_record_value(record)),
    )
}

/// Execution state of one TASK intent on this replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExecutionState {
    Queued,
    Working { started_at: u64 },
    /// Reserved for ONE-1888's consent-required ladder state.
    Interrupted,
    Terminal(TaskTerminalRecord),
}

impl TaskExecutionState {
    /// The terminal record, if this replica has settled the task.
    #[must_use]
    pub const fn terminal(&self) -> Option<&TaskTerminalRecord> {
        match self {
            Self::Terminal(record) => Some(record),
            Self::Queued | Self::Working { .. } | Self::Interrupted => None,
        }
    }
}

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

/// Result of one `tasks.create` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCreateReceipt {
    pub task_ref: Option<EntityId>,
    pub proposal_ref: Option<EntityId>,
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
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

    const fn ceiling(self) -> PolicyApprovalCeiling {
        match self {
            Self::Auto | Self::FullAccess => PolicyApprovalCeiling::Auto,
            Self::Manual => PolicyApprovalCeiling::Proposed,
        }
    }
}

/// Default ladder vocabulary for own-task and own-spawn cancellation.
pub const DEFAULT_TASK_CANCEL_MODE: TaskCancelMode = TaskCancelMode::Auto;

/// A TASK entity or agent-dispatch spawn addressed by `tasks.cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCancelTarget {
    Task(EntityId),
    Spawn(AttemptId),
}

/// Result of one `tasks.cancel` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCancelReceipt {
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
    pub proposal_ref: Option<EntityId>,
    pub gate_decision_ref: Option<String>,
    pub status: Option<RunTreeStatus>,
}

/// Result of persisting one render-tier task acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAckReceipt {
    pub task_ref: EntityId,
    pub acked: bool,
}

/// One peer answer landing on an existing consult TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultKind {
    Answer {
        result_ref: EntityId,
        evidence_refs: Vec<ConsultPayloadRef>,
    },
    Abstain {
        result_ref: EntityId,
        reason_ref: ConsultPayloadRef,
    },
}

impl ConsultResultKind {
    const fn result_ref(&self) -> EntityId {
        match self {
            Self::Answer { result_ref, .. } | Self::Abstain { result_ref, .. } => *result_ref,
        }
    }

    fn summary(&self) -> ConsultResultSummary {
        match self {
            Self::Answer { evidence_refs, .. } => ConsultResultSummary::Answer {
                evidence_refs: evidence_refs.clone(),
            },
            Self::Abstain { reason_ref, .. } => ConsultResultSummary::Abstained {
                reason_ref: *reason_ref,
            },
        }
    }

    /// Every typed ref this result carries, for resolution checks.
    fn carried_refs(&self) -> Vec<ConsultPayloadRef> {
        match self {
            Self::Answer { evidence_refs, .. } => evidence_refs.clone(),
            Self::Abstain { reason_ref, .. } => vec![*reason_ref],
        }
    }

    /// An answer carries at least one typed evidence ref; an abstention
    /// carries its durable reason by construction.
    fn validate(&self) -> Result<()> {
        match self {
            Self::Answer { evidence_refs, .. } => {
                if evidence_refs.is_empty() {
                    return Err(Error::InvalidTaskBody("tasks.consult.evidence"));
                }
                let mut seen = HashSet::with_capacity(evidence_refs.len());
                if evidence_refs.iter().any(|entry| !seen.insert(*entry)) {
                    return Err(Error::InvalidTaskBody("tasks.consult.duplicate_ref"));
                }
                Ok(())
            }
            Self::Abstain { .. } => Ok(()),
        }
    }
}

/// Input to [`MemoryFacade::land_consult_result`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultResultInput {
    pub kind: ConsultResultKind,
    pub completed_at: u64,
}

/// Receipt for one landed consult result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskResultReceipt {
    pub task_ref: EntityId,
    pub terminal: TaskTerminalRecord,
    pub idempotent_replay: bool,
}

/// One question addressed to N distinct peer actors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutSpec {
    pub question_ref: ConsultPayloadRef,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub assignees: Vec<EntityId>,
    pub deadline_at: u64,
    pub label: Option<String>,
}

/// Receipt for one fan-out: the shared correlation ref plus one task per peer,
/// in deterministic assignee order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutReceipt {
    pub correlation_ref: EntityId,
    pub task_refs: Vec<EntityId>,
}

/// Host-supplied addressing for the ARCH-0046 expiry digest, plus the typed
/// recovery choices the lens renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultDigestRoute {
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub on_behalf_of: Option<String>,
    pub recovery: Vec<ConsultRecovery>,
}

/// Outcome of one TTL reconciliation sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultExpiryReport {
    pub expired_task_refs: Vec<EntityId>,
    pub digest_intent_refs: Vec<String>,
    pub already_settled: usize,
}

#[derive(Debug, Clone, PartialEq)]
struct TaskVerbBody {
    role: u8,
    schema_version: u8,
    subkind: String,
    kind: Option<TaskKind>,
    owner_ref: String,
    assignee: Option<TaskAssignee>,
    label: Option<String>,
    spec: Value,
    consult: Option<ConsultPayload>,
    ttl: Option<TaskTtl>,
    state: Option<TaskExecutionState>,
    provenance: Value,
    created_at: u64,
}

impl TaskVerbBody {
    /// `None` is the schema-v1 compatibility representation of a standard task.
    const fn task_kind(&self) -> TaskKind {
        match self.kind {
            Some(kind) => kind,
            None => TaskKind::Standard,
        }
    }

    const fn terminal(&self) -> Option<&TaskTerminalRecord> {
        match &self.state {
            Some(state) => state.terminal(),
            None => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CancelTargetState {
    owned: bool,
    task_ref: Option<EntityId>,
    attempts: Vec<(AttemptId, AttemptState)>,
    proposal_subject: EntityId,
    target_ref: String,
}

impl MemoryFacade<'_> {
    /// Mints one TASK plus one linked realizing attempt when the actor's live
    /// definition/manifest ceiling permits Auto; otherwise parks one proposal.
    pub fn tasks_create(&self, spec: &TaskCreateSpec) -> FacadeResult<TaskCreateReceipt> {
        self.tasks_create_with_engine_rate_limit(spec, TaskCreateRateLimit::default())
    }

    /// Compatibility entry point whose quota arguments cannot override the
    /// engine-owned default.
    #[cfg(not(test))]
    pub fn tasks_create_with_rate_limit(
        &self,
        spec: &TaskCreateSpec,
        _rate_limit: TaskCreateRateLimit,
    ) -> FacadeResult<TaskCreateReceipt> {
        self.tasks_create(spec)
    }

    /// Crate-test seam for exercising exact quota boundaries.
    #[cfg(test)]
    pub(crate) fn tasks_create_with_rate_limit(
        &self,
        spec: &TaskCreateSpec,
        rate_limit: TaskCreateRateLimit,
    ) -> FacadeResult<TaskCreateReceipt> {
        self.tasks_create_with_engine_rate_limit(spec, rate_limit)
    }

    fn tasks_create_with_engine_rate_limit(
        &self,
        spec: &TaskCreateSpec,
        rate_limit: TaskCreateRateLimit,
    ) -> FacadeResult<TaskCreateReceipt> {
        let verb = task_verb_contract(TasksVerb::Create);
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = spec.now.unwrap_or_else(unix_seconds_now);
        let rate_now = unix_seconds_now();
        let provenance = facade_provenance(verb);
        // The typed shape is settled BEFORE any write transaction opens: an
        // invalid consult never reaches the TASK write, so a rejected request
        // leaves no partial entity and burns no rate slot.
        let validated = validate_task_create(self.vault(), spec, now)?;
        let direct = self.with_verified_actor_write_txn(|wtxn| {
            let ceiling =
                task_actor_ceiling(self.vault(), &*wtxn, self.actor(), self.actor_class())?;
            if ceiling != PolicyApprovalCeiling::Auto
                || !consume_create_rate_slot(
                    self.vault(),
                    wtxn,
                    self.actor(),
                    rate_now,
                    rate_limit,
                )?
            {
                return Ok(None);
            }

            let owner_ref = spec.owner_ref.unwrap_or_else(|| self.actor());
            let task_ref = self.mint_task_in_txn(
                wtxn,
                &validated,
                spec.label.clone(),
                owner_ref,
                &provenance,
                now,
            )?;
            if validated.kind == TaskKind::Standard {
                self.enqueue_task_realization_in_txn(wtxn, task_ref, &validated.spec, now)?;
            }
            Ok(Some(task_ref))
        })?;

        if let Some(task_ref) = direct {
            return Ok(TaskCreateReceipt {
                task_ref: Some(task_ref),
                proposal_ref: None,
                approval: ClaimApprovalStatus::Auto,
                effected: true,
            });
        }

        let (proposal_ref, _gate_decision_ref) = self.persist_task_proposal(
            TASK_CREATE_PROPOSAL_PREDICATE,
            task_create_proposal_value(spec, now),
            self.actor(),
            now,
            provenance,
        )?;
        Ok(TaskCreateReceipt {
            task_ref: None,
            proposal_ref: Some(proposal_ref),
            approval: ClaimApprovalStatus::Proposed,
            effected: false,
        })
    }

    /// Mints one TASK entity plus its create-time owner record.
    ///
    /// The realizing attempt is deliberately NOT part of this: a consult mints
    /// the CRDT-synced entity and nothing else, because a node-local lease can
    /// never reach a peer on another machine.
    fn mint_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        validated: &ValidatedTaskCreate,
        label: Option<String>,
        owner_ref: EntityId,
        provenance: &Value,
        now: u64,
    ) -> FacadeResult<EntityId> {
        let task_ref = EntityId::now();
        let body = encode_task_verb_body(TaskVerbBody {
            role: TaskRole::Task.role_byte(),
            schema_version: TASK_VERB_BODY_SCHEMA_VERSION,
            subkind: TASK_VERB_BODY_SUBKIND.to_owned(),
            kind: Some(validated.kind),
            owner_ref: owner_ref.to_hex(),
            assignee: validated.assignee,
            label,
            spec: validated.spec.clone(),
            consult: validated.consult.clone(),
            ttl: validated.ttl,
            state: Some(TaskExecutionState::Queued),
            provenance: provenance.clone(),
            created_at: now,
        })?;
        self.put_task_body_in_txn(wtxn, task_ref, &body, now)?;
        record_task_create_owner_in_txn(self.vault(), wtxn, task_ref, owner_ref)?;
        Ok(task_ref)
    }

    fn put_task_body_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        body: &[u8],
        now: u64,
    ) -> FacadeResult<()> {
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault()
            .batch_in()
            .put(&task_ref, ENTITY_TYPE_TASK, occurred, now, body)
            .apply(wtxn)?;
        Ok(())
    }

    /// The engine — never the agent — decides the realizing job. ONE-1700 turns
    /// this unconditional standard-path enqueue into an assignee match.
    fn enqueue_task_realization_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        spec: &Value,
        now: u64,
    ) -> FacadeResult<()> {
        let outcome = AttemptQueue::new(self.vault()).enqueue_with_task_ref_in_txn(
            wtxn,
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: encode_task_realization_input(spec)?,
                dedupe_key: None,
                run_id: None,
                now,
            },
            Some(task_ref.to_hex()),
        )?;
        let EnqueueOutcome::Enqueued(_) = outcome else {
            return Err(FacadeError::from(Error::InvariantViolation(
                "tasks.create.enqueue",
            )));
        };
        Ok(())
    }

    // ── consult delegation (ONE-1699) ───────────────────────────────────

    /// Lands one peer answer or abstention on the consult TASK it was addressed
    /// to. Engine-owned and outside the five agent-visible `tasks.*` verbs: the
    /// synced TASK is the single coordination object, so the result settles ON
    /// it rather than being cloned into a second synthetic task.
    pub fn land_consult_result(
        &self,
        task_ref: EntityId,
        input: &ConsultResultInput,
    ) -> FacadeResult<TaskResultReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        input.kind.validate()?;
        // Refs bind to resolved entities HERE, before the write transaction
        // opens — a read transaction cannot be nested inside a write one, and
        // a refusal must leave no partial state behind.
        require_resolved_entity(self.vault(), input.kind.result_ref())?;
        for carried_ref in input.kind.carried_refs() {
            require_resolved_payload_ref(self.vault(), carried_ref)?;
        }
        let landed = TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: Some(input.kind.result_ref()),
            summary: Some(input.kind.summary()),
            finished_at: input.completed_at,
        };

        let (terminal, idempotent_replay) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = consult_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            let Some(TaskAssignee::Peer { actor_ref }) = body.assignee else {
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "consult carries no peer assignee",
                    "Land results only on peer-addressed consults.",
                ));
            };
            // The ask is ADDRESSED. An answer from anyone else is not a late
            // answer, it is an unaddressed write.
            if actor_ref != self.actor() {
                return Err(consult_refusal(
                    FACADE_CODE_FORBIDDEN,
                    "only the addressed peer assignee may land this consult result",
                    "Land the result as the actor the consult is addressed to.",
                ));
            }
            // Local compare-and-set: one replica settles a task once. A
            // byte-identical replay is the network retrying rather than a
            // second result, so it reports the winner and mutates nothing.
            if let Some(existing) = body.terminal() {
                if *existing == landed {
                    return Ok((existing.clone(), true));
                }
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "consult is already terminal",
                    "Read the settled terminal record; a converged terminal task is immutable.",
                ));
            }
            body.state = Some(TaskExecutionState::Terminal(landed.clone()));
            let encoded = encode_task_verb_body(body)?;
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, input.completed_at)?;
            // ONE-1702 SEAM (own-task settlement → WAKE/CARRIER): this is the
            // producer call site for `mint_own_task_event` → `route_event`.
            // ONE-1702 has not landed on this base and owns both signatures and
            // every `context_board/stream.rs` edit, so the call is added on its
            // rebase; no oracle-only event injection substitutes for it.
            Ok((landed.clone(), false))
        })?;

        Ok(TaskResultReceipt {
            task_ref,
            terminal,
            idempotent_replay,
        })
    }

    /// Fans one question out to N distinct peer actors as N independent consult
    /// TASKs sharing one correlation ref. Each task has its own assignee,
    /// deadline, terminal state, and result. There is no consult budget: a
    /// missing budget never blocks consult creation.
    pub fn fan_out_consults(
        &self,
        input: &ConsultFanOutSpec,
    ) -> FacadeResult<ConsultFanOutReceipt> {
        let verb = task_verb_contract(TasksVerb::Create);
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = unix_seconds_now();
        let provenance = facade_provenance(verb);
        if input.assignees.is_empty() {
            return Err(FacadeError::bad_request(
                "a fan-out addresses at least one peer actor",
            ));
        }
        // Deterministic assignee order, and duplicates REFUSED rather than
        // collapsed: asking one peer twice under one correlation is a caller
        // bug whose silent de-duplication would return fewer tasks than asked.
        let mut assignees = input.assignees.clone();
        assignees.sort_unstable();
        if assignees.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FacadeError::bad_request(
                "fan-out assignees must be distinct peer actors",
            ));
        }
        let correlation_ref = EntityId::now();
        let validated = assignees
            .iter()
            .map(|actor_ref| {
                validate_task_create(
                    self.vault(),
                    &TaskCreateSpec::new(Value::Nil, input.label.clone(), None, Some(now))
                        .with_kind(TaskKind::Consult)
                        .with_consult(ConsultPayload {
                            question_ref: input.question_ref,
                            context_refs: input.context_refs.clone(),
                            correlation_ref,
                        })
                        .with_assignee(TaskAssignee::Peer {
                            actor_ref: *actor_ref,
                        })
                        .with_ttl(TaskTtl::at(input.deadline_at)),
                    now,
                )
            })
            .collect::<FacadeResult<Vec<_>>>()?;

        let rate_now = unix_seconds_now();
        let task_refs = self.with_verified_actor_write_txn(|wtxn| {
            let ceiling =
                task_actor_ceiling(self.vault(), &*wtxn, self.actor(), self.actor_class())?;
            if ceiling != PolicyApprovalCeiling::Auto {
                return Err(consult_refusal(
                    FACADE_CODE_FORBIDDEN,
                    "fan-out requires an auto-ceiling actor",
                    "Create the consults individually so each surfaces its own proposal.",
                ));
            }
            let mut task_refs = Vec::with_capacity(validated.len());
            for entry in &validated {
                // All-or-nothing: a quota refusal mid-fan-out aborts the whole
                // transaction rather than minting a silent subset.
                if !consume_create_rate_slot(
                    self.vault(),
                    wtxn,
                    self.actor(),
                    rate_now,
                    TaskCreateRateLimit::default(),
                )? {
                    return Err(consult_refusal(
                        FACADE_CODE_INVALID_STATE,
                        "fan-out exceeds the actor's create quota for this window",
                        "Retry the whole fan-out in the next window.",
                    ));
                }
                task_refs.push(self.mint_task_in_txn(
                    wtxn,
                    entry,
                    input.label.clone(),
                    self.actor(),
                    &provenance,
                    now,
                )?);
            }
            Ok(task_refs)
        })?;

        Ok(ConsultFanOutReceipt {
            correlation_ref,
            task_refs,
        })
    }

    /// Reconciles consults whose absolute deadline has passed: local
    /// compare-and-set to terminal `Expired` with a durable expiry artifact,
    /// then ONE ARCH-0046 digest per task through the existing outbound facade.
    ///
    /// Engine-owned; it never enters `TASKS_VERBS`. It walks TASK ids through
    /// the bounded `entities_by_type_page` primitive rather than adding another
    /// unpaged TASK scan, and it re-drives an already-expired task whose digest
    /// marker is absent — closing the crash window between terminalization and
    /// outbound scheduling.
    pub fn settle_due_consults(
        &self,
        now: u64,
        digest_route: &ConsultDigestRoute,
    ) -> FacadeResult<ConsultExpiryReport> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        // ARCH-0046 O3: a degrade is receipted WITH a way forward. A digest
        // carrying no recovery choice is a dead end, so it is refused here
        // rather than delivered as one.
        if digest_route.recovery.is_empty() {
            return Err(FacadeError::bad_request(
                "an expiry digest must carry at least one typed recovery choice",
            ));
        }
        for choice in &digest_route.recovery {
            if let ConsultRecovery::TryPeer(actor_ref) = choice {
                require_resolved_entity(self.vault(), *actor_ref)?;
            }
        }

        let mut report = ConsultExpiryReport {
            expired_task_refs: Vec::new(),
            digest_intent_refs: Vec::new(),
            already_settled: 0,
        };
        let mut undigested: Vec<(EntityId, EntityId)> = Vec::new();
        let mut cursor: Option<EntityId> = None;
        loop {
            let page = self
                .vault()
                .entities_by_type_page(ENTITY_TYPE_TASK, cursor.as_ref(), CONSULT_SETTLE_PAGE)?;
            let exhausted = page.len() < CONSULT_SETTLE_PAGE;
            cursor = page.last().copied();
            for task_ref in page {
                // One malformed body must not wedge the sweep for every other
                // consult — the same degrade `tasks.check` already applies.
                let Ok(Some(body)) = task_verb_body(self.vault(), task_ref) else {
                    continue;
                };
                if body.task_kind() != TaskKind::Consult {
                    continue;
                }
                let Some(ttl) = body.ttl else {
                    continue;
                };
                if ttl.deadline_at >= now {
                    continue;
                }
                match body.terminal() {
                    // Answered (or otherwise settled) before the deadline swept
                    // it: nothing is due.
                    Some(record) if record.disposition != TaskTerminalDisposition::Expired => {
                        continue;
                    }
                    Some(record) => {
                        let Some(result_ref) = record.result_ref else {
                            continue;
                        };
                        if task_follow_up_marker(
                            self.vault(),
                            task_ref,
                            TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED,
                        )? {
                            report.already_settled += 1;
                        } else {
                            undigested.push((task_ref, result_ref));
                        }
                    }
                    None => {
                        if let Some(result_ref) =
                            self.expire_consult_in_txn(task_ref, now, digest_route)?
                        {
                            report.expired_task_refs.push(task_ref);
                            undigested.push((task_ref, result_ref));
                        }
                    }
                }
            }
            if exhausted {
                break;
            }
        }

        for (task_ref, result_ref) in undigested {
            let key =
                task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED);
            let receipt = self.schedule_outbound(&OutboundDraftInput {
                verb: digest_route.verb.clone(),
                channel: digest_route.channel.clone(),
                target: digest_route.target.clone(),
                on_behalf_of: digest_route.on_behalf_of.clone(),
                // Outbound copy renders from typed state, never from prose
                // assembled here.
                content_ref: Some(result_ref.to_hex()),
                idempotency_key: Some(key.clone()),
                dedupe_key: Some(key),
                trigger: "gap_queue".to_owned(),
                trigger_ref: task_ref.to_hex(),
                job_ref: None,
                occurred_at: Some(now),
            })?;
            report.digest_intent_refs.push(receipt.intent_ref);
            // The marker lands AFTER the schedule, deliberately: a crash in
            // between leaves a marker-less expired task that the next sweep
            // re-drives, and the outbound idempotency key coalesces the retry.
            self.with_verified_actor_write_txn(|wtxn| {
                set_task_follow_up_marker_in_txn(
                    self.vault(),
                    wtxn,
                    task_ref,
                    TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED,
                )
                .map_err(FacadeError::from)
            })?;
        }
        Ok(report)
    }

    /// Compare-and-set one unanswered consult to terminal `Expired` and mint
    /// its durable expiry artifact in the same transaction. Returns `None` when
    /// the task settled between the page read and this write.
    fn expire_consult_in_txn(
        &self,
        task_ref: EntityId,
        now: u64,
        digest_route: &ConsultDigestRoute,
    ) -> FacadeResult<Option<EntityId>> {
        self.with_verified_actor_write_txn(|wtxn| {
            let mut body = consult_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            if body.terminal().is_some() {
                return Ok(None);
            }
            let result_ref = EntityId::now();
            let artifact = canonical_bytes(&consult_expiry_artifact_value(
                task_ref,
                body.ttl.map_or(now, |ttl| ttl.deadline_at),
                now,
                &digest_route.recovery,
            ));
            let occurred = TimeRange {
                start: now,
                end: now,
            };
            self.vault()
                .batch_in()
                .put(&result_ref, ENTITY_TYPE_TURN, occurred, now, &artifact)
                .apply(wtxn)?;
            body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
                disposition: TaskTerminalDisposition::Expired,
                result_ref: Some(result_ref),
                summary: None,
                finished_at: now,
            }));
            let encoded = encode_task_verb_body(body)?;
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, now)?;
            // ONE-1702 SEAM (own-task settlement → WAKE/CARRIER): second
            // producer call site for `mint_own_task_event` → `route_event`.
            // See `land_consult_result` for why it is not called on this base.
            Ok(Some(result_ref))
        })
    }

    /// Registers the DISPLAY handle for one peer actor. Board projections
    /// resolve handles through this table; TASK storage stays actor-addressed,
    /// so a renamed harness never rewrites a single consult row.
    pub fn register_peer_handle(&self, actor_ref: EntityId, handle: &str) -> FacadeResult<()> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        require_resolved_entity(self.vault(), actor_ref)?;
        self.with_verified_actor_write_txn(|wtxn| {
            self.vault()
                .store
                .vault_meta
                .put(wtxn, peer_handle_key(actor_ref).as_slice(), handle.as_bytes())
                .map_err(|err| FacadeError::from(Error::from(err)))
        })
    }

    /// Renders the current TASKS section through the existing board renderer.
    pub fn tasks_check(&self) -> FacadeResult<TasksSection> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Check));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (intents, bare_jobs) = task_presence(self.vault())?;
        Ok(render_tasks_section(&intents, &bare_jobs))
    }

    /// Expands one TASK intent through the existing Context Board projection.
    pub fn tasks_expand(&self, task_ref: EntityId) -> FacadeResult<Vec<String>> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Expand));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (intents, _) = task_presence(self.vault())?;
        let task_hex = task_ref.to_hex();
        let Some(intent) = intents.into_iter().find(|intent| intent.id == task_hex) else {
            return Err(FacadeError::from(Error::EntityNotFound));
        };
        // An acked failure has left the TASKS surface (`render_tasks_section`
        // drops it); the typed read verbs must agree, so it is not expandable
        // by id either.
        if intent.is_acked_failure() {
            return Err(FacadeError::from(Error::EntityNotFound));
        }
        Ok(expand_task(&intent))
    }

    /// Persists the free render-tier acknowledgement bit for one TASK.
    pub fn tasks_ack(&self, task_ref: EntityId) -> FacadeResult<TaskAckReceipt> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Ack));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        // Ack applies only to a currently-FAILED task: failed rows stay
        // surfaced until acked (08b §3). Acking a queued/running task would
        // pre-set the bit so the later failure is dropped from render and never
        // surfaced — so a non-failed ack is a no-op that leaves the bit unset.
        let (intents, _) = task_presence(self.vault())?;
        let task_hex = task_ref.to_hex();
        let Some(intent) = intents.into_iter().find(|intent| intent.id == task_hex) else {
            return Err(FacadeError::from(Error::EntityNotFound));
        };
        if intent.status != TaskBoardStatus::Failed {
            return Ok(TaskAckReceipt {
                task_ref,
                acked: intent.acked,
            });
        }
        self.with_verified_actor_write_txn(|wtxn| {
            ack_task_in_txn(self.vault(), wtxn, task_ref).map_err(FacadeError::from)
        })?;
        Ok(TaskAckReceipt {
            task_ref,
            acked: task_is_acked(self.vault(), task_ref)?,
        })
    }

    /// Cancels under the own-scoped `auto` default.
    pub fn tasks_cancel(&self, target: TaskCancelTarget) -> FacadeResult<TaskCancelReceipt> {
        self.tasks_cancel_with_mode(target, DEFAULT_TASK_CANCEL_MODE)
    }

    /// Cancels under one ladder vocabulary token. `auto` and `full-access`
    /// map to the existing Auto ceiling; `manual` maps to Proposed.
    pub fn tasks_cancel_with_mode(
        &self,
        target: TaskCancelTarget,
        mode: TaskCancelMode,
    ) -> FacadeResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let state = cancel_target_state(self.vault(), self.actor(), target)?;
        self.tasks_cancel_resolved(mode, state)
    }

    /// Crate-test seam: runs the cancel decision over a caller-supplied (and
    /// possibly deliberately stale) target snapshot, so the in-txn live-state
    /// re-read (P1-b) can be exercised without a mid-call injection point.
    #[cfg(test)]
    pub(crate) fn tasks_cancel_with_injected_state_for_test(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> FacadeResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        self.tasks_cancel_resolved(mode, state)
    }

    fn tasks_cancel_resolved(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> FacadeResult<TaskCancelReceipt> {
        let verb = task_verb_contract(TasksVerb::Cancel);
        let now = unix_seconds_now();
        let provenance = facade_provenance(verb);
        if !state.owned || mode.ceiling() == PolicyApprovalCeiling::Proposed {
            let (proposal_ref, gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(mode.as_str())),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref,
                status: None,
            });
        }

        let (gate_decision_ref, gate_outcome, effected, status) = self
            .with_verified_actor_write_txn(|wtxn| {
                let policy = resolve_policy_manifest(&self.vault().store, &*wtxn)?;
                let effect = ExternalEffectGateInput {
                    actor: GateActor {
                        actor_class: self.actor_class().gate_actor_class().to_owned(),
                        actor_ref: Some(self.actor().to_hex()),
                    },
                    provenance: GateProvenanceHandles {
                        actor_entity_ref: Some(self.actor()),
                        ..GateProvenanceHandles::default()
                    },
                    verb: verb.to_owned(),
                    channel: TASK_CANCEL_GATE_CHANNEL.to_owned(),
                    channel_identity_ref: None,
                    counterparty: None,
                    brief_ref: Some(state.target_ref.clone()),
                    send_ref: None,
                    standing_grant_ref: None,
                    scoped_mcp_call: None,
                    counterparty_first_touch: None,
                    counterparty_opted_out: false,
                    counterparty_opt_out_receipt_reason: None,
                    has_opted_in: true,
                    has_permission: true,
                    policy_risk: ExternalEffectPolicyRisk::Normal,
                };
                let (decision_id, decision, _charge) = check_external_effect_policy(
                    &self.vault().store,
                    wtxn,
                    &effect,
                    &policy,
                    false,
                )?;
                let decision_ref = format!("gate:{}", decision_id.to_hex());
                if decision.outcome() != GateOutcome::Allow {
                    return Ok((decision_ref, decision.outcome(), false, None));
                }

                // P1-b (TOCTOU): decide on transaction-current attempt state,
                // not the pre-txn snapshot. A `Leased`→`Queued` requeue (lease
                // cleanup / timeout) between the snapshot and this write txn
                // must be acted on as its live state; otherwise the now-Queued
                // attempt survives a "successful" cancel and stays claimable.
                let queue = AttemptQueue::new(self.vault());
                let live_attempts: Vec<(AttemptId, AttemptState)> = match state.task_ref {
                    // Membership TOCTOU: a retry mints a NEW row under the same
                    // `task_ref` and finalizes its source as `Failed`, so
                    // re-reading only the snapshotted IDS would see the dead
                    // source, report the task terminally failed, cancel
                    // nothing, and leave the live successor to run and send. A
                    // TASK target therefore re-derives its realizing SET here,
                    // reduced to retry-chain heads.
                    Some(task_ref) => {
                        let records =
                            queue.list_task_in_write_txn(&*wtxn, task_ref.to_hex().as_str())?;
                        let superseded = superseded_attempt_ids(&records);
                        records
                            .iter()
                            .filter(|record| !superseded.contains(&record.id))
                            .map(|record| (record.id, record.state))
                            .collect()
                    }
                    // A spawn realization carries no TASK backlink to re-derive
                    // membership from, so its single row is re-read by id.
                    None => {
                        let mut attempts = Vec::with_capacity(state.attempts.len());
                        for (attempt_id, snapshot_state) in &state.attempts {
                            match queue.get_in_write_txn(&*wtxn, *attempt_id)? {
                                Some(record) => attempts.push((*attempt_id, record.state)),
                                // Preserve an already-terminal spawn snapshot
                                // when the in-txn lookup cannot surface its
                                // row; terminal states cannot transition again.
                                None if matches!(
                                    snapshot_state,
                                    AttemptState::Completed
                                        | AttemptState::Failed
                                        | AttemptState::Cancelled
                                ) =>
                                {
                                    attempts.push((*attempt_id, *snapshot_state));
                                }
                                None => {}
                            }
                        }
                        attempts
                    }
                };

                // P1-a (leased-cancel honesty): a leased realization cannot be
                // stopped in this txn (`intervene` refuses a leased attempt) and
                // its local/outbound work keeps running. Report the honest
                // partial — do NOT hide the task and do NOT claim effect while a
                // live lease remains; the task stays VISIBLE (it folds to
                // Running under its live lease) until the lease releases. A
                // Queued+Leased mix is uneffected too: nothing is intervened and
                // nothing is hidden, so the receipt never conceals live work.
                if live_attempts
                    .iter()
                    .any(|(_, attempt_state)| *attempt_state == AttemptState::Leased)
                {
                    return Ok((
                        decision_ref,
                        decision.outcome(),
                        false,
                        Some(RunTreeStatus::Running),
                    ));
                }

                // A `Scheduled` retry is live work waiting on its instant: it
                // cancels exactly like a queued one. Omitting it would report
                // the task terminal off its failed source row while the next
                // try still ran and sent.
                let terminal_status = terminal_attempt_status(&live_attempts);
                if !live_attempts
                    .iter()
                    .any(|(_, attempt_state)| is_cancelable_attempt_state(*attempt_state))
                {
                    return Ok((decision_ref, decision.outcome(), false, terminal_status));
                }

                let mut cancelled_count = 0usize;
                for (attempt_id, attempt_state) in &live_attempts {
                    if !is_cancelable_attempt_state(*attempt_state) {
                        continue;
                    }
                    let outcome = queue.intervene_in_txn(
                        wtxn,
                        InterveneAttempt {
                            id: *attempt_id,
                            kind: AttemptInterventionKind::Cancel,
                            actor: self.actor().to_hex(),
                            note: None,
                            now,
                        },
                    )?;
                    match outcome.effect {
                        AttemptInterventionEffect::Cancelled => cancelled_count += 1,
                        AttemptInterventionEffect::AlreadyCancelled => {}
                        _ => {
                            return Err(FacadeError::from(Error::InvariantViolation(
                                "tasks.cancel.effect",
                            )));
                        }
                    }
                }
                if cancelled_count == 0 {
                    return Ok((decision_ref, decision.outcome(), false, terminal_status));
                }
                // A Completed/Failed sibling remains real terminal work. Keep
                // its TASK intent visible so the unchanged job stays folded
                // exactly once, and surface that aggregate terminal status
                // instead of claiming the whole target was cancelled.
                let preserved_terminal_status = terminal_status.filter(|status| {
                    matches!(status, RunTreeStatus::Completed | RunTreeStatus::Failed)
                });
                if preserved_terminal_status.is_none()
                    && let Some(task_ref) = state.task_ref
                {
                    cancel_task_in_txn(self.vault(), wtxn, task_ref)?;
                }
                Ok((
                    decision_ref,
                    decision.outcome(),
                    true,
                    preserved_terminal_status.or(Some(RunTreeStatus::Cancelled)),
                ))
            })?;

        if gate_outcome != GateOutcome::Allow {
            let (proposal_ref, _proposal_gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(mode.as_str())),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref: Some(gate_decision_ref),
                status: None,
            });
        }

        // Gate allowed. `effected` is honest: true only when at least one live
        // Queued/Paused realization was cancelled. A terminal sibling keeps the
        // task visible and owns the combined status; all-cancellable work is
        // hidden. A live lease or an all-terminal target remains uneffected.
        Ok(TaskCancelReceipt {
            approval: ClaimApprovalStatus::Auto,
            effected,
            proposal_ref: None,
            gate_decision_ref: Some(gate_decision_ref),
            status,
        })
    }

    fn persist_task_proposal(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
    ) -> FacadeResult<(EntityId, Option<String>)> {
        let proposal_ref = EntityId::now();
        let candidate = ClaimCandidate::new(
            predicate.to_owned(),
            ClaimSubject::Entity(subject),
            value,
            1.0,
        );
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor(), self.actor_class()),
            ClaimSource::ToolOutput,
            WriteProvenance::new(provenance)?,
            ClaimApprovalStatus::Proposed,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.with_verified_actor_write_txn(|wtxn| {
            apply_ops_with_gate_mode(
                &self.vault().store,
                &self.vault().config,
                &self.vault().analyzer,
                wtxn,
                vec![BatchOp::ClaimCandidate {
                    id: proposal_ref,
                    candidate: Box::new(candidate),
                    envelope,
                    occurred,
                    learned_at: now,
                    internal_lexical_query_hint: false,
                }],
                self.vault().text_index_trusted.load(Ordering::Acquire),
                ApplyOpsGateMode::new(true, true),
            )
            .map_err(FacadeError::from)
        })?;
        let gate_decision_ref = self
            .vault()
            .gate_decisions(TASK_GATE_RECEIPT_SCAN_LIMIT)?
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(proposal_ref.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex())
            .map(|record| format!("gate:{}", record.decision_id.to_hex()));
        Ok((proposal_ref, gate_decision_ref))
    }
}

fn task_verb_contract(verb: TasksVerb) -> &'static str {
    verb.as_str()
}

fn task_actor_ceiling(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<PolicyApprovalCeiling> {
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    let policy_projection = policy.actor_ceiling(
        actor_class.gate_actor_class(),
        Some(actor.to_hex().as_str()),
    );
    let definition = crate::gate::agent_definition_ceiling_for_actor(
        &vault.store,
        txn,
        WriteActor::new(actor, actor_class),
    );
    Ok(definition.map_or(policy_projection, |definition| {
        dispatched_agent_effective_ceiling(definition, policy_projection)
    }))
}

fn consume_create_rate_slot(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
    rate_limit: TaskCreateRateLimit,
) -> Result<bool> {
    let window_seconds = rate_limit.window_seconds.max(1);
    let window = now / window_seconds;
    // One node-local key per (actor, window_seconds), overwritten each window:
    // value = {window, count}. A stored window other than the current one
    // resets the count, so elapsed windows overwrite the same key instead of
    // leaving a per-window residue that grows unbounded over the vault's life.
    let key = task_create_rate_key(actor, window_seconds);
    let count = match vault.store.vault_meta.get(&*wtxn, key.as_slice())? {
        Some(raw) => {
            let stored: [u8; 16] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("tasks.create.rate"))?;
            let stored_window = u64::from_le_bytes(stored[..8].try_into().expect("rate window"));
            if stored_window == window {
                u64::from_le_bytes(stored[8..].try_into().expect("rate count"))
            } else {
                0
            }
        }
        None => 0,
    };
    if count >= rate_limit.limit as u64 {
        return Ok(false);
    }
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&window.to_le_bytes());
    value[8..].copy_from_slice(&count.saturating_add(1).to_le_bytes());
    vault.store.vault_meta.put(wtxn, key.as_slice(), &value)?;
    Ok(true)
}

fn task_create_rate_key(actor: EntityId, window_seconds: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        TASK_CREATE_RATE_KEY_PREFIX.len() + actor.as_bytes().len() + size_of::<u64>(),
    );
    key.extend_from_slice(TASK_CREATE_RATE_KEY_PREFIX);
    key.extend_from_slice(actor.as_bytes());
    key.extend_from_slice(&window_seconds.to_be_bytes());
    key
}

fn record_task_create_owner_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    owner_ref: EntityId,
) -> Result<()> {
    vault.store.vault_meta.put(
        wtxn,
        task_create_owner_key(task_ref).as_slice(),
        owner_ref.as_bytes(),
    )?;
    Ok(())
}

fn task_create_owner(vault: &Vault, task_ref: EntityId) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, task_create_owner_key(task_ref).as_slice())?
    else {
        return Ok(None);
    };
    let bytes: [u8; 16] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("tasks.create.owner"))?;
    EntityId::from_bytes(bytes).map(Some)
}

fn task_create_owner_key(task_ref: EntityId) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(TASK_CREATE_OWNER_KEY_PREFIX.len() + task_ref.as_bytes().len());
    key.extend_from_slice(TASK_CREATE_OWNER_KEY_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key
}

/// Serializes one rmpv value. Writing msgpack into a `Vec` cannot fail, so
/// this is the infallible canonical-bytes primitive the terminal-register
/// tiebreak and the body encoder both build on.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .expect("writing msgpack into a Vec is infallible");
    encoded
}

fn entity_ref_value(entity_ref: EntityId) -> Value {
    Value::from(entity_ref.to_hex())
}

fn task_assignee_value(assignee: TaskAssignee) -> Value {
    let mut entries = vec![(Value::from("kind"), Value::from(assignee.as_str()))];
    match assignee {
        TaskAssignee::Dreamer => {}
        TaskAssignee::AgentDef { agent_def_ref } => entries.push((
            Value::from("agent_def_ref"),
            entity_ref_value(agent_def_ref),
        )),
        TaskAssignee::Peer { actor_ref } | TaskAssignee::Human { actor_ref } => {
            entries.push((Value::from("actor_ref"), entity_ref_value(actor_ref)));
        }
    }
    Value::Map(entries)
}

fn consult_payload_ref_value(payload_ref: ConsultPayloadRef) -> Value {
    Value::Map(vec![
        (
            Value::from("kind"),
            Value::from(match payload_ref {
                ConsultPayloadRef::Claim(_) => "claim",
                ConsultPayloadRef::Turn(_) => "turn",
            }),
        ),
        (
            Value::from("entity_ref"),
            entity_ref_value(payload_ref.entity_ref()),
        ),
    ])
}

fn consult_payload_value(payload: &ConsultPayload) -> Value {
    Value::Map(vec![
        (
            Value::from("question_ref"),
            consult_payload_ref_value(payload.question_ref),
        ),
        (
            Value::from("context_refs"),
            Value::Array(
                payload
                    .context_refs
                    .iter()
                    .copied()
                    .map(consult_payload_ref_value)
                    .collect(),
            ),
        ),
        (
            Value::from("correlation_ref"),
            entity_ref_value(payload.correlation_ref),
        ),
    ])
}

fn consult_result_summary_value(summary: &ConsultResultSummary) -> Value {
    match summary {
        ConsultResultSummary::Answer { evidence_refs } => Value::Map(vec![
            (Value::from("outcome"), Value::from("answer")),
            (
                Value::from("evidence_refs"),
                Value::Array(
                    evidence_refs
                        .iter()
                        .copied()
                        .map(consult_payload_ref_value)
                        .collect(),
                ),
            ),
        ]),
        ConsultResultSummary::Abstained { reason_ref } => Value::Map(vec![
            (Value::from("outcome"), Value::from("abstained")),
            (
                Value::from("reason_ref"),
                consult_payload_ref_value(*reason_ref),
            ),
        ]),
    }
}

fn task_terminal_record_value(record: &TaskTerminalRecord) -> Value {
    Value::Map(vec![
        (
            Value::from("disposition"),
            Value::from(record.disposition.as_str()),
        ),
        (
            Value::from("result_ref"),
            record.result_ref.map_or(Value::Nil, entity_ref_value),
        ),
        (
            Value::from("summary"),
            record
                .summary
                .as_ref()
                .map_or(Value::Nil, consult_result_summary_value),
        ),
        (Value::from("finished_at"), Value::from(record.finished_at)),
    ])
}

fn task_execution_state_value(state: &TaskExecutionState) -> Value {
    match state {
        TaskExecutionState::Queued => {
            Value::Map(vec![(Value::from("state"), Value::from("queued"))])
        }
        TaskExecutionState::Working { started_at } => Value::Map(vec![
            (Value::from("state"), Value::from("working")),
            (Value::from("started_at"), Value::from(*started_at)),
        ]),
        TaskExecutionState::Interrupted => {
            Value::Map(vec![(Value::from("state"), Value::from("interrupted"))])
        }
        TaskExecutionState::Terminal(record) => Value::Map(vec![
            (Value::from("state"), Value::from("terminal")),
            (Value::from("terminal"), task_terminal_record_value(record)),
        ]),
    }
}

fn encode_task_verb_body(body: TaskVerbBody) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (Value::from("role"), Value::from(body.role)),
        (
            Value::from("schema_version"),
            Value::from(body.schema_version),
        ),
        (Value::from("subkind"), Value::from(body.subkind)),
        (
            Value::from("kind"),
            body.kind.map_or(Value::Nil, |kind| Value::from(kind.as_str())),
        ),
        (Value::from("owner_ref"), Value::from(body.owner_ref)),
        (
            Value::from("assignee"),
            body.assignee.map_or(Value::Nil, task_assignee_value),
        ),
        (
            Value::from("label"),
            body.label.map_or(Value::Nil, Value::from),
        ),
        (Value::from("spec"), body.spec),
        (
            Value::from("consult"),
            body.consult
                .as_ref()
                .map_or(Value::Nil, consult_payload_value),
        ),
        (
            Value::from("ttl"),
            body.ttl.map_or(Value::Nil, |ttl| {
                Value::Map(vec![(
                    Value::from("deadline_at"),
                    Value::from(ttl.deadline_at),
                )])
            }),
        ),
        (
            Value::from("state"),
            body.state
                .as_ref()
                .map_or(Value::Nil, task_execution_state_value),
        ),
        (Value::from("provenance"), body.provenance),
        (Value::from("created_at"), Value::from(body.created_at)),
    ]);
    Ok(canonical_bytes(&value))
}

fn encode_task_realization_input(spec: &Value) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, spec)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.spec"))?;
    Ok(payload)
}

fn task_verb_body(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskVerbBody>> {
    let rtxn = vault.store.env.read_txn()?;
    task_verb_body_in(vault, &rtxn, task_ref)
}

/// Transaction-scoped body read. The custody seal `get_raw` applies is not
/// needed here: a non-TASK type byte returns `None` two lines below, so a
/// SECRET_CUSTODY row can never be decoded through this door.
fn task_verb_body_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<TaskVerbBody>> {
    let Some(raw) = vault.get_raw_in(rtxn, &task_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("tasks.create.header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if !task_body_has_typed_subkind(body)? {
        return Ok(None);
    }
    let body = decode_task_verb_body(body)?;
    if !TASK_VERB_BODY_SCHEMA_VERSIONS.contains(&body.schema_version)
        || body.role != TaskRole::Task.role_byte()
    {
        return Err(Error::InvalidTaskBody("tasks.create.version"));
    }
    Ok(Some(body))
}

fn task_entity_role(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskRole>> {
    let Some(raw) = vault.get_raw(&task_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("tasks.role.header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    crate::habit::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn decode_task_verb_body(body: &[u8]) -> Result<TaskVerbBody> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    let byte = |key| {
        task_body_field(entries, key)?
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(Error::InvalidTaskBody("tasks.create.body"))
    };
    let string = |key| {
        task_body_field(entries, key)?
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::InvalidTaskBody("tasks.create.body"))
    };
    let label = match task_body_field(entries, "label")? {
        Value::Nil => None,
        value => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidTaskBody("tasks.create.body"))?,
        ),
    };
    let created_at = task_body_field(entries, "created_at")?
        .as_u64()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    Ok(TaskVerbBody {
        role: byte("role")?,
        schema_version: byte("schema_version")?,
        subkind: string("subkind")?,
        // A schema-v1 row carries none of the additive keys; absent decodes to
        // `None`, and `None` is the legacy standard/Dreamer-routed behavior.
        kind: task_body_optional(entries, "kind")?
            .map(|value| {
                value
                    .as_str()
                    .ok_or(Error::InvalidTaskBody("tasks.body.kind"))
                    .and_then(TaskKind::from_token)
            })
            .transpose()?,
        owner_ref: string("owner_ref")?,
        assignee: task_body_optional(entries, "assignee")?
            .map(decode_task_assignee)
            .transpose()?,
        label,
        spec: task_body_field(entries, "spec")?.clone(),
        consult: task_body_optional(entries, "consult")?
            .map(decode_consult_payload)
            .transpose()?,
        ttl: task_body_optional(entries, "ttl")?
            .map(|value| {
                let entries = value
                    .as_map()
                    .ok_or(Error::InvalidTaskBody("tasks.body.ttl"))?;
                task_body_field(entries, "deadline_at")?
                    .as_u64()
                    .map(TaskTtl::at)
                    .ok_or(Error::InvalidTaskBody("tasks.body.ttl"))
            })
            .transpose()?,
        state: task_body_optional(entries, "state")?
            .map(decode_task_execution_state)
            .transpose()?,
        provenance: task_body_field(entries, "provenance")?.clone(),
        created_at,
    })
}

/// Reads one additive body key. Absent (schema-v1 row) and explicitly `Nil`
/// both mean "not set"; a duplicated key is still a corrupt body.
fn task_body_optional<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<Option<&'a Value>> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    Ok(match value {
        Value::Nil => None,
        value => Some(value),
    })
}

fn decode_entity_ref(value: &Value, context: &'static str) -> Result<EntityId> {
    value
        .as_str()
        .ok_or(Error::InvalidTaskBody(context))
        .and_then(|hex| EntityId::from_hex(hex).map_err(|_| Error::InvalidTaskBody(context)))
}

fn decode_task_assignee(value: &Value) -> Result<TaskAssignee> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.assignee"))?;
    let kind = task_body_field(entries, "kind")?
        .as_str()
        .ok_or(Error::InvalidTaskBody("tasks.body.assignee"))?;
    match kind {
        "dreamer" => Ok(TaskAssignee::Dreamer),
        "agent_def" => Ok(TaskAssignee::AgentDef {
            agent_def_ref: decode_entity_ref(
                task_body_field(entries, "agent_def_ref")?,
                "tasks.body.assignee",
            )?,
        }),
        "peer" => Ok(TaskAssignee::Peer {
            actor_ref: decode_entity_ref(
                task_body_field(entries, "actor_ref")?,
                "tasks.body.assignee",
            )?,
        }),
        "human" => Ok(TaskAssignee::Human {
            actor_ref: decode_entity_ref(
                task_body_field(entries, "actor_ref")?,
                "tasks.body.assignee",
            )?,
        }),
        _ => Err(Error::InvalidTaskBody("tasks.body.assignee")),
    }
}

fn decode_consult_payload_ref(value: &Value) -> Result<ConsultPayloadRef> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.ref"))?;
    let entity_ref = decode_entity_ref(
        task_body_field(entries, "entity_ref")?,
        "tasks.consult.ref",
    )?;
    match task_body_field(entries, "kind")?.as_str() {
        Some("claim") => Ok(ConsultPayloadRef::Claim(entity_ref)),
        Some("turn") => Ok(ConsultPayloadRef::Turn(entity_ref)),
        _ => Err(Error::InvalidTaskBody("tasks.consult.ref")),
    }
}

fn decode_consult_payload(value: &Value) -> Result<ConsultPayload> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.consult"))?;
    let context_refs = task_body_field(entries, "context_refs")?
        .as_array()
        .ok_or(Error::InvalidTaskBody("tasks.body.consult"))?
        .iter()
        .map(decode_consult_payload_ref)
        .collect::<Result<Vec<_>>>()?;
    let payload = ConsultPayload {
        question_ref: decode_consult_payload_ref(task_body_field(entries, "question_ref")?)?,
        context_refs,
        correlation_ref: decode_entity_ref(
            task_body_field(entries, "correlation_ref")?,
            "tasks.body.consult",
        )?,
    };
    payload.validate()?;
    Ok(payload)
}

fn decode_consult_result_summary(value: &Value) -> Result<ConsultResultSummary> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.terminal.summary"))?;
    match task_body_field(entries, "outcome")?.as_str() {
        Some("answer") => Ok(ConsultResultSummary::Answer {
            evidence_refs: task_body_field(entries, "evidence_refs")?
                .as_array()
                .ok_or(Error::InvalidTaskBody("tasks.terminal.summary"))?
                .iter()
                .map(decode_consult_payload_ref)
                .collect::<Result<Vec<_>>>()?,
        }),
        Some("abstained") => Ok(ConsultResultSummary::Abstained {
            reason_ref: decode_consult_payload_ref(task_body_field(entries, "reason_ref")?)?,
        }),
        _ => Err(Error::InvalidTaskBody("tasks.terminal.summary")),
    }
}

fn decode_task_terminal_record(value: &Value) -> Result<TaskTerminalRecord> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.terminal"))?;
    Ok(TaskTerminalRecord {
        disposition: task_body_field(entries, "disposition")?
            .as_str()
            .ok_or(Error::InvalidTaskBody("tasks.terminal.disposition"))
            .and_then(TaskTerminalDisposition::from_token)?,
        result_ref: task_body_optional(entries, "result_ref")?
            .map(|value| decode_entity_ref(value, "tasks.body.terminal"))
            .transpose()?,
        summary: task_body_optional(entries, "summary")?
            .map(decode_consult_result_summary)
            .transpose()?,
        finished_at: task_body_field(entries, "finished_at")?
            .as_u64()
            .ok_or(Error::InvalidTaskBody("tasks.body.terminal"))?,
    })
}

fn decode_task_execution_state(value: &Value) -> Result<TaskExecutionState> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.state"))?;
    match task_body_field(entries, "state")?.as_str() {
        Some("queued") => Ok(TaskExecutionState::Queued),
        Some("working") => Ok(TaskExecutionState::Working {
            started_at: task_body_field(entries, "started_at")?
                .as_u64()
                .ok_or(Error::InvalidTaskBody("tasks.body.state"))?,
        }),
        Some("interrupted") => Ok(TaskExecutionState::Interrupted),
        Some("terminal") => Ok(TaskExecutionState::Terminal(decode_task_terminal_record(
            task_body_field(entries, "terminal")?,
        )?)),
        _ => Err(Error::InvalidTaskBody("tasks.body.state")),
    }
}

fn task_body_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let value = values
        .next()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    if values.next().is_some() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    Ok(value)
}

fn task_body_has_typed_subkind(body: &[u8]) -> Result<bool> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    let Some(entries) = value.as_map() else {
        return Ok(false);
    };
    Ok(entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("subkind"))
        .count()
        == 1
        && entries
            .iter()
            .filter(|(key, value)| {
                key.as_str() == Some("subkind") && value.as_str() == Some(TASK_VERB_BODY_SUBKIND)
            })
            .count()
            == 1)
}

fn task_create_proposal_value(spec: &TaskCreateSpec, now: u64) -> Value {
    Value::Map(vec![
        (Value::from("spec"), spec.spec.clone()),
        (
            Value::from("label"),
            spec.label.clone().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("owner_ref"),
            spec.owner_ref
                .map_or(Value::Nil, |owner| Value::from(owner.to_hex())),
        ),
        // The typed shape travels WITH the proposal: an approved consult
        // proposal must replay as a consult, never silently as a standard task.
        (
            Value::from("kind"),
            spec.kind
                .map_or(Value::Nil, |kind| Value::from(kind.as_str())),
        ),
        (
            Value::from("assignee"),
            spec.assignee.map_or(Value::Nil, task_assignee_value),
        ),
        (
            Value::from("consult"),
            spec.consult
                .as_ref()
                .map_or(Value::Nil, consult_payload_value),
        ),
        (
            Value::from("ttl"),
            spec.ttl.map_or(Value::Nil, |ttl| {
                Value::Map(vec![(
                    Value::from("deadline_at"),
                    Value::from(ttl.deadline_at),
                )])
            }),
        ),
        (Value::from("created_at"), Value::from(now)),
    ])
}

/// The settled typed shape of one `tasks.create`. Producing this value is the
/// only door to a TASK write, so an invalid combination can never reach one.
struct ValidatedTaskCreate {
    kind: TaskKind,
    assignee: Option<TaskAssignee>,
    consult: Option<ConsultPayload>,
    ttl: Option<TaskTtl>,
    spec: Value,
}

/// Settles `(kind, consult, assignee, ttl)` into one legal shape.
///
/// ONE-1699 admits exactly two branches: a peer-addressed consult with a typed
/// payload, a future deadline and a `Nil` spec; and the unchanged legacy
/// standard/Dreamer path. ONE-1700 owns generalizing the second branch into
/// full assignee routing — it is deliberately not pre-built here.
fn validate_task_create(
    vault: &Vault,
    spec: &TaskCreateSpec,
    now: u64,
) -> FacadeResult<ValidatedTaskCreate> {
    match (
        spec.kind.unwrap_or(TaskKind::Standard),
        &spec.consult,
        &spec.assignee,
        &spec.ttl,
    ) {
        (
            TaskKind::Consult,
            Some(payload),
            Some(assignee @ TaskAssignee::Peer { .. }),
            Some(ttl),
        ) if spec.spec == Value::Nil => {
            if ttl.deadline_at <= now {
                return Err(FacadeError::bad_request(
                    "a consult deadline must be in the future",
                ));
            }
            payload.validate()?;
            assignee.validate(vault)?;
            for payload_ref in std::iter::once(payload.question_ref)
                .chain(payload.context_refs.iter().copied())
            {
                require_resolved_payload_ref(vault, payload_ref)?;
            }
            Ok(ValidatedTaskCreate {
                kind: TaskKind::Consult,
                assignee: Some(*assignee),
                consult: Some(payload.clone()),
                ttl: Some(*ttl),
                spec: Value::Nil,
            })
        }
        (TaskKind::Standard, None, assignee @ (None | Some(TaskAssignee::Dreamer)), ttl) => {
            Ok(ValidatedTaskCreate {
                kind: TaskKind::Standard,
                assignee: *assignee,
                consult: None,
                ttl: *ttl,
                spec: spec.spec.clone(),
            })
        }
        _ => Err(FacadeError::bad_request("invalid typed task shape")),
    }
}

/// A typed ref must still name a live entity of its declared kind at write
/// time: `ConsultPayloadRef::parse` binds caller strings, but the enum can also
/// be constructed directly.
fn require_resolved_payload_ref(vault: &Vault, payload_ref: ConsultPayloadRef) -> FacadeResult<()> {
    if vault.get_entity_type(&payload_ref.entity_ref())? == Some(payload_ref.entity_type()) {
        Ok(())
    } else {
        Err(FacadeError::bad_request(
            "consult ref does not resolve to an entity of its declared kind",
        ))
    }
}

fn require_resolved_entity(vault: &Vault, entity_ref: EntityId) -> FacadeResult<()> {
    if vault.get_entity_type(&entity_ref)?.is_some() {
        Ok(())
    } else {
        Err(FacadeError::from(Error::EntityNotFound))
    }
}

/// `FacadeError::new` is private to the facade module and no `Error` variant
/// carries these refusals, so the typed shape is built from its public fields.
fn consult_refusal(code: &str, message: &str, suggestion: &str) -> FacadeError {
    FacadeError {
        code: code.to_owned(),
        message: message.to_owned(),
        suggestions: vec![suggestion.to_owned()],
        successor_short_id: None,
    }
}

/// Reads one TASK body as a consult inside a live transaction.
fn consult_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    let body = task_verb_body_in(vault, rtxn, task_ref)?
        .ok_or_else(|| FacadeError::from(Error::EntityNotFound))?;
    if body.task_kind() != TaskKind::Consult {
        return Err(FacadeError::bad_request("target task is not a consult"));
    }
    Ok(body)
}

/// Canonical outbound idempotency/dedupe key in the shared task-follow-up
/// namespace. ONE-1708's human follow-up stages key the same way, so one task
/// never double-notifies across follow-up families.
#[must_use]
pub fn task_follow_up_dedupe_key(task_ref: EntityId, stage: &str) -> String {
    format!(
        "{TASK_FOLLOW_UP_NAMESPACE}:{}:{stage}",
        task_ref.to_hex()
    )
}

fn task_follow_up_key(task_ref: EntityId, stage: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        TASK_FOLLOW_UP_KEY_PREFIX.len() + task_ref.as_bytes().len() + 1 + stage.len(),
    );
    key.extend_from_slice(TASK_FOLLOW_UP_KEY_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key.push(0);
    key.extend_from_slice(stage.as_bytes());
    key
}

fn task_follow_up_marker(vault: &Vault, task_ref: EntityId, stage: &str) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, task_follow_up_key(task_ref, stage).as_slice())?
        .is_some())
}

fn set_task_follow_up_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    stage: &str,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(wtxn, task_follow_up_key(task_ref, stage).as_slice(), &[1])?;
    Ok(())
}

fn peer_handle_key(actor_ref: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PEER_HANDLE_KEY_PREFIX.len() + actor_ref.as_bytes().len());
    key.extend_from_slice(PEER_HANDLE_KEY_PREFIX);
    key.extend_from_slice(actor_ref.as_bytes());
    key
}

fn peer_handle(vault: &Vault, actor_ref: EntityId) -> Result<Option<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, peer_handle_key(actor_ref).as_slice())?
    else {
        return Ok(None);
    };
    Ok(std::str::from_utf8(raw.as_ref()).ok().map(str::to_owned))
}

/// The durable expiry artifact. It carries TYPED recovery choices — the
/// consuming lens localizes the human sentence, so no product prose lives here.
fn consult_expiry_artifact_value(
    task_ref: EntityId,
    deadline_at: u64,
    expired_at: u64,
    recovery: &[ConsultRecovery],
) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("consult.expiry")),
        (Value::from("task_ref"), entity_ref_value(task_ref)),
        (Value::from("deadline_at"), Value::from(deadline_at)),
        (Value::from("expired_at"), Value::from(expired_at)),
        (
            Value::from("recovery"),
            Value::Array(
                recovery
                    .iter()
                    .copied()
                    .map(|choice| {
                        Value::Map(vec![
                            (Value::from("choice"), Value::from(choice.as_str())),
                            (
                                Value::from("actor_ref"),
                                match choice {
                                    ConsultRecovery::TryPeer(actor_ref) => {
                                        entity_ref_value(actor_ref)
                                    }
                                    ConsultRecovery::RetryAssignee
                                    | ConsultRecovery::NudgeAssignee => Value::Nil,
                                },
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// Decodes the typed recovery choices persisted on one expiry artifact.
pub fn decode_consult_expiry_recovery(artifact_body: &[u8]) -> Result<Vec<ConsultRecovery>> {
    let mut cursor = artifact_body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.consult.expiry"))?;
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.expiry"))?;
    task_body_field(entries, "recovery")?
        .as_array()
        .ok_or(Error::InvalidTaskBody("tasks.consult.expiry"))?
        .iter()
        .map(|entry| {
            let entry = entry
                .as_map()
                .ok_or(Error::InvalidTaskBody("tasks.consult.expiry"))?;
            match task_body_field(entry, "choice")?.as_str() {
                Some("retry_assignee") => Ok(ConsultRecovery::RetryAssignee),
                Some("nudge_assignee") => Ok(ConsultRecovery::NudgeAssignee),
                Some("try_peer") => Ok(ConsultRecovery::TryPeer(decode_entity_ref(
                    task_body_field(entry, "actor_ref")?,
                    "tasks.consult.expiry",
                )?)),
                _ => Err(Error::InvalidTaskBody("tasks.consult.expiry")),
            }
        })
        .collect()
}

fn task_presence(vault: &Vault) -> Result<(Vec<TaskIntentPresence>, Vec<JobPresence>)> {
    let records = AttemptQueue::new(vault).list()?;
    let task_refs_by_attempt: BTreeMap<String, Option<String>> = records
        .iter()
        .map(|record| (attempt_hex(record.id), record.task_ref.clone()))
        .collect();
    let superseded: HashSet<String> = superseded_attempt_ids(&records)
        .into_iter()
        .map(attempt_hex)
        .collect();
    let tree = RunTreeAdapter::new(vault).read()?;
    let mut nodes = Vec::new();
    collect_run_tree_nodes(&tree.roots, &mut nodes);
    let mut realizing_jobs: BTreeMap<String, Vec<JobPresence>> = BTreeMap::new();
    let mut bare_jobs = Vec::new();
    for node in nodes {
        // Only retry-chain HEADS reach the board: a superseded try is replaced
        // work whose successor owns the realization. The run tree keeps every
        // try — nested under the one it replaces — as the forensic surface.
        if superseded.contains(&node.attempt_id) {
            continue;
        }
        let Some(job) = JobPresence::from_run_tree_node(node) else {
            continue;
        };
        match task_refs_by_attempt.get(&node.attempt_id) {
            Some(Some(task_ref)) => realizing_jobs
                .entry(task_ref.clone())
                .or_default()
                .push(job),
            _ if node.worker_kind == BRIDGE_OUTBOUND_ATTEMPT_KIND => {}
            _ => bare_jobs.push(job),
        }
    }

    // Read-time clock: a consult past its deadline surfaces as expired from the
    // persisted deadline alone, so the failed row is never hidden behind
    // outbound (or reconciliation) availability.
    let now = unix_seconds_now();
    let mut intents = Vec::new();
    for task_ref in vault.entities_by_type(ENTITY_TYPE_TASK)? {
        if task_is_cancelled(vault, task_ref)? {
            continue;
        }
        let task_hex = task_ref.to_hex();
        let jobs = realizing_jobs.get(&task_hex).cloned().unwrap_or_default();
        let acked = task_is_acked(vault, task_ref)?;
        // P2 F8 (board poisoning): one malformed TASK body must not abort the
        // whole board. A body that decodes badly — e.g. a role byte carrying
        // `subkind:"typed"` but missing the typed fields — is skipped/degraded,
        // never propagated as a hard error that takes down `tasks.check`.
        match task_intent_presence(vault, task_ref, &task_hex, jobs, acked, now) {
            Ok(Some(intent)) => {
                realizing_jobs.remove(&task_hex);
                intents.push(intent);
            }
            Ok(None) => {}
            Err(_) => continue,
        }
    }

    // P2 F7 (dangling backlink): every live realizing job must render exactly
    // once. A backlink naming no surviving intent (deleted / malformed /
    // case-mismatched owner) is re-emitted as a bare job instead of vanishing.
    bare_jobs.extend(realizing_jobs.into_values().flatten());

    Ok((intents, bare_jobs))
}

/// Projects one surviving (non-cancelled) TASK entity into its board intent
/// row, or `None` when the entity is not a board-visible TASK. Returns an error
/// only for that single entity; `task_presence` degrades one bad entity into a
/// skip so the whole board survives (P2 F8).
fn task_intent_presence(
    vault: &Vault,
    task_ref: EntityId,
    task_hex: &str,
    jobs: Vec<JobPresence>,
    acked: bool,
    now: u64,
) -> Result<Option<TaskIntentPresence>> {
    if let Some(task) = task_verb_body(vault, task_ref)? {
        let terminal = task.terminal().cloned();
        let (status, terminal_disposition) = match (&terminal, task.ttl) {
            (Some(record), _) => (
                board_status_for_disposition(record.disposition),
                Some(record.disposition),
            ),
            // Derived, not stored: the deadline alone makes the row expired,
            // whether or not the reconciliation sweep has run yet.
            (None, Some(ttl)) if ttl.deadline_at < now => (
                TaskBoardStatus::Failed,
                Some(TaskTerminalDisposition::Expired),
            ),
            _ => (
                fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued),
                None,
            ),
        };
        let kind = task.task_kind();
        let mut presence =
            TaskIntentPresence::new(task_hex.to_owned(), status, task.label, acked, jobs);
        presence.kind = Some(kind);
        // Display only. The row resolves a handle, storage keeps the actor ref;
        // an unregistered actor renders as its own id rather than as a guess.
        presence.assignee = task
            .assignee
            .and_then(TaskAssignee::entity_ref)
            .map(|actor_ref| {
                peer_handle(vault, actor_ref)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| actor_ref.to_hex())
            });
        presence.terminal_disposition = terminal_disposition;
        presence.result_ref = terminal
            .as_ref()
            .and_then(|record| record.result_ref)
            .map(|result_ref| result_ref.to_hex());
        presence.consult_result = terminal.as_ref().and_then(consult_result_presence);
        return Ok(Some(presence));
    }
    if let Some(task) = vault.connector_send_task(&task_ref)? {
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Scheduled);
        return Ok(Some(TaskIntentPresence::from_connector_send_task_with_ack(
            &task, status, jobs, acked,
        )));
    }
    // P2 F6 (role fold): only the `Task` role folds into the TASKS section.
    // Goal / Milestone / Habit / HabitCheckin roles are not tasks and must not
    // render as TASKS rows (nor enter the cancel fallback below).
    if matches!(task_entity_role(vault, task_ref)?, Some(TaskRole::Task)) {
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued);
        return Ok(Some(TaskIntentPresence::new(
            task_hex.to_owned(),
            status,
            None,
            acked,
            jobs,
        )));
    }
    Ok(None)
}

/// Projects the terminal register's small typed summary. Refs only — a result
/// BODY never reaches a one-line board row.
fn consult_result_presence(record: &TaskTerminalRecord) -> Option<ConsultResultPresence> {
    let result_ref = record.result_ref?.to_hex();
    match record.summary.as_ref()? {
        ConsultResultSummary::Answer { evidence_refs } => Some(ConsultResultPresence::Answer {
            result_ref,
            evidence_ref_count: evidence_refs.len(),
        }),
        ConsultResultSummary::Abstained { reason_ref } => Some(ConsultResultPresence::Abstained {
            result_ref,
            reason_ref: reason_ref.short_ref(),
        }),
    }
}

fn collect_run_tree_nodes<'a>(nodes: &'a [RunTreeNode], out: &mut Vec<&'a RunTreeNode>) {
    for node in nodes {
        out.push(node);
        collect_run_tree_nodes(&node.children, out);
    }
}

fn cancel_target_state(
    vault: &Vault,
    actor: EntityId,
    target: TaskCancelTarget,
) -> FacadeResult<CancelTargetState> {
    match target {
        TaskCancelTarget::Task(task_ref) => {
            let task_hex = task_ref.to_hex();
            let owned = if task_verb_body(vault, task_ref)?.is_some() {
                // The typed body is mutable storage and its `owner_ref` is not
                // authority. Only the owner record stamped atomically by the
                // verified `tasks.create` path proves direct-cancel ownership;
                // typed bodies from any other write door fail closed.
                task_create_owner(vault, task_ref)? == Some(actor)
            } else if let Some(task) = vault.connector_send_task(&task_ref)? {
                task.actor_ref == actor
            } else if matches!(task_entity_role(vault, task_ref)?, Some(TaskRole::Task)) {
                // P1-c (role-only ownership): a role-only TASK carries no stored
                // owner/author provenance (ONE-1695 role bodies are `{role}`
                // only, and no header / side-index / ledger records the author
                // of a raw TASK put). Ownership therefore cannot be established,
                // so fail CLOSED to the foreign ladder (propose-only) rather
                // than vacuously trusting the caller — no principal may directly
                // cancel another's role-only task. Visibility (fix-r1 F6) is
                // unaffected: role-only Tasks still render in `tasks.check` and
                // remain cancellable via a proposal. (F6 also narrows this
                // fallback to `Task`; Goal/Milestone/Habit/HabitCheckin ids are
                // not TASKS and fall through to `EntityNotFound`.)
                false
            } else {
                return Err(FacadeError::from(Error::EntityNotFound));
            };
            let attempts = AttemptQueue::new(vault)
                .list()?
                .into_iter()
                .filter(|attempt| attempt.task_ref.as_deref() == Some(task_hex.as_str()))
                .map(|attempt| (attempt.id, attempt.state))
                .collect();
            Ok(CancelTargetState {
                owned,
                task_ref: Some(task_ref),
                attempts,
                proposal_subject: task_ref,
                target_ref: task_hex,
            })
        }
        TaskCancelTarget::Spawn(attempt_ref) => {
            let queue = AttemptQueue::new(vault);
            let child = queue
                .get(attempt_ref)?
                .ok_or_else(|| FacadeError::from(Error::EntityNotFound))?;
            let child_payload = decode_dreamer_attempt_payload(&child.payload)?;
            let owned = if child.kind == DREAMER_RUNNER_ATTEMPT_KIND
                && child_payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE
            {
                child_payload
                    .parent_attempt
                    .and_then(|parent_ref| queue.get(parent_ref).ok().flatten())
                    .and_then(|parent| decode_dreamer_attempt_payload(&parent.payload).ok())
                    .filter(|parent| parent.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
                    .and_then(|parent| decode_agent_dispatch_input(&parent.input).ok())
                    .is_some_and(|parent| agent_dispatch_actor(&parent).entity_ref() == actor)
            } else {
                false
            };
            Ok(CancelTargetState {
                owned,
                task_ref: None,
                attempts: vec![(attempt_ref, child.state)],
                proposal_subject: actor,
                target_ref: attempt_hex(attempt_ref),
            })
        }
    }
}

fn attempt_hex(attempt_id: AttemptId) -> String {
    let mut out = String::with_capacity(32);
    for byte in attempt_id.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("fmt::Write for String is infallible");
    }
    out
}

/// Attempt ids replaced by a later try.
///
/// A retry mints a NEW row and leaves its source terminally `Failed`, so the
/// rows behind one TASK are a forest of retry CHAINS, not a set of peers. Only
/// chain HEADS — rows no later try replaces — are live realizations; deciding
/// over every row decides over superseded history instead. Any-row status
/// precedence would fold a held retry up as `Failed` rather than `Scheduled`
/// and would keep folding a chain that later SUCCEEDED up as `Failed` forever,
/// and a cancel would rule against a dead source while its live successor
/// still runs and sends.
fn superseded_attempt_ids(records: &[AttemptRecord]) -> HashSet<AttemptId> {
    records
        .iter()
        .filter_map(|record| record.retry_of)
        .collect()
}

/// Pre-lease states a task cancel can still stop in its own transaction.
fn is_cancelable_attempt_state(state: AttemptState) -> bool {
    matches!(
        state,
        AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled
    )
}

fn terminal_attempt_status(attempts: &[(AttemptId, AttemptState)]) -> Option<RunTreeStatus> {
    if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Failed)
    {
        Some(RunTreeStatus::Failed)
    } else if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Completed)
    {
        Some(RunTreeStatus::Completed)
    } else if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Cancelled)
    {
        Some(RunTreeStatus::Cancelled)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_dispatch::{
        AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
    };
    use crate::attempt_queue::{
        ClaimAttempt, ClaimOutcome, CompleteAttempt, FailAttempt, RetryAttempt, RetryOutcome,
    };
    use crate::config::VaultConfig;
    use crate::facade::OutboundDraftInput;
    use crate::genui::{GrantMintIntent, GrantMintIntentScope};
    use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    fn put_person(vault: &Vault, id: EntityId) {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"actor",
            )
            .expect("put actor");
    }

    fn own_agent(vault: &Vault) -> EntityId {
        let actor = EntityId::from_bytes([0xE1; 16]).expect("actor id");
        put_person(vault, actor);
        actor
    }

    fn grant_cancel(vault: &Vault, actor: EntityId, seed: u8) {
        let grant_ref = EntityId::from_bytes([seed; 16]).expect("grant id");
        vault
            .mint_standing_outbound_grant(
                &grant_ref,
                &GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "cancel".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: TasksVerb::Cancel.as_str().to_owned(),
                    },
                },
                1,
            )
            .expect("mint cancel grant");
    }

    fn spec(now: u64) -> TaskCreateSpec {
        TaskCreateSpec {
            spec: Value::from("unit-task"),
            label: None,
            owner_ref: None,
            now: Some(now),
        }
    }

    fn assert_queued_terminal_mix_cancel(
        terminal_state: AttemptState,
        expected_receipt_status: RunTreeStatus,
        expected_board_status: TaskBoardStatus,
    ) {
        assert!(matches!(
            terminal_state,
            AttemptState::Completed | AttemptState::Failed
        ));
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xDA);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        let terminal = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "terminal-mix-worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim terminal realization")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("terminal realization must be claimable"),
        };
        let queued = match queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 121,
                },
                Some(task_hex.clone()),
            )
            .expect("enqueue live sibling")
        {
            EnqueueOutcome::Enqueued(queued) => queued,
            EnqueueOutcome::Existing(_) => panic!("live sibling must be fresh"),
        };
        match terminal_state {
            AttemptState::Completed => {
                queue
                    .complete(CompleteAttempt {
                        id: terminal.id,
                        lease_owner: "terminal-mix-worker".to_owned(),
                        attempt_count: terminal.attempt_count,
                        now: 122,
                    })
                    .expect("complete terminal sibling");
            }
            AttemptState::Failed => {
                queue
                    .fail(FailAttempt {
                        id: terminal.id,
                        lease_owner: "terminal-mix-worker".to_owned(),
                        attempt_count: terminal.attempt_count,
                        reason: "terminal mix failure".to_owned(),
                        now: 122,
                    })
                    .expect("fail terminal sibling");
            }
            _ => unreachable!("helper accepts only completed or failed states"),
        }

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel live sibling");
        let records = queue.list().expect("list attempts after cancel");
        let terminal_after = queue
            .get(terminal.id)
            .expect("read terminal sibling")
            .expect("terminal sibling exists");
        let queued_after = queue
            .get(queued.id)
            .expect("read cancelled sibling")
            .expect("cancelled sibling exists");
        let section = facade.tasks_check().expect("check mixed task");
        let terminal_hex = attempt_hex(terminal.id);
        let queued_hex = attempt_hex(queued.id);

        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
        assert_eq!(cancel.status, Some(expected_receipt_status));
        assert_eq!(terminal_after.state, terminal_state);
        assert_eq!(queued_after.state, AttemptState::Cancelled);
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.task_ref.as_deref() == Some(task_hex.as_str())
                        && record.state == terminal_state
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.task_ref.as_deref() == Some(task_hex.as_str())
                        && record.state == AttemptState::Cancelled
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
                .count(),
            2
        );
        assert_eq!(
            section.rows.iter().filter(|row| row.id == task_hex).count(),
            1
        );
        let task_row = section
            .rows
            .iter()
            .find(|row| row.id == task_hex)
            .expect("mixed task row");
        assert_eq!(task_row.status, expected_board_status);
        assert_eq!(task_row.folded_job_count, 1);
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == terminal_hex)
                .count(),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == queued_hex)
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }

    #[test]
    fn verb_family_is_exactly_five_without_queue_verbs() {
        let verbs = TasksVerb::ALL.map(TasksVerb::as_str);
        assert_eq!(verbs.len(), 5);
        assert_eq!(verbs, TASKS_VERBS);
        assert_eq!(
            verbs
                .iter()
                .filter(|verb| verb.contains("queue") || verb.contains("lease"))
                .count(),
            0
        );
    }

    #[test]
    fn own_create_effects_and_foreign_create_proposes() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let foreign = EntityId::from_bytes([0xE2; 16]).expect("foreign id");
        put_person(&vault, foreign);
        let rate = TaskCreateRateLimit {
            limit: 10,
            window_seconds: 60,
        };

        let own_result = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create_with_rate_limit(&spec(120), rate)
            .expect("own create");
        let foreign_result = vault
            .memory_facade(foreign, EdgeActorClass::Agent)
            .tasks_create_with_rate_limit(&spec(120), rate)
            .expect("foreign create");

        assert_eq!(usize::from(own_result.effected), 1);
        assert_eq!(own_result.approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(own_result.proposal_ref.is_some()), 0);
        assert_eq!(usize::from(foreign_result.effected), 0);
        assert_eq!(foreign_result.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(foreign_result.proposal_ref.is_some()), 1);
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .len(),
            1
        );
    }

    #[test]
    fn rate_limit_effects_n_and_proposes_every_overflow() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let limit = 3;
        let attempted = 5;
        // The rate window is keyed on the ENGINE clock (`unix_seconds_now()`,
        // not caller time — the codex-r1 anti-bypass fix). A single window here
        // keeps the overflow behavior deterministic: with a finite window these
        // creates could straddle a wall-clock boundary under load and reset the
        // count mid-loop. (Window advancement is covered separately by
        // `create_rate_slot_overwrites_one_key_across_windows`.)
        let rate = TaskCreateRateLimit {
            limit,
            window_seconds: u64::MAX,
        };
        let mut results = Vec::new();
        for _ in 0..attempted {
            results.push(
                facade
                    .tasks_create_with_rate_limit(&spec(120), rate)
                    .expect("create"),
            );
        }

        assert_eq!(usize::from(results[limit - 1].effected), 1);
        assert_eq!(results[limit - 1].approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(results[limit - 1].proposal_ref.is_some()), 0);
        assert_eq!(usize::from(results[limit].effected), 0);
        assert_eq!(results[limit].approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(results[limit].proposal_ref.is_some()), 1);
        assert_eq!(
            results.iter().filter(|result| result.effected).count(),
            limit
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.proposal_ref.is_some())
                .count(),
            attempted - limit
        );
    }

    #[test]
    fn create_rate_slot_overwrites_one_key_across_windows() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let rate = TaskCreateRateLimit {
            limit: 2,
            window_seconds: 10,
        };
        {
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            // Window 0 (now 0..9): two slots, then the third is refused.
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 0, rate).expect("w0 s1"));
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 3, rate).expect("w0 s2"));
            assert!(!consume_create_rate_slot(&vault, &mut wtxn, own, 9, rate).expect("w0 over"));
            // Window 1 (now 10..): the count resets, a slot is available again.
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 10, rate).expect("w1 s1"));
            // Window 2 (now 20..): still resets, still the same single key.
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 20, rate).expect("w2 s1"));
            wtxn.commit().expect("commit");
        }
        // Elapsed windows overwrite the SAME key: exactly one rate key persists
        // for this (actor, window_seconds), not one row per elapsed window.
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let keys = vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, TASK_CREATE_RATE_KEY_PREFIX)
            .expect("rate prefix iter")
            .count();
        assert_eq!(keys, 1);
    }

    #[test]
    fn caller_time_variation_does_not_bypass_one_engine_rate_window() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let limit = 3;
        let rate = TaskCreateRateLimit {
            limit,
            window_seconds: u64::MAX,
        };
        let caller_times = [0, 60, 120, 180];
        let results = caller_times.map(|now| {
            facade
                .tasks_create_with_rate_limit(&spec(now), rate)
                .expect("create")
        });

        assert_eq!(
            results.iter().filter(|result| result.effected).count(),
            limit
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.approval == ClaimApprovalStatus::Proposed)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.proposal_ref.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn cancel_ladder_is_own_scoped_and_records_gate_decision() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD1);
        let other = EntityId::from_bytes([0xE2; 16]).expect("other id");
        put_person(&vault, other);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let own_create = facade.tasks_create(&spec(120)).expect("own task");
        let mut other_spec = spec(120);
        other_spec.owner_ref = Some(other);
        let other_create = facade.tasks_create(&other_spec).expect("other task");

        let decisions_before = vault.gate_decisions(512).expect("decisions before").len();
        let own_cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(
                own_create.task_ref.expect("own task ref"),
            ))
            .expect("own cancel");
        let decisions_after_own = vault
            .gate_decisions(512)
            .expect("decisions after own")
            .len();
        let foreign_cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(
                other_create.task_ref.expect("other task ref"),
            ))
            .expect("foreign cancel");

        assert_eq!(TaskCancelMode::ALL.map(TaskCancelMode::as_str).len(), 3);
        assert_eq!(
            TaskCancelMode::ALL.map(TaskCancelMode::as_str),
            ["auto", "full-access", "manual"]
        );
        assert_eq!(DEFAULT_TASK_CANCEL_MODE.as_str(), "auto");
        assert_eq!(TaskCancelMode::Auto.ceiling(), PolicyApprovalCeiling::Auto);
        assert_eq!(
            TaskCancelMode::FullAccess.ceiling(),
            PolicyApprovalCeiling::Auto
        );
        assert_eq!(
            TaskCancelMode::Manual.ceiling(),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(decisions_after_own - decisions_before, 1);
        assert_eq!(usize::from(own_cancel.gate_decision_ref.is_some()), 1);
        assert_eq!(
            vault
                .gate_decisions(512)
                .expect("gate decisions")
                .iter()
                .filter(|decision| {
                    own_cancel.gate_decision_ref.as_deref()
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == GateOutcome::Allow.as_str()
                })
                .count(),
            1
        );
        assert_eq!(usize::from(own_cancel.effected), 1);
        assert_eq!(own_cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(own_cancel.status, Some(RunTreeStatus::Cancelled));
        assert_eq!(usize::from(foreign_cancel.effected), 0);
        assert_eq!(foreign_cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(foreign_cancel.proposal_ref.is_some()), 1);
        assert_eq!(usize::from(foreign_cancel.gate_decision_ref.is_some()), 1);

        let queue = AttemptQueue::new(&vault);
        let records = queue.list().expect("list attempts");
        let own_task_hex = own_create.task_ref.expect("own task ref").to_hex();
        let other_task_hex = other_create.task_ref.expect("other task ref").to_hex();
        let own_attempts: Vec<_> = records
            .iter()
            .filter(|attempt| attempt.task_ref.as_deref() == Some(own_task_hex.as_str()))
            .collect();
        let other_attempts: Vec<_> = records
            .iter()
            .filter(|attempt| attempt.task_ref.as_deref() == Some(other_task_hex.as_str()))
            .collect();
        assert_eq!(own_attempts.len(), 1);
        assert_eq!(other_attempts.len(), 1);
        let own_attempt = own_attempts[0];
        let other_attempt = other_attempts[0];
        assert_eq!(own_attempt.state, AttemptState::Cancelled);
        assert_eq!(other_attempt.state, AttemptState::Queued);
    }

    #[test]
    fn pending_cancel_proposes_without_intervening_realization() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("propose cancel");
        let records = AttemptQueue::new(&vault).list().expect("list attempts");
        let task_hex = task_ref.to_hex();

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        assert_eq!(
            vault
                .gate_decisions(512)
                .expect("gate decisions")
                .iter()
                .filter(|decision| {
                    cancel.gate_decision_ref.as_deref()
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == GateOutcome::Pending.as_str()
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.task_ref.as_deref() == Some(task_hex.as_str())
                        && record.state == AttemptState::Queued
                })
                .count(),
            1
        );
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
    }

    #[test]
    fn leased_realization_keeps_cancel_receipt_running() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD2);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "w1".to_owned(),
                    now: 120,
                },
            )
            .expect("claim realization")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("realization must be claimable"),
        };

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel task");
        let post_cancel = queue
            .get(claimed.id)
            .expect("read realization")
            .expect("realization exists");
        let section = facade.tasks_check().expect("check tasks");

        // P1-a: a leased realization is NOT stoppable in-txn, so the cancel is
        // honest — it does not claim effect and does not hide the task.
        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Running));
        assert_eq!(
            usize::from(cancel.status == Some(RunTreeStatus::Cancelled)),
            0
        );
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
        assert_eq!(post_cancel.state, AttemptState::Leased);
        // The task is NOT hidden while the lease keeps realizing (outbound
        // delivery included): the cancelled bit is not set.
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        // The board still shows the task exactly once — it folds to Running
        // under its live lease rather than vanishing.
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );
    }

    #[test]
    fn terminal_task_cancel_is_uneffected_and_keeps_intent_folded() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD3);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "terminal-task-worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim realization")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("realization must be claimable"),
        };
        queue
            .complete(CompleteAttempt {
                id: claimed.id,
                lease_owner: "terminal-task-worker".to_owned(),
                attempt_count: claimed.attempt_count,
                now: 121,
            })
            .expect("complete realization");

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel terminal task");
        let realization = queue
            .get(claimed.id)
            .expect("read realization")
            .expect("realization exists");
        let section = facade.tasks_check().expect("check tasks");
        let job_hex = attempt_hex(claimed.id);

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(realization.state, AttemptState::Completed);
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_hex && row.status == TaskBoardStatus::Done)
                .count(),
            1
        );
        assert_eq!(
            section.rows.iter().filter(|row| row.id == job_hex).count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }

    #[test]
    fn queued_completed_mix_cancel_preserves_terminal_fold_exactly_once() {
        assert_queued_terminal_mix_cancel(
            AttemptState::Completed,
            RunTreeStatus::Completed,
            TaskBoardStatus::Done,
        );
    }

    #[test]
    fn queued_failed_mix_cancel_preserves_terminal_fold_exactly_once() {
        assert_queued_terminal_mix_cancel(
            AttemptState::Failed,
            RunTreeStatus::Failed,
            TaskBoardStatus::Failed,
        );
    }

    // Deferred post-close (CB-04): traced root cause is NOT cancel-receipt
    // honesty. For an agent principal cancelling its OWN already-terminal
    // spawn, `check_external_effect_policy` resolves `Pending` (propose), not
    // `Allow`, so `tasks_cancel_resolved` returns at the gate branch with
    // `approval = Proposed, status = None` before the terminal-status path
    // runs. The receipt is therefore honest about the proposal; the terminal
    // `Some(Completed)`/`Auto` this test expects is unreachable until the
    // external-effect gate auto-allows an agent's self-cancel of its own
    // spawn. That is gate-authority-surface work (an owner decision on whether
    // agent spawn self-cancel is Auto), out of 1696 scope, and fail-closed
    // (propose ⊃ allow) so non-security. Re-enable once that authority lands.
    #[test]
    #[ignore = "CB-04 follow-up: agent spawn self-cancel proposes (gate Pending); Auto/Some(Completed) needs gate-authority change, deferred post-close, non-security"]
    fn terminal_spawn_cancel_is_uneffected_and_preserves_terminal_state() {
        let (_dir, vault) = open_vault();
        let own = EntityId::from_bytes([0xB3; 16]).expect("custom agent id");
        // Ordinary row fork off the seeded keeper row: lineage is the parent
        // ROW id, and the child copies the parent's stored ceiling.
        let (keeper_id, keeper) = vault
            .get_seeded_agent_definition_by_logical_id("sys.keeper")
            .expect("resolve seeded keeper")
            .expect("seeded keeper exists");
        let mut fork = keeper.clone();
        fork.agent_id = "spawn-owner".to_owned();
        fork.version = "1".to_owned();
        fork.forked_from = Some(keeper_id);
        fork.ceiling = keeper.ceiling;
        fork.logical_id = None;
        fork.display_name = None;
        fork.source = crate::claim::ClaimSource::UserStated;
        fork.provenance = rmpv::Value::Map(vec![(
            rmpv::Value::from("forkOf"),
            rmpv::Value::from(keeper_id.to_hex()),
        )]);
        vault
            .put_agent_definition(&own, &fork, TimeRange { start: 1, end: 1 }, 1)
            .expect("fork custom agent");
        grant_cancel(&vault, own, 0xD4);
        let dispatcher = AgentDispatcher::new(&vault);
        let parent = match dispatcher
            .dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(own),
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now: 120,
            })
            .expect("dispatch parent")
        {
            AgentDispatchOutcome::Dispatched(status) => status,
            AgentDispatchOutcome::Existing(_) => panic!("parent dispatch must be fresh"),
        };
        let child = match dispatcher
            .dispatch_default_base(Some(parent.attempt.id), None, None, 121)
            .expect("dispatch child")
        {
            AgentDispatchOutcome::Dispatched(status) => status,
            AgentDispatchOutcome::Existing(_) => panic!("child dispatch must be fresh"),
        };
        let queue = AttemptQueue::new(&vault);
        for (expected, lease_owner, now) in [
            (parent.attempt.id, "terminal-parent-worker", 122),
            (child.attempt.id, "terminal-child-worker", 123),
        ] {
            let claimed = match queue
                .claim_kind(
                    DREAMER_RUNNER_ATTEMPT_KIND,
                    ClaimAttempt {
                        lease_owner: lease_owner.to_owned(),
                        now,
                    },
                )
                .expect("claim dispatch")
            {
                ClaimOutcome::Claimed(claimed) => claimed,
                ClaimOutcome::Empty => panic!("dispatch must be claimable"),
            };
            assert_eq!(usize::from(claimed.id == expected), 1);
            queue
                .complete(CompleteAttempt {
                    id: claimed.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: claimed.attempt_count,
                    now,
                })
                .expect("complete dispatch");
        }

        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Spawn(child.attempt.id))
            .expect("cancel terminal spawn");
        let terminal = queue
            .get(child.attempt.id)
            .expect("read child")
            .expect("child exists");

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(terminal.state, AttemptState::Completed);
        assert_eq!(
            vault
                .gate_decisions(512)
                .expect("gate decisions")
                .iter()
                .filter(|decision| {
                    cancel.gate_decision_ref.as_deref()
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == GateOutcome::Allow.as_str()
                })
                .count(),
            1
        );
    }

    #[test]
    fn connector_send_cancel_cancels_queued_realization() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let send_grant_ref = EntityId::from_bytes([0xD3; 16]).expect("send grant id");
        vault
            .mint_standing_outbound_grant(
                &send_grant_ref,
                &GrantMintIntent {
                    principal_ref: own.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "create".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "send".to_owned(),
                    },
                },
                1,
            )
            .expect("mint send grant");
        grant_cancel(&vault, own, 0xD4);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        facade
            .schedule_outbound(&OutboundDraftInput {
                verb: "send".to_owned(),
                channel: "email".to_owned(),
                target: "x".to_owned(),
                on_behalf_of: None,
                content_ref: None,
                idempotency_key: Some("k1".to_owned()),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: "s1".to_owned(),
                job_ref: None,
                occurred_at: Some(120),
            })
            .expect("schedule send");
        let tasks = vault.connector_send_tasks().expect("connector tasks");
        assert_eq!(tasks.len(), 1);
        let task_ref = tasks[0].task_ref;

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel send");
        let attempts = AttemptQueue::new(&vault).list().expect("list attempts");
        let task_hex = task_ref.to_hex();

        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Cancelled
                })
                .count(),
            1
        );
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Queued
                })
                .count(),
            0
        );
    }

    #[test]
    fn role_only_task_is_present_and_cancel_fails_closed() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD5);
        let task_ref = EntityId::from_bytes([0xB1; 16]).expect("task id");
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("put task");
        let outcome = AttemptQueue::new(&vault)
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(task_ref.to_hex()),
            )
            .expect("enqueue realization");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("realization must enqueue");
        };
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let section = facade.tasks_check().expect("check tasks");
        assert_eq!(section.rows.len(), 1);
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel task");
        let realization = AttemptQueue::new(&vault)
            .get(attempt.id)
            .expect("read realization")
            .expect("realization exists");

        // P1-c: a role-only TASK carries no stored owner provenance, so cancel
        // fails closed to the foreign ladder — a proposal, never a direct
        // effect. The realizing attempt is untouched (still Queued), and the
        // task stays visible (asserted above: fix-r1 F6 is preserved).
        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        assert_eq!(realization.state, AttemptState::Queued);
    }

    #[test]
    fn ack_persists_and_removes_failed_task_from_render() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("created task must be claimable"),
        };
        queue
            .fail(FailAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                reason: "failed".to_owned(),
                now: 121,
            })
            .expect("fail task");

        let before = facade.tasks_check().expect("check before ack");
        assert_eq!(before.rows.len(), 1);
        assert_eq!(before.rows[0].status, TaskBoardStatus::Failed);
        assert!(!task_is_acked(&vault, task_ref).expect("read unacked state"));
        // An unacked failure is still expandable by id.
        assert!(facade.tasks_expand(task_ref).is_ok());
        let ack = facade.tasks_ack(task_ref).expect("ack task");
        assert!(ack.acked);
        assert!(task_is_acked(&vault, task_ref).expect("read ack"));
        // Once acked, the failure has left the surface — expand agrees with check.
        assert_eq!(
            facade
                .tasks_expand(task_ref)
                .expect_err("acked failure is not expandable")
                .code,
            crate::facade::FACADE_CODE_NOT_FOUND
        );
        let after = facade.tasks_check().expect("check after ack");
        assert_eq!(after.rows.len(), 0);
    }

    #[test]
    fn ack_before_failure_is_a_noop_and_failure_still_surfaces() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");

        // The task is Queued (not failed): acking it is a no-op — the bit stays
        // unset so a later failure is not pre-suppressed.
        let premature = facade.tasks_ack(task_ref).expect("ack queued task");
        assert!(!premature.acked);
        assert!(!task_is_acked(&vault, task_ref).expect("no ack bit set"));

        // The realization now fails.
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("created task must be claimable"),
        };
        queue
            .fail(FailAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                reason: "failed".to_owned(),
                now: 121,
            })
            .expect("fail task");

        // The failure STILL surfaces — the premature ack did not suppress it.
        let after_fail = facade.tasks_check().expect("check after fail");
        assert_eq!(after_fail.rows.len(), 1);
        assert_eq!(after_fail.rows[0].status, TaskBoardStatus::Failed);

        // A real ack (now that it is failed) removes it from the surface.
        let acked = facade.tasks_ack(task_ref).expect("ack failed task");
        assert!(acked.acked);
        assert_eq!(facade.tasks_check().expect("check after ack").rows.len(), 0);
    }

    #[test]
    fn malformed_dreamer_row_does_not_poison_the_board() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        // A healthy TASK.
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        // A malformed dreamer-kind row enqueued through the public queue API (as
        // a downstream product could): 0xC1 is the reserved, never-valid
        // MessagePack marker, so the payload envelope never decodes.
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(_) = queue
            .enqueue(EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: vec![0xC1],
                dedupe_key: None,
                run_id: None,
                now: 121,
            })
            .expect("enqueue malformed dreamer row")
        else {
            panic!("malformed row must enqueue");
        };
        // The board still reads for the unrelated healthy TASK — one bad row
        // degrades to a bare job in the run tree instead of poisoning the whole
        // read (previously the tree read errored and failed tasks.check/expand).
        let section = facade
            .tasks_check()
            .expect("board reads despite the malformed row");
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );
        // The typed read verb for the healthy TASK also works.
        assert!(facade.tasks_expand(task_ref).is_ok());
    }

    /// P1-a: a Queued+Leased mix cannot be fully cancelled in-txn (the lease
    /// can't be stopped), so the cancel is honest — uneffected, nothing hidden,
    /// nothing intervened — and the task stays visible under its live lease.
    #[test]
    fn queued_leased_mix_cancel_is_honest_and_not_hidden() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD6);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        // Second realizing attempt so the task has a Queued + Leased mix.
        assert!(matches!(
            queue
                .enqueue_with_task_ref(
                    EnqueueAttempt {
                        kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                        payload: Vec::new(),
                        dedupe_key: None,
                        run_id: None,
                        now: 120,
                    },
                    Some(task_hex.clone()),
                )
                .expect("enqueue second realization"),
            EnqueueOutcome::Enqueued(_)
        ));
        // Lease exactly one realization; the other stays Queued.
        match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "w1".to_owned(),
                    now: 120,
                },
            )
            .expect("claim one realization")
        {
            ClaimOutcome::Claimed(_) => {}
            ClaimOutcome::Empty => panic!("a realization must be claimable"),
        }

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel task");
        let records = queue.list().expect("list attempts");
        let section = facade.tasks_check().expect("check tasks");

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Running));
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        // Neither attempt was touched: exactly one Leased, exactly one Queued.
        assert_eq!(
            records
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Leased)
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Queued)
                .count(),
            1
        );
        // The board still shows the task exactly once.
        assert_eq!(
            section.rows.iter().filter(|row| row.id == task_hex).count(),
            1
        );
    }

    /// P1-b (TOCTOU): the cancel acts on the transaction-current attempt state,
    /// not a pre-txn snapshot. A stale `Leased` snapshot whose live state is now
    /// `Queued` must still be cancelled in-txn.
    #[test]
    fn cancel_uses_in_txn_live_state_not_stale_leased_snapshot() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xDB);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        let records = queue.list().expect("list attempts");
        let attempt = records
            .iter()
            .find(|r| r.task_ref.as_deref() == Some(task_hex.as_str()))
            .expect("realizing attempt");
        // Live state is Queued (as if a lease-cleanup requeue already happened).
        assert_eq!(attempt.state, AttemptState::Queued);

        // A deliberately STALE snapshot claims the attempt is still Leased.
        let stale = CancelTargetState {
            owned: true,
            task_ref: Some(task_ref),
            attempts: vec![(attempt.id, AttemptState::Leased)],
            proposal_subject: task_ref,
            target_ref: task_hex.clone(),
        };
        let cancel = facade
            .tasks_cancel_with_injected_state_for_test(TaskCancelMode::Auto, stale)
            .expect("cancel with stale snapshot");
        let after = queue.list().expect("list after");

        // The in-txn re-read acts on the LIVE (Queued) state and cancels it,
        // despite the stale Leased snapshot. Trusting the snapshot would skip
        // intervention and leave the attempt claimable.
        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
        assert_eq!(
            after
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Cancelled)
                .count(),
            1
        );
        assert_eq!(
            after
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Queued)
                .count(),
            0
        );
    }

    /// Membership TOCTOU: a retry between the snapshot and the write txn
    /// REPLACES the target's live realization with a new row under the same
    /// `task_ref`. Re-reading only the snapshotted ids sees the dead source,
    /// reports the task terminally failed, cancels nothing, and leaves the
    /// scheduled successor to run and send.
    #[test]
    fn cancel_reaches_a_retry_minted_between_snapshot_and_write_txn() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xDC);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 121,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("created task must be claimable"),
        };

        // The snapshot the cancel would have taken: one leased realization.
        let snapshot = CancelTargetState {
            owned: true,
            task_ref: Some(task_ref),
            attempts: vec![(claimed.id, AttemptState::Leased)],
            proposal_subject: task_ref,
            target_ref: task_ref.to_hex(),
        };

        // The executor retries FIRST: the snapshotted row is now a terminal
        // Failed source and a fresh Scheduled row owns the pending send.
        let RetryOutcome::Retried(next) = queue
            .retry(RetryAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                backoff_until: 400,
                last_error: Some("rate limited".to_owned()),
                now: 122,
            })
            .expect("retry the leased realization");
        assert_ne!(next.id, claimed.id);

        let cancel = facade
            .tasks_cancel_with_injected_state_for_test(TaskCancelMode::Auto, snapshot)
            .expect("cancel with pre-retry snapshot");
        let after = queue.list().expect("list after");

        // The successor is STOPPED, not merely reported around.
        assert_eq!(
            after
                .iter()
                .find(|r| r.id == next.id)
                .expect("successor row")
                .state,
            AttemptState::Cancelled
        );
        // The task is not read off its superseded source: the cancel took
        // effect and the TASK itself is withdrawn, rather than the verb
        // reporting a terminal failure it did not stop.
        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
        assert!(task_is_cancelled(&vault, task_ref).expect("cancel state"));
        // Per-try history survives: the failed source stays point-readable.
        assert_eq!(
            after
                .iter()
                .find(|r| r.id == claimed.id)
                .expect("source row")
                .state,
            AttemptState::Failed
        );
    }

    /// A retry chain's HEAD carries the task's board status. Any-row precedence
    /// (Failed > Scheduled > Done) reads the task off a superseded try: a held
    /// retry folds up as `Failed`, and a chain that later SUCCEEDED keeps
    /// folding up as `Failed` forever.
    #[test]
    fn board_reads_a_retry_chain_off_its_head_not_a_superseded_try() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);

        // Two retries: three rows, the first two terminally Failed sources.
        let mut head = None;
        for now in [121_u64, 141] {
            let claimed = match queue
                .claim_kind(
                    TASK_REALIZE_ATTEMPT_KIND,
                    ClaimAttempt {
                        lease_owner: "worker".to_owned(),
                        now,
                    },
                )
                .expect("claim")
            {
                ClaimOutcome::Claimed(claimed) => claimed,
                ClaimOutcome::Empty => panic!("the chain head must be claimable"),
            };
            let RetryOutcome::Retried(next) = queue
                .retry(RetryAttempt {
                    id: claimed.id,
                    lease_owner: "worker".to_owned(),
                    attempt_count: claimed.attempt_count,
                    backoff_until: now + 10,
                    last_error: Some("upstream refused".to_owned()),
                    now: now + 1,
                })
                .expect("retry");
            head = Some(next.id);
        }
        let head = head.expect("chain head");

        // Held retry: the task is deferred, not failed — and only the head is
        // folded, so the board shows one live realization, not three rows.
        let section = facade.tasks_check().expect("check tasks");
        let row = section
            .rows
            .iter()
            .find(|row| row.id == task_hex)
            .expect("task row");
        assert_eq!(row.status, TaskBoardStatus::Scheduled);
        assert_eq!(row.folded_job_count, 1);

        // The head SUCCEEDS: the logical task is done, not permanently failed.
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 200,
                },
            )
            .expect("claim head")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("the chain head must be claimable"),
        };
        assert_eq!(claimed.id, head);
        queue
            .complete(CompleteAttempt {
                id: head,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                now: 201,
            })
            .expect("complete the head");

        let done = facade.tasks_check().expect("check after success");
        let row = done
            .rows
            .iter()
            .find(|row| row.id == task_hex)
            .expect("task row");
        assert_eq!(row.status, TaskBoardStatus::Done);
    }

    /// P1-c: a stored, `tasks.cancel`-granted actor cannot DIRECTLY cancel a
    /// role-only task it cannot prove it owns — it surfaces a proposal. Role-only
    /// ownership is not derivable from storage, so the fallback fails closed.
    #[test]
    fn role_only_task_cancel_by_foreign_granted_actor_proposes() {
        let (_dir, vault) = open_vault();
        let agent_b = own_agent(&vault);
        grant_cancel(&vault, agent_b, 0xD8);
        // Role-only TASK nominally belonging to some agent A; no stored
        // provenance links it to any actor.
        let task_ref = EntityId::from_bytes([0xB2; 16]).expect("task id");
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("put role-only task");
        let outcome = AttemptQueue::new(&vault)
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(task_ref.to_hex()),
            )
            .expect("enqueue realization");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("realization must enqueue");
        };
        let facade = vault.memory_facade(agent_b, EdgeActorClass::Agent);

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel role-only task");
        let realization = AttemptQueue::new(&vault)
            .get(attempt.id)
            .expect("read realization")
            .expect("realization exists");
        let section = facade.tasks_check().expect("check tasks");

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        // The realizing attempt is untouched and the task stays visible.
        assert_eq!(realization.state, AttemptState::Queued);
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );
    }

    /// FIX A: a valid typed body can claim any `owner_ref`, so that field is
    /// never cancellation authority. The create-time owner record remains the
    /// sole proof even if trusted low-level storage rewrites the body.
    #[test]
    fn typed_task_cancel_ignores_forged_body_owner() {
        let (_dir, vault) = open_vault();
        let attacker = own_agent(&vault);
        let owner = EntityId::from_bytes([0xE2; 16]).expect("owner id");
        put_person(&vault, owner);
        grant_cancel(&vault, attacker, 0xD9);
        let created = vault
            .memory_facade(owner, EdgeActorClass::Human)
            .tasks_create(&spec(120))
            .expect("owner creates task");
        let task_ref = created.task_ref.expect("task ref");
        let mut forged_body = task_verb_body(&vault, task_ref)
            .expect("decode created body")
            .expect("created task is typed");
        forged_body.owner_ref = attacker.to_hex();
        let forged_body = encode_task_verb_body(forged_body).expect("encode forged body");
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 121,
                    end: 121,
                },
                121,
                &forged_body,
            )
            .expect("rewrite body below facade");
        let forged = task_verb_body(&vault, task_ref)
            .expect("decode forged body")
            .expect("typed task");
        let cancel = vault
            .memory_facade(attacker, EdgeActorClass::Agent)
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel forged-owner task");
        let task_hex = task_ref.to_hex();
        let attempts = AttemptQueue::new(&vault).list().expect("list attempts");

        assert_eq!(usize::from(forged.owner_ref == attacker.to_hex()), 1);
        assert_eq!(
            task_create_owner(&vault, task_ref).expect("read proven owner"),
            Some(owner)
        );
        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Queued
                })
                .count(),
            1
        );
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Cancelled
                })
                .count(),
            0
        );
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
    }

    /// P2 F6: only the `Task` role folds into TASKS. A `Habit`-role entity is
    /// not a task and must not render as a TASKS row.
    #[test]
    fn only_task_role_folds_into_tasks_section() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let task_role = EntityId::from_bytes([0xB3; 16]).expect("task role id");
        let habit_role = EntityId::from_bytes([0xB4; 16]).expect("habit role id");
        vault
            .put_entity(
                &task_role,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("put task-role");
        vault
            .put_entity(
                &habit_role,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Habit),
            )
            .expect("put habit-role");
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let section = facade.tasks_check().expect("check tasks");

        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_role.to_hex())
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == habit_role.to_hex())
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }

    /// P2 F7: a realizing job whose backlink names no surviving intent is
    /// re-emitted as a bare job — rendered exactly once, never dropped.
    #[test]
    fn dangling_backlink_job_still_renders_once() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let missing_task_hex = EntityId::from_bytes([0xC1; 16])
            .expect("missing id")
            .to_hex();
        let outcome = AttemptQueue::new(&vault)
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(missing_task_hex),
            )
            .expect("enqueue dangling attempt");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("attempt must enqueue");
        };
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let section = facade.tasks_check().expect("check tasks");
        let job_id = attempt_hex(attempt.id);

        assert_eq!(
            section.rows.iter().filter(|row| row.id == job_id).count(),
            1
        );
        assert_eq!(section.rows.len(), 1);
    }

    /// FIX C: projection failure/non-membership cannot consume a live job.
    /// Both jobs degrade to bare rows exactly once when their backlink entity
    /// cannot produce a TASKS intent.
    #[test]
    fn unprojectable_task_backlinks_render_jobs_exactly_once() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let malformed = EntityId::from_bytes([0xC2; 16]).expect("malformed id");
        let non_task_role = EntityId::from_bytes([0xC3; 16]).expect("non-task role id");
        let malformed_body = {
            let value = Value::Map(vec![
                (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
                (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode malformed body");
            bytes
        };
        vault
            .put_entity(
                &malformed,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &malformed_body,
            )
            .expect("put malformed task");
        vault
            .put_entity(
                &non_task_role,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Habit),
            )
            .expect("put non-task role");
        let queue = AttemptQueue::new(&vault);
        let attempts: Vec<_> = [malformed, non_task_role]
            .into_iter()
            .map(|task_ref| {
                match queue
                    .enqueue_with_task_ref(
                        EnqueueAttempt {
                            kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                            payload: Vec::new(),
                            dedupe_key: None,
                            run_id: None,
                            now: 120,
                        },
                        Some(task_ref.to_hex()),
                    )
                    .expect("enqueue realization")
                {
                    EnqueueOutcome::Enqueued(attempt) => attempt,
                    EnqueueOutcome::Existing(_) => panic!("realization must be fresh"),
                }
            })
            .collect();

        let section = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_check()
            .expect("check tasks");
        let malformed_job = attempt_hex(attempts[0].id);
        let non_task_job = attempt_hex(attempts[1].id);

        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == malformed_job)
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == non_task_job)
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == malformed.to_hex())
                .count(),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == non_task_role.to_hex())
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 2);
    }

    /// P2 F8: one malformed TASK body (typed subkind but missing the typed
    /// fields) must not abort the whole board — it is skipped, and every other
    /// task still renders.
    #[test]
    fn malformed_task_body_does_not_poison_the_board() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let valid_task = created.task_ref.expect("task ref");
        let poison = EntityId::from_bytes([0xC2; 16]).expect("poison id");
        let poison_body = {
            let value = Value::Map(vec![
                (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
                (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode poison body");
            bytes
        };
        vault
            .put_entity(
                &poison,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &poison_body,
            )
            .expect("put poison task");

        let section = facade.tasks_check().expect("check tasks survives poison");

        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == valid_task.to_hex())
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == poison.to_hex())
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }
}
