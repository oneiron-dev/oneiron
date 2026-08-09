//! Typed, actor-bound verbs over the Context Board TASKS section.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    DispatchAgent, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, EnqueueAttempt, EnqueueOutcome, InterveneAttempt,
};
use crate::batch::{
    ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    apply_ops_with_gate_mode,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::code_run::{SelfDurableWait, peer_result_wait};
use crate::consult_ladder::{
    A2aTaskProjection, ConsultLadderState, ConsultLineage, ConsultLineageRelation, ConsultPurpose,
    DREAMER_MAGISTRATE_ATTEMPT_TYPE, EntityDeltaArtifact, EntityDeltaShape, GraduationLookup,
    GraduationScope, HumanVerdict, LadderTerminalDisposition, LadderTerminalState,
    LadderTransition, LadderTransitionError, MagistrateCase, MagistrateOverturnRecord,
    MagistrateReceipt, MagistrateVerdict, NoveltyDecision, StateAuthorship,
    decide_magistrate_from_derived_authorship, magistrate_decision_layer, novelty_guard,
    project_to_a2a, transition_ladder,
};
use crate::context_board::{
    JobPresence, TaskBoardStatus, TaskIntentPresence, TasksSection, ack_task_in_txn,
    cancel_task_in_txn, expand_task, fold_up_status, task_is_acked, task_is_cancelled,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload,
};
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
use crate::human_task::{
    HumanTaskError, register_human_followup_in_txn, resolve_native_human_route,
};
use crate::llm::send_peer_result_signal;
use crate::provenance::validate_actor_class;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
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
///
/// The three ONE-1888 additions are optional and default to absent. Absent is
/// exactly ONE-1699's question consult, so no migration rewrites a stored row
/// and no old row decodes differently than it did before this ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultPayload {
    // ONE-1699 fields — unchanged and required.
    pub question_ref: ConsultPayloadRef,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub correlation_ref: EntityId,

    // ONE-1888 additions — optional/defaulted, never a re-shape.
    pub purpose: Option<ConsultPurpose>,
    pub entity_delta: Option<EntityDeltaArtifact>,
    pub lineage: Option<ConsultLineage>,
}

impl ConsultPayload {
    /// The ONE-1699 construction surface, unchanged.
    #[must_use]
    pub const fn question(
        question_ref: ConsultPayloadRef,
        context_refs: Vec<ConsultPayloadRef>,
        correlation_ref: EntityId,
    ) -> Self {
        Self {
            question_ref,
            context_refs,
            correlation_ref,
            purpose: None,
            entity_delta: None,
            lineage: None,
        }
    }

    /// Declares this consult an entity-delta ask over one typed artifact.
    #[must_use]
    pub fn with_entity_delta(mut self, delta: EntityDeltaArtifact) -> Self {
        self.purpose = Some(ConsultPurpose::EntityDelta);
        self.entity_delta = Some(delta);
        self
    }

    /// Links this consult to the record it counters, appeals, or escalates.
    #[must_use]
    pub const fn with_lineage(mut self, lineage: ConsultLineage) -> Self {
        self.lineage = Some(lineage);
        self
    }

    /// Typed `cl_*`/`tn_*` entries carried by this payload.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        1 + self.context_refs.len()
    }

    /// `None` and `Some(Question)` are the SAME ONE-1699 shape; only an
    /// explicit `EntityDelta` requires the typed artifact.
    #[must_use]
    pub fn consult_purpose(&self) -> ConsultPurpose {
        self.purpose.unwrap_or(ConsultPurpose::Question)
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
        self.validate_purpose()
    }

    /// The ONE-1888 validation matrix: the purpose and the typed artifact
    /// agree, or the payload is refused. A question consult carrying a delta —
    /// or a delta consult carrying none — is a shape no writer may persist.
    fn validate_purpose(&self) -> Result<()> {
        let agrees = match self.consult_purpose() {
            ConsultPurpose::Question => self.entity_delta.is_none(),
            ConsultPurpose::EntityDelta => self.entity_delta.is_some(),
        };
        if !agrees {
            return Err(Error::InvalidTaskBody("tasks.consult.purpose"));
        }
        // Chatter never enters the state machine: the artifact carries refs,
        // and a thread pointer is the ONLY door to the discussion itself.
        if let Some(delta) = &self.entity_delta
            && delta.proposer_actor_ref == delta.owning_actor_ref
        {
            // A cross-actor consult whose proposer IS the owner is the
            // auto-apply path taking the wrong door.
            return Err(Error::InvalidTaskBody("tasks.consult.same_actor"));
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
pub const fn board_status_for_disposition(disposition: TaskTerminalDisposition) -> TaskBoardStatus {
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
    Answer {
        evidence_refs: Vec<ConsultPayloadRef>,
    },
    Abstained {
        reason_ref: ConsultPayloadRef,
    },
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
    /// ONE-1888 ladder projection. `Approved` and `Overridden` both persist as
    /// `Completed`, and `Countered` as `Rejected`, so the finer ladder
    /// vocabulary rides HERE — inside the same single register, never as an
    /// independently mergeable field. Absent on every ONE-1699 row.
    pub ladder: Option<LadderTerminalDisposition>,
    /// Set exactly on a `Countered` ladder outcome: the NEW task minted in the
    /// same transaction that terminalized this one.
    pub counter_task_ref: Option<EntityId>,
}

/// CRDT merge for the one terminal register. Later `finished_at` wins; a
/// SUBSTANTIVE terminal (`Completed` or `Rejected` — someone actually decided)
/// dominates an expiry-like one (`Expired`/`Abandoned` — nobody did) on an
/// exact tie; any remaining tie falls to canonical serialized bytes so both
/// replicas pick the same winner in either merge order.
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

/// A decision beats a timeout at the same instant. `Completed` and `Rejected`
/// are both decisions — an owner's "no" that landed exactly on the deadline is
/// no less an answer than a "yes" — so both outrank the expiry sweep, and the
/// two of them fall to canonical bytes against each other.
fn terminal_register_order(record: &TaskTerminalRecord) -> (u64, u8, Vec<u8>) {
    let substantive = matches!(
        record.disposition,
        TaskTerminalDisposition::Completed | TaskTerminalDisposition::Rejected
    );
    (
        record.finished_at,
        u8::from(substantive),
        canonical_bytes(&task_terminal_record_value(record)),
    )
}

/// Execution state of one TASK intent on this replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExecutionState {
    Queued,
    Working {
        started_at: u64,
    },
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

/// The lanes `TASK.assignee` routes over: three pluggable EXECUTION lanes, plus
/// the human lane, which executes nothing at all (ONE-1708).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRouteLane {
    Dreamer,
    AgentDefinition,
    PeerActor,
    /// A person was asked. Nothing realizes the task; the Dreamer follows up.
    HumanAssignee,
}

/// What routing one created TASK actually did. The peer variant naming zero
/// attempts is the point: the synced entity IS the transport. The human variant
/// names zero attempts for a different reason — a person is not a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRouteOutcome {
    DreamerAttempt {
        attempt_ref: AttemptId,
    },
    AgentDispatch {
        attempt_ref: AttemptId,
        agent_def_ref: EntityId,
    },
    PeerSyncedOnly {
        actor_ref: EntityId,
    },
    HumanFollowup {
        actor_ref: EntityId,
    },
}

impl TaskRouteOutcome {
    /// The lane this outcome came from.
    #[must_use]
    pub const fn lane(self) -> TaskRouteLane {
        match self {
            Self::DreamerAttempt { .. } => TaskRouteLane::Dreamer,
            Self::AgentDispatch { .. } => TaskRouteLane::AgentDefinition,
            Self::PeerSyncedOnly { .. } => TaskRouteLane::PeerActor,
            Self::HumanFollowup { .. } => TaskRouteLane::HumanAssignee,
        }
    }

    /// The local realizing attempt, or `None` on the peer and human lanes.
    #[must_use]
    pub const fn local_attempt(self) -> Option<AttemptId> {
        match self {
            Self::DreamerAttempt { attempt_ref } | Self::AgentDispatch { attempt_ref, .. } => {
                Some(attempt_ref)
            }
            Self::PeerSyncedOnly { .. } | Self::HumanFollowup { .. } => None,
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
    /// The lane the created TASK routed to. `None` when nothing was created —
    /// a parked proposal has not routed anywhere yet.
    pub route: Option<TaskRouteOutcome>,
}

/// Receipt for stamping the authoritative `started_at` fact on a TASK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStartedReceipt {
    pub task_ref: EntityId,
    pub started_at: u64,
    pub idempotent_replay: bool,
}

/// Input to the general terminal writer. Every terminal transition carries a
/// `result_ref` — including `Abandoned`, whose durable outputs are exactly what
/// makes an abandoned run reviewable rather than lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskResultInput {
    pub result_ref: EntityId,
    pub disposition: TaskTerminalDisposition,
    pub finished_at: u64,
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
    /// Caller clock, exactly as `TaskCreateSpec::now`: the fan-out runs the
    /// same validated consult-create path, so it reads the same clock. The
    /// rate window stays on the engine clock either way.
    pub now: Option<u64>,
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
            // The TASK and its realizing work commit together, so a route
            // failure rolls the intent back rather than leaving an invisible
            // half-created task behind.
            let route = self.route_created_task_in_txn(wtxn, task_ref, &validated, now)?;
            Ok(Some((task_ref, route)))
        })?;

        if let Some((task_ref, route)) = direct {
            return Ok(TaskCreateReceipt {
                task_ref: Some(task_ref),
                proposal_ref: None,
                approval: ClaimApprovalStatus::Auto,
                effected: true,
                route: Some(route),
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
            route: None,
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
        });
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

    /// The engine — never the agent — decides the realizing job, and
    /// `TASK.assignee` is the only thing it decides from: never the label, the
    /// spec prose, the caller's harness, or the model vendor.
    ///
    /// The match is exhaustive so a new assignee variant cannot silently
    /// default into Dreamer realization.
    fn route_created_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        validated: &ValidatedTaskCreate,
        now: u64,
    ) -> FacadeResult<TaskRouteOutcome> {
        match validated.assignee {
            // Absent assignee is the schema-v1 representation of the Dreamer
            // lane and routes identically — old rows are never rewritten.
            None | Some(TaskAssignee::Dreamer) => {
                let attempt_ref =
                    self.enqueue_task_realization_in_txn(wtxn, task_ref, &validated.spec, now)?;
                Ok(TaskRouteOutcome::DreamerAttempt { attempt_ref })
            }
            Some(TaskAssignee::AgentDef { agent_def_ref }) => {
                let outcome = AgentDispatcher::new(self.vault()).dispatch_for_task_in_txn(
                    wtxn,
                    task_ref,
                    DispatchAgent {
                        target: AgentDispatchTarget::Custom(agent_def_ref),
                        parent_attempt: None,
                        dedupe_key: Some(task_route_dedupe_key(task_ref)),
                        run_id: None,
                        now,
                    },
                )?;
                // Dispatched and deduped-existing are ONE idempotent outcome: a
                // retried route returns the attempt already realizing the task.
                let (AgentDispatchOutcome::Dispatched(status)
                | AgentDispatchOutcome::Existing(status)) = outcome;
                Ok(TaskRouteOutcome::AgentDispatch {
                    attempt_ref: status.attempt.id,
                    agent_def_ref,
                })
            }
            // The synced TASK is the transport. A local attempt could never
            // reach an executor on another machine, so none is minted.
            Some(TaskAssignee::Peer { actor_ref }) => {
                Ok(TaskRouteOutcome::PeerSyncedOnly { actor_ref })
            }
            // A person is not a worker. The TASK row and its follow-up cursor
            // commit together and NOTHING else is minted: no `tasks.realize`
            // attempt, no task-linked queue row, no dispatcher call. Follow-up
            // is Dreamer maintenance over the synced TASK fact, never a hidden
            // executor realizing the task on the person's behalf.
            Some(TaskAssignee::Human { actor_ref }) => {
                let route = resolve_native_human_route(self.vault(), actor_ref)
                    .map_err(human_route_refusal)?;
                register_human_followup_in_txn(
                    self.vault(),
                    wtxn,
                    task_ref,
                    route.person_ref,
                    now,
                )?;
                Ok(TaskRouteOutcome::HumanFollowup {
                    actor_ref: route.person_ref,
                })
            }
        }
    }

    /// Enqueues the one existing `tasks.realize` attempt for the Dreamer lane,
    /// keyed on the TASK so a retry can never mint a second realization.
    fn enqueue_task_realization_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        spec: &Value,
        now: u64,
    ) -> FacadeResult<AttemptId> {
        let outcome = AttemptQueue::new(self.vault()).enqueue_with_task_ref_in_txn(
            wtxn,
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: encode_task_realization_input(spec)?,
                dedupe_key: Some(task_route_dedupe_key(task_ref)),
                run_id: None,
                now,
            },
            Some(task_ref.to_hex()),
        )?;
        let (EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record)) = outcome;
        Ok(record.id)
    }

    // ── authoritative execution facts (ONE-1700) ────────────────────────

    /// Stamps the authoritative `started_at` fact once an executor begins. It
    /// is a synced FACT — every device sees who is working on what — and is
    /// engine-owned, outside the five agent-visible `TASKS_VERBS` names.
    ///
    /// Replaying it on an already-started task reports the FIRST `started_at`
    /// and mutates nothing: a re-delivered start is not a restart.
    pub fn mark_task_started(
        &self,
        task_ref: EntityId,
        started_at: u64,
    ) -> FacadeResult<TaskStartedReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (started_at, idempotent_replay) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            self.require_execution_writer(&body)?;
            match body.state {
                Some(TaskExecutionState::Working {
                    started_at: already,
                }) => return Ok((already, true)),
                Some(TaskExecutionState::Terminal(_)) => {
                    return Err(consult_refusal(
                        FACADE_CODE_INVALID_STATE,
                        "task is already terminal",
                        "A settled task cannot start; read its terminal record.",
                    ));
                }
                Some(TaskExecutionState::Interrupted) => {
                    return Err(consult_refusal(
                        FACADE_CODE_INVALID_STATE,
                        "an interrupted task resumes through its ladder, not through start",
                        "Settle the interrupting decision before starting the task.",
                    ));
                }
                None | Some(TaskExecutionState::Queued) => {}
            }
            body.state = Some(TaskExecutionState::Working { started_at });
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, started_at)?;
            Ok((started_at, false))
        })?;

        Ok(TaskStartedReceipt {
            task_ref,
            started_at,
            idempotent_replay,
        })
    }

    /// Lands the terminal record for ANY executor lane: the local Dreamer or
    /// agent-definition child projecting through its TASK backlink, or a peer
    /// whose exhaust was captured as a durable artifact first and whose ref
    /// lands here.
    ///
    /// `Abandoned` is as first-class as `Completed` — both carry `result_ref`,
    /// because the durable outputs of a run nobody finished are exactly what
    /// makes it reviewable.
    pub fn land_task_result(
        &self,
        task_ref: EntityId,
        input: &TaskResultInput,
    ) -> FacadeResult<TaskResultReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        require_resolved_entity(self.vault(), input.result_ref)?;
        let landed = TaskTerminalRecord {
            disposition: input.disposition,
            result_ref: Some(input.result_ref),
            summary: None,
            finished_at: input.finished_at,
            ladder: None,
            counter_task_ref: None,
        };
        self.settle_task_terminal(task_ref, &landed, input.finished_at, standard_body_in_txn)
    }

    /// Hands one peer-assigned TASK to its executor and returns the durable
    /// wait the C9 host parks on. The TASK ref IS the wait id, so the trap, the
    /// local binding, and the peer's eventual result all key on one entity.
    pub fn delegate_task_and_wait(
        &self,
        spec: &TaskCreateSpec,
    ) -> FacadeResult<(TaskCreateReceipt, SelfDurableWait)> {
        if !matches!(spec.assignee, Some(TaskAssignee::Peer { .. })) {
            return Err(FacadeError::bad_request(
                "delegation requires a peer-actor assignee",
            ));
        }
        let receipt = self.tasks_create(spec)?;
        let Some(task_ref) = receipt.task_ref else {
            return Err(consult_refusal(
                FACADE_CODE_INVALID_STATE,
                "delegation parked as a proposal and has nothing to wait on",
                "Approve the parked create, then delegate against the minted task.",
            ));
        };
        Ok((receipt, peer_result_wait(task_ref)))
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
            ladder: None,
            counter_task_ref: None,
        };
        // The consult keeps its own reader: a non-consult task is refused
        // before the shared terminal writer ever sees it, and the evidence /
        // abstention contract above is unchanged.
        self.settle_task_terminal(task_ref, &landed, input.completed_at, consult_body_in_txn)
    }

    /// The one terminal-write path: assignee actor check, local compare-and-set
    /// against the existing terminal register, one body write, then the C9
    /// peer-result signal. Both the consult and general result doors run it, so
    /// there is exactly one place a task settles.
    fn settle_task_terminal(
        &self,
        task_ref: EntityId,
        landed: &TaskTerminalRecord,
        at: u64,
        read_body: impl FnOnce(&Vault, &heed::RoTxn<'_>, EntityId) -> FacadeResult<TaskVerbBody>,
    ) -> FacadeResult<TaskResultReceipt> {
        let (terminal, idempotent_replay) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = read_body(self.vault(), &*wtxn, task_ref)?;
            self.require_execution_writer(&body)?;
            // Local compare-and-set: one replica settles a task once. A
            // byte-identical replay is the network retrying rather than a
            // second result, so it reports the winner and mutates nothing.
            if let Some(existing) = body.terminal() {
                if existing == landed {
                    return Ok((existing.clone(), true));
                }
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "task is already terminal",
                    "Read the settled terminal record; a converged terminal task is immutable.",
                ));
            }
            body.state = Some(TaskExecutionState::Terminal(landed.clone()));
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, at)?;
            // ONE-1702 SEAM (own-task settlement → WAKE/CARRIER): this is the
            // producer call site for `mint_own_task_event` → `route_event`.
            // ONE-1702 has not landed on this base and owns both signatures and
            // every `context_board/stream.rs` edit, so the call is added on its
            // rebase; no oracle-only event injection substitutes for it.
            Ok((landed.clone(), false))
        })?;

        // The terminal record is committed before the signal goes out, so a
        // crash in this gap loses nothing: `reconcile_peer_result_signals`
        // replays the edge from the local binding index.
        send_peer_result_signal(self.vault(), task_ref, at)?;

        Ok(TaskResultReceipt {
            task_ref,
            terminal,
            idempotent_replay,
        })
    }

    /// The one actor allowed to write execution facts on this TASK: the
    /// addressed executor, or the owner when the assignee is the local Dreamer,
    /// which has no actor row of its own.
    fn require_execution_writer(&self, body: &TaskVerbBody) -> FacadeResult<()> {
        let expected = match body.assignee.and_then(TaskAssignee::entity_ref) {
            Some(entity_ref) => entity_ref,
            None => EntityId::from_hex(&body.owner_ref)
                .map_err(|_| FacadeError::from(Error::InvalidTaskBody("tasks.body.owner_ref")))?,
        };
        if expected == self.actor() {
            Ok(())
        } else {
            // The task is ADDRESSED. A write from anyone else is not a late
            // result, it is an unaddressed write.
            Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "only the addressed assignee may write this task's execution facts",
                "Write as the actor the task is addressed to.",
            ))
        }
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
        let now = input.now.unwrap_or_else(unix_seconds_now);
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
                        .with_consult(ConsultPayload::question(
                            input.question_ref,
                            input.context_refs.clone(),
                            correlation_ref,
                        ))
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
            let page = self.vault().entities_by_type_page(
                ENTITY_TYPE_TASK,
                cursor.as_ref(),
                CONSULT_SETTLE_PAGE,
            )?;
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
            let key = task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED);
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
                ladder: None,
                counter_task_ref: None,
            }));
            let encoded = encode_task_verb_body(body);
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
                .put(
                    wtxn,
                    peer_handle_key(actor_ref).as_slice(),
                    handle.as_bytes(),
                )
                .map_err(FacadeError::from)
        })
    }

    // ── consult ladder (ONE-1888) ───────────────────────────────────────

    /// Compare-and-set one consult ladder step onto ONE-1699's TASK body.
    ///
    /// The pure [`transition_ladder`] decides; this only checks that the
    /// caller's `expected` ladder state still PROJECTS onto what is persisted,
    /// then writes the new projection as the same single register ONE-1699
    /// minted. The ladder never becomes a second durable record: everything
    /// here is the TASK body.
    ///
    /// Terminal immutability is enforced twice over — once by the projection
    /// check (a settled row no longer matches a working `expected`) and once
    /// by the pure transition, which refuses every move out of terminal.
    pub fn compare_and_set_consult_ladder(
        &self,
        task_ref: EntityId,
        expected: &ConsultLadderState,
        transition: LadderTransition,
    ) -> FacadeResult<LadderTransitionReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let expected_state = project_consult_ladder_state(expected);
        let (ladder_state, task_state) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = consult_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            if body.state.as_ref() != Some(&expected_state) {
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "consult ladder state moved since it was read",
                    "Re-read the TASK body and retry the transition against its current state.",
                ));
            }
            let next = transition_ladder(expected, transition).map_err(ladder_refusal)?;
            let next_state = project_consult_ladder_state(&next);
            body.state = Some(next_state.clone());
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, now_for_ladder(&next))?;
            Ok((next, next_state))
        })?;
        Ok(LadderTransitionReceipt {
            task_ref,
            ladder_state,
            task_state,
        })
    }

    /// Mints one counter TASK, and — when the original is still open —
    /// terminalizes it as rejected-with-counter-lineage in the SAME
    /// transaction.
    ///
    /// A counter is never an edit. The original keeps its own terminal row
    /// forever; an ALREADY-terminal original is left byte-identical and only
    /// the new task is written.
    pub fn mint_counter_task(
        &self,
        parent_task_ref: EntityId,
        counter_delta: EntityDeltaArtifact,
        deadline_at: u64,
        now: u64,
    ) -> FacadeResult<TaskCreateReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let provenance = facade_provenance(task_verb_contract(TasksVerb::Create));
        // A counter is a fresh cross-actor consult, so it answers to exactly
        // the same attribution and ownership laws as the original ask.
        let owning_actor_ref = self.resolve_cross_actor_owner(&counter_delta)?;
        let payload = self
            .entity_delta_payload(counter_delta)?
            .with_lineage(ConsultLineage {
                relation: ConsultLineageRelation::Counter,
                parent_task_ref,
            });
        let spec = TaskCreateSpec::new(Value::Nil, None, None, Some(now))
            .with_kind(TaskKind::Consult)
            .with_consult(payload)
            .with_assignee(TaskAssignee::Peer {
                actor_ref: owning_actor_ref,
            })
            .with_ttl(TaskTtl::at(deadline_at));
        let validated = validate_task_create(self.vault(), &spec, now)?;
        let rate_now = unix_seconds_now();
        let (task_ref, route) = self.with_verified_actor_write_txn(|wtxn| {
            let parent = consult_body_in_txn(self.vault(), &*wtxn, parent_task_ref)?;
            self.require_auto_ceiling_in_txn(&*wtxn)?;
            if !consume_create_rate_slot(
                self.vault(),
                wtxn,
                self.actor(),
                rate_now,
                TaskCreateRateLimit::default(),
            )? {
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "counter exceeds the actor's create quota for this window",
                    "Retry the counter in the next window.",
                ));
            }
            let task_ref =
                self.mint_task_in_txn(wtxn, &validated, None, self.actor(), &provenance, now)?;
            // A counter routes through the same one door as any other create,
            // so a peer-addressed counter mints zero local attempts here too.
            let route = self.route_created_task_in_txn(wtxn, task_ref, &validated, now)?;
            if parent.terminal().is_none() {
                self.terminalize_countered_parent_in_txn(
                    wtxn,
                    parent_task_ref,
                    parent,
                    task_ref,
                    now,
                )?;
            }
            Ok((task_ref, route))
        })?;
        Ok(TaskCreateReceipt {
            task_ref: Some(task_ref),
            proposal_ref: None,
            approval: ClaimApprovalStatus::Auto,
            effected: true,
            route: Some(route),
        })
    }

    /// Writes the OLD task's terminal row: rejected on the ONE-1699 axis,
    /// `Countered` on the ladder axis, with a durable counter-lineage artifact
    /// as its `result_ref`.
    fn terminalize_countered_parent_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        parent_ref: EntityId,
        mut parent: TaskVerbBody,
        counter_task_ref: EntityId,
        now: u64,
    ) -> FacadeResult<()> {
        let result_ref = EntityId::now();
        let artifact = canonical_bytes(&counter_lineage_artifact_value(
            parent_ref,
            counter_task_ref,
            now,
        ));
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault()
            .batch_in()
            .put(&result_ref, ENTITY_TYPE_TURN, occurred, now, &artifact)
            .apply(wtxn)?;
        parent.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Rejected,
            result_ref: Some(result_ref),
            summary: None,
            finished_at: now,
            ladder: Some(LadderTerminalDisposition::Countered),
            counter_task_ref: Some(counter_task_ref),
        }));
        let encoded = encode_task_verb_body(parent);
        self.put_task_body_in_txn(wtxn, parent_ref, &encoded, now)
    }

    fn require_auto_ceiling_in_txn(&self, txn: &heed::RoTxn<'_>) -> FacadeResult<()> {
        let ceiling = task_actor_ceiling(self.vault(), txn, self.actor(), self.actor_class())?;
        if ceiling == PolicyApprovalCeiling::Auto {
            Ok(())
        } else {
            Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "this ladder write requires an auto-ceiling actor",
                "Create the consult through `tasks.create` so it surfaces its own proposal.",
            ))
        }
    }

    /// Routes one cross-actor entity-delta write.
    ///
    /// Ownership is RESOLVED from durable state, never asserted by the caller:
    /// a delta naming an owning actor the vault disagrees with is refused
    /// outright. "Auto" never means bypassing the write gate, the actor
    /// ceiling, or the standing-grant scope — it means the existing typed
    /// write path may proceed without a NEW owner-agent consult, because
    /// ownership or an already-receipted narrow grant already permits it.
    ///
    /// This function writes no target state on any branch. The consult branch
    /// writes exactly one TASK.
    pub fn route_entity_delta(
        &self,
        delta: EntityDeltaArtifact,
        graduation: Option<(&dyn GraduationLookup, &GraduationScope)>,
        deadline_at: u64,
        now: u64,
    ) -> FacadeResult<CrossActorRoute> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let owning_actor_ref = self.resolve_cross_actor_owner(&delta)?;
        if owning_actor_ref == self.actor() {
            return Ok(CrossActorRoute::AutoOwn);
        }
        if let Some((lookup, scope)) = graduation
            && scope.proposer_actor_ref == delta.proposer_actor_ref
            && scope.owning_actor_ref == owning_actor_ref
            && let NoveltyDecision::AutoKnownShape { standing_grant_ref } =
                novelty_guard(lookup, scope, &delta.shape)
        {
            return Ok(CrossActorRoute::AutoViaStandingGrant { standing_grant_ref });
        }
        let payload = self.entity_delta_payload(delta)?;
        let receipt = self.tasks_create(
            &TaskCreateSpec::new(Value::Nil, None, None, Some(now))
                .with_kind(TaskKind::Consult)
                .with_consult(payload)
                .with_assignee(TaskAssignee::Peer {
                    actor_ref: owning_actor_ref,
                })
                .with_ttl(TaskTtl::at(deadline_at)),
        )?;
        Ok(CrossActorRoute::ConsultOwner { receipt })
    }

    /// The two attribution laws every cross-actor delta answers to, and the
    /// owning actor they resolve.
    ///
    /// The proposer must BE the acting actor — a delta proposed "on behalf of"
    /// a third actor is an unattributed write — and the owning actor must be
    /// the one the target's own provenance names (ARCH-0043: actor = WHO, and
    /// WHO is read, never claimed).
    fn resolve_cross_actor_owner(&self, delta: &EntityDeltaArtifact) -> FacadeResult<EntityId> {
        if delta.proposer_actor_ref != self.actor() {
            return Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "the proposer of an entity delta must be the acting actor",
                "Route the delta as the actor that authored it.",
            ));
        }
        let owning_actor_ref = resolve_owning_actor(self.vault(), delta.target_ref)?.ok_or_else(
            || {
                consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "the target's owning actor does not resolve from durable state",
                    "Record the target's ownership provenance, or route the case as a pathology consult.",
                )
            },
        )?;
        if owning_actor_ref == delta.owning_actor_ref {
            Ok(owning_actor_ref)
        } else {
            Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "the delta names an owning actor the target's provenance contradicts",
                "Resolve the owning actor from the target's provenance before proposing.",
            ))
        }
    }

    /// Builds the consult payload for one entity-delta ask, binding every
    /// carried ref to a live entity of its declared kind first.
    fn entity_delta_payload(&self, delta: EntityDeltaArtifact) -> FacadeResult<ConsultPayload> {
        let vault = self.vault();
        require_resolved_entity(vault, delta.target_ref)?;
        require_resolved_entity(vault, delta.proposer_actor_ref)?;
        require_resolved_entity(vault, delta.owning_actor_ref)?;
        let question_ref = consult_payload_ref_for(vault, delta.delta_ref)?;
        let mut context_refs = Vec::new();
        for optional in [delta.base_state_ref, delta.message_thread_ref] {
            let Some(entity_ref) = optional else { continue };
            let carried = consult_payload_ref_for(vault, entity_ref)?;
            if carried != question_ref && !context_refs.contains(&carried) {
                context_refs.push(carried);
            }
        }
        Ok(
            ConsultPayload::question(question_ref, context_refs, EntityId::now())
                .with_entity_delta(delta),
        )
    }

    /// Renders the current TASKS section through the existing board renderer.
    ///
    /// The TASK type-index walk is bounded and paged, so a vault past the
    /// 100k-row `entities_by_type` cliff still renders a live board (ARCH-0067
    /// §2: the board is the dynamic tail, re-rendered every turn). What the
    /// scan or the render cap left out is stated in the section's additive
    /// overflow footer, never silently dropped.
    pub fn tasks_check(&self) -> FacadeResult<TasksSection> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Check));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let snapshot = task_presence(self.vault())?;
        Ok(TasksSection::render_bounded(
            &snapshot.intents,
            &snapshot.bare_jobs,
            snapshot.source_exhausted,
        ))
    }

    /// Expands one TASK intent through the existing Context Board projection.
    ///
    /// Direct by id: a row outside the collapsed board prefix is hidden, never
    /// gone, so this never inherits `tasks.check`'s scan cap.
    pub fn tasks_expand(&self, task_ref: EntityId) -> FacadeResult<Vec<String>> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Expand));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let Some(intent) = task_presence_for_id(self.vault(), task_ref)? else {
            return Err(FacadeError::from(Error::EntityNotFound));
        };
        // An acked failure has left the TASKS surface (the renderer drops it);
        // the typed read verbs must agree, so it is not expandable by id
        // either.
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
        //
        // Direct by id, like `tasks.expand`: a failed row past the board scan
        // prefix must stay acknowledgeable.
        let Some(intent) = task_presence_for_id(self.vault(), task_ref)? else {
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

/// The actor whose ceiling admitted this create. ONE-1708's follow-up driver
/// sends its reminders as this actor, so a nudge rides the same gate, budget
/// and delivery-window pipeline as any other send the owner makes.
pub(crate) fn task_create_owner(vault: &Vault, task_ref: EntityId) -> Result<Option<EntityId>> {
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
        // ONE-1888 additions. Absent (nil) is the ONE-1699 question shape.
        (
            Value::from("purpose"),
            payload
                .purpose
                .map_or(Value::Nil, |purpose| Value::from(purpose.as_str())),
        ),
        (
            Value::from("entity_delta"),
            payload
                .entity_delta
                .as_ref()
                .map_or(Value::Nil, entity_delta_artifact_value),
        ),
        (
            Value::from("lineage"),
            payload.lineage.map_or(Value::Nil, consult_lineage_value),
        ),
    ])
}

fn entity_delta_shape_value(shape: &EntityDeltaShape) -> Value {
    Value::Map(vec![
        (
            Value::from("operation_kind"),
            Value::from(shape.operation_kind.as_str()),
        ),
        (
            Value::from("target_entity_type"),
            Value::from(shape.target_entity_type),
        ),
        (
            Value::from("normalized_paths"),
            Value::Array(
                shape
                    .normalized_paths
                    .iter()
                    .map(|path| Value::from(path.as_str()))
                    .collect(),
            ),
        ),
    ])
}

fn entity_delta_artifact_value(delta: &EntityDeltaArtifact) -> Value {
    Value::Map(vec![
        (
            Value::from("target_ref"),
            entity_ref_value(delta.target_ref),
        ),
        (
            Value::from("base_state_ref"),
            delta.base_state_ref.map_or(Value::Nil, entity_ref_value),
        ),
        (Value::from("delta_ref"), entity_ref_value(delta.delta_ref)),
        (Value::from("shape"), entity_delta_shape_value(&delta.shape)),
        (
            Value::from("proposer_actor_ref"),
            entity_ref_value(delta.proposer_actor_ref),
        ),
        (
            Value::from("owning_actor_ref"),
            entity_ref_value(delta.owning_actor_ref),
        ),
        (
            Value::from("message_thread_ref"),
            delta
                .message_thread_ref
                .map_or(Value::Nil, entity_ref_value),
        ),
    ])
}

fn consult_lineage_value(lineage: ConsultLineage) -> Value {
    Value::Map(vec![
        (
            Value::from("relation"),
            Value::from(lineage.relation.as_str()),
        ),
        (
            Value::from("parent_task_ref"),
            entity_ref_value(lineage.parent_task_ref),
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
        (
            Value::from("ladder"),
            record
                .ladder
                .map_or(Value::Nil, |ladder| Value::from(ladder.as_str())),
        ),
        (
            Value::from("counter_task_ref"),
            record.counter_task_ref.map_or(Value::Nil, entity_ref_value),
        ),
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

fn encode_task_verb_body(body: TaskVerbBody) -> Vec<u8> {
    let value = Value::Map(vec![
        (Value::from("role"), Value::from(body.role)),
        (
            Value::from("schema_version"),
            Value::from(body.schema_version),
        ),
        (Value::from("subkind"), Value::from(body.subkind)),
        (
            Value::from("kind"),
            body.kind
                .map_or(Value::Nil, |kind| Value::from(kind.as_str())),
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
    canonical_bytes(&value)
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
    let rtxn = vault.store.env.read_txn()?;
    task_entity_role_in(vault, &rtxn, task_ref)
}

/// Transaction-scoped role read, so a board page classifies its rows without
/// opening a second entity transaction per id.
fn task_entity_role_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<TaskRole>> {
    let Some(raw) = vault.get_raw_in(rtxn, &task_ref)? else {
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
    let entity_ref =
        decode_entity_ref(task_body_field(entries, "entity_ref")?, "tasks.consult.ref")?;
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
        // A ONE-1699 row carries none of these keys; absent decodes to `None`,
        // and `None` is the legacy question shape.
        purpose: task_body_optional(entries, "purpose")?
            .map(|value| {
                value
                    .as_str()
                    .and_then(ConsultPurpose::from_token)
                    .ok_or(Error::InvalidTaskBody("tasks.consult.purpose"))
            })
            .transpose()?,
        entity_delta: task_body_optional(entries, "entity_delta")?
            .map(decode_entity_delta_artifact)
            .transpose()?,
        lineage: task_body_optional(entries, "lineage")?
            .map(decode_consult_lineage)
            .transpose()?,
    };
    payload.validate()?;
    Ok(payload)
}

fn decode_entity_delta_shape(value: &Value) -> Result<EntityDeltaShape> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?;
    let normalized_paths = task_body_field(entries, "normalized_paths")?
        .as_array()
        .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(EntityDeltaShape {
        operation_kind: task_body_field(entries, "operation_kind")?
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?,
        target_entity_type: task_body_field(entries, "target_entity_type")?
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?,
        normalized_paths,
    })
}

fn decode_entity_delta_artifact(value: &Value) -> Result<EntityDeltaArtifact> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.entity_delta"))?;
    let optional_ref = |name| -> Result<Option<EntityId>> {
        task_body_optional(entries, name)?
            .map(|value| decode_entity_ref(value, "tasks.consult.entity_delta"))
            .transpose()
    };
    Ok(EntityDeltaArtifact {
        target_ref: decode_entity_ref(
            task_body_field(entries, "target_ref")?,
            "tasks.consult.entity_delta",
        )?,
        base_state_ref: optional_ref("base_state_ref")?,
        delta_ref: decode_entity_ref(
            task_body_field(entries, "delta_ref")?,
            "tasks.consult.entity_delta",
        )?,
        shape: decode_entity_delta_shape(task_body_field(entries, "shape")?)?,
        proposer_actor_ref: decode_entity_ref(
            task_body_field(entries, "proposer_actor_ref")?,
            "tasks.consult.entity_delta",
        )?,
        owning_actor_ref: decode_entity_ref(
            task_body_field(entries, "owning_actor_ref")?,
            "tasks.consult.entity_delta",
        )?,
        message_thread_ref: optional_ref("message_thread_ref")?,
    })
}

fn decode_consult_lineage(value: &Value) -> Result<ConsultLineage> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.lineage"))?;
    Ok(ConsultLineage {
        relation: task_body_field(entries, "relation")?
            .as_str()
            .and_then(ConsultLineageRelation::from_token)
            .ok_or(Error::InvalidTaskBody("tasks.consult.lineage"))?,
        parent_task_ref: decode_entity_ref(
            task_body_field(entries, "parent_task_ref")?,
            "tasks.consult.lineage",
        )?,
    })
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
        ladder: task_body_optional(entries, "ladder")?
            .map(|value| {
                value
                    .as_str()
                    .and_then(LadderTerminalDisposition::from_token)
                    .ok_or(Error::InvalidTaskBody("tasks.terminal.ladder"))
            })
            .transpose()?,
        counter_task_ref: task_body_optional(entries, "counter_task_ref")?
            .map(|value| decode_entity_ref(value, "tasks.body.terminal"))
            .transpose()?,
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
/// Two branches: a peer-addressed consult with a typed payload, a future
/// deadline and a `Nil` spec (ONE-1699); and a standard task on any routable
/// assignee (ONE-1700). Every assignee binds to a live entity of the right kind
/// HERE, before the write transaction opens, so a dangling or unroutable
/// assignee leaves no partial task behind.
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
            for payload_ref in
                std::iter::once(payload.question_ref).chain(payload.context_refs.iter().copied())
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
        (TaskKind::Standard, None, assignee, ttl) => {
            if let Some(assignee) = assignee {
                // A human assignee binds to a live entity HERE like every other
                // lane; whether that person has a NATIVE route is settled
                // inside the create transaction, so a known-but-unreachable
                // person rolls the whole create back instead of leaving a human
                // task nothing is tracking.
                assignee.validate(vault)?;
            }
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

/// The one local-realization dedupe key per TASK, shared by both local lanes so
/// a retried route returns the existing attempt instead of minting a second.
fn task_route_dedupe_key(task_ref: EntityId) -> String {
    format!("task:{}", task_ref.to_hex())
}

/// Surfaces a native-human routing refusal in its own name. A person the vault
/// knows but cannot currently reach is NOT a missing entity and NOT a reason to
/// fall through to Dreamer realization — the TASK simply does not get created,
/// and the caller is told which of the two it was.
fn human_route_refusal(error: HumanTaskError) -> FacadeError {
    match error {
        HumanTaskError::Engine(error) => FacadeError::from(error),
        HumanTaskError::NotAPerson => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "a human assignee must be a person",
            "Assign the task to the dreamer, an agent definition, or a peer actor.",
        ),
        HumanTaskError::NotNativelyReachable => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "known person is not currently reachable through a native route",
            "Connect a channel this person is reachable on, then assign the task.",
        ),
        // Belongs to the response half of the module and cannot arise from
        // route resolution; it is still spelled out rather than folded into a
        // neighbouring message that would misreport what happened.
        HumanTaskError::UnboundResponse => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "human response does not match its wait binding",
            "Signal the response against the binding that names this task, person, and step.",
        ),
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

/// Reads one typed TASK body of any kind inside a live transaction.
fn task_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    task_verb_body_in(vault, rtxn, task_ref)?
        .ok_or_else(|| FacadeError::from(Error::EntityNotFound))
}

/// Reads one NON-consult TASK body inside a live transaction.
///
/// The general result door routes through here so a consult can never settle
/// through it: a consult's terminal record must carry the ONE-1699
/// evidence-or-abstention summary, and the general input has no way to express
/// one. Sending a consult back to its own door keeps that contract the only
/// path to a terminal consult, rather than one of two.
fn standard_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    let body = task_body_in_txn(vault, rtxn, task_ref)?;
    if body.task_kind() == TaskKind::Consult {
        return Err(consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "a consult settles through the consult result door, not the general one",
            "Land the answer or reasoned abstention with land_consult_result.",
        ));
    }
    Ok(body)
}

/// Reads one TASK body as a consult inside a live transaction.
fn consult_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    let body = task_body_in_txn(vault, rtxn, task_ref)?;
    if body.task_kind() != TaskKind::Consult {
        return Err(FacadeError::bad_request("target task is not a consult"));
    }
    Ok(body)
}

/// The PERSON one TASK is assigned to, or `None` on every other lane. The
/// follow-up cursor is derived state, so this is how a lost cursor is rebuilt
/// from the authoritative synced fact.
pub(crate) fn task_human_assignee(vault: &Vault, task_ref: EntityId) -> Result<Option<EntityId>> {
    Ok(
        task_verb_body(vault, task_ref)?.and_then(|body| match body.assignee {
            Some(TaskAssignee::Human { actor_ref }) => Some(actor_ref),
            None
            | Some(
                TaskAssignee::Dreamer | TaskAssignee::AgentDef { .. } | TaskAssignee::Peer { .. },
            ) => None,
        }),
    )
}

/// Whether this replica has settled the TASK. The C9 peer-result signal reads
/// it as its no-early-resume guard: a queued or working delegation has nothing
/// to resume on.
pub(crate) fn task_is_terminal(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    Ok(task_verb_body(vault, task_ref)?
        .and_then(|body| body.state)
        .is_some_and(|state| state.terminal().is_some()))
}

/// Canonical outbound idempotency/dedupe key in the shared task-follow-up
/// namespace. ONE-1708's human follow-up stages key the same way, so one task
/// never double-notifies across follow-up families.
#[must_use]
pub fn task_follow_up_dedupe_key(task_ref: EntityId, stage: &str) -> String {
    format!("{TASK_FOLLOW_UP_NAMESPACE}:{}:{stage}", task_ref.to_hex())
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

/// Transaction-scoped handle read: the only caller is page hydration, which
/// already holds its page's shared read transaction.
fn peer_handle_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor_ref: EntityId,
) -> Result<Option<String>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, peer_handle_key(actor_ref).as_slice())?
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

// ── consult ladder durable bridge (ONE-1888) ────────────────────────────

/// Where one cross-actor entity-delta write went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossActorRoute {
    /// The writer owns the target: the existing typed write path applies.
    AutoOwn,
    /// A graduated pair on an already-receipted shape: the existing standing
    /// grant applies, with no NEW owner-agent consult.
    AutoViaStandingGrant { standing_grant_ref: EntityId },
    /// The owning actor is the first adjudicator.
    ConsultOwner { receipt: TaskCreateReceipt },
}

/// One landed ladder step, in both vocabularies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderTransitionReceipt {
    pub task_ref: EntityId,
    pub ladder_state: ConsultLadderState,
    pub task_state: TaskExecutionState,
}

/// Projects the pure ladder state onto the fields ONE-1699 already persists.
///
/// `Escalated` is deliberately NOT a terminal record: the case is waiting on
/// the follow-on assignee named in its escalation receipt, so it persists as
/// `Interrupted`. `Approved`/`Overridden` both persist as `Completed` and
/// `Countered` as `Rejected` — the finer ladder vocabulary rides inside the
/// same single terminal register rather than widening the ONE-1699 axis.
#[must_use]
pub fn project_consult_ladder_state(state: &ConsultLadderState) -> TaskExecutionState {
    match state {
        ConsultLadderState::Working(working) => TaskExecutionState::Working {
            started_at: working.started_at,
        },
        ConsultLadderState::Interrupted(_) => TaskExecutionState::Interrupted,
        ConsultLadderState::Terminal(terminal) => {
            if terminal.disposition.defers_to_follow_on() {
                return TaskExecutionState::Interrupted;
            }
            TaskExecutionState::Terminal(TaskTerminalRecord {
                disposition: task_disposition_for_ladder(terminal.disposition),
                result_ref: Some(terminal.result_ref),
                summary: None,
                finished_at: terminal.finished_at,
                ladder: Some(terminal.disposition),
                counter_task_ref: terminal.counter_task_ref,
            })
        }
    }
}

/// The ONE-1699 disposition each non-deferring ladder outcome persists as.
const fn task_disposition_for_ladder(
    disposition: LadderTerminalDisposition,
) -> TaskTerminalDisposition {
    match disposition {
        LadderTerminalDisposition::Approved | LadderTerminalDisposition::Overridden => {
            TaskTerminalDisposition::Completed
        }
        // A counter is a rejection that named its successor. It is never
        // `Failed`: the owner decided, the machine did not break.
        LadderTerminalDisposition::Rejected | LadderTerminalDisposition::Countered => {
            TaskTerminalDisposition::Rejected
        }
        LadderTerminalDisposition::Failed => TaskTerminalDisposition::Failed,
        LadderTerminalDisposition::Abandoned => TaskTerminalDisposition::Abandoned,
        // Unreachable for `Escalated`, which never reaches a terminal record.
        LadderTerminalDisposition::Escalated => TaskTerminalDisposition::Failed,
    }
}

/// Lifts one persisted terminal register back into the pure ladder terminal.
///
/// A ONE-1699 row that carries no `result_ref` cannot become a ladder terminal
/// at all — the ladder's `result_ref` is not optional — so it fails closed.
///
/// # Errors
///
/// [`LadderTransitionError::MissingResultRef`] when the persisted record has
/// no durable result.
pub fn ladder_terminal_from_task_terminal(
    record: &TaskTerminalRecord,
) -> std::result::Result<LadderTerminalState, LadderTransitionError> {
    let result_ref = record
        .result_ref
        .ok_or(LadderTransitionError::MissingResultRef)?;
    Ok(LadderTerminalState {
        disposition: record
            .ladder
            .unwrap_or_else(|| ladder_disposition_for_task(record.disposition)),
        result_ref,
        counter_task_ref: record.counter_task_ref,
        finished_at: record.finished_at,
    })
}

/// The ladder reading of a pre-ONE-1888 terminal row. `Completed` reads as
/// `Approved` and `Expired`/`Cancelled` as `Abandoned`: an unstamped row
/// carries no finer outcome, and inventing one would be worse than widening.
const fn ladder_disposition_for_task(
    disposition: TaskTerminalDisposition,
) -> LadderTerminalDisposition {
    match disposition {
        TaskTerminalDisposition::Completed => LadderTerminalDisposition::Approved,
        TaskTerminalDisposition::Rejected => LadderTerminalDisposition::Rejected,
        TaskTerminalDisposition::Failed => LadderTerminalDisposition::Failed,
        TaskTerminalDisposition::Expired
        | TaskTerminalDisposition::Abandoned
        | TaskTerminalDisposition::Cancelled => LadderTerminalDisposition::Abandoned,
    }
}

/// The instant one ladder state settled on, for the entity envelope.
const fn now_for_ladder(state: &ConsultLadderState) -> u64 {
    match state {
        ConsultLadderState::Working(working) => working.started_at,
        ConsultLadderState::Interrupted(interrupted) => interrupted.interrupted_at,
        ConsultLadderState::Terminal(terminal) => terminal.finished_at,
    }
}

fn ladder_refusal(error: LadderTransitionError) -> FacadeError {
    match error {
        LadderTransitionError::TerminalImmutable => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "a terminal consult is immutable",
            "Mint a counter, appeal, or escalation task with lineage instead of reopening this one.",
        ),
        LadderTransitionError::ConsentRequired => consult_refusal(
            FACADE_CODE_FORBIDDEN,
            "this interruption resumes only through a human verdict",
            "Apply the typed human verdict, then finish the ladder.",
        ),
        LadderTransitionError::InvalidTransition => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "the requested ladder transition has no meaning from this state",
            "Read the current ladder state and choose a transition it admits.",
        ),
        LadderTransitionError::MissingResultRef => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "the persisted terminal record carries no result ref",
            "Terminal ladder states require a durable result; settle through the ladder path.",
        ),
    }
}

/// Projects one consult TASK onto A2A task vocabulary. Projection only — this
/// is neither an A2A server nor a conformance claim.
pub fn project_consult_task_to_a2a(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<A2aTaskProjection>> {
    let Some(body) = task_verb_body(vault, task_ref)? else {
        return Ok(None);
    };
    let Some(state) = &body.state else {
        return Ok(None);
    };
    let ladder = match state {
        // A2A has no `queued`: a task that exists and has not been paused is
        // progressing, which is exactly what `working` says.
        TaskExecutionState::Queued => {
            ConsultLadderState::Working(crate::consult_ladder::WorkingState {
                started_at: body.created_at,
                decision_round: 0,
            })
        }
        TaskExecutionState::Working { started_at } => {
            ConsultLadderState::Working(crate::consult_ladder::WorkingState {
                started_at: *started_at,
                decision_round: 0,
            })
        }
        // ONE-1699's body keeps interruption DETAIL in the referenced case, so
        // the kind is unknown here. `consent_required` is the fail-closed
        // reading — durably paused progress is not progress — and the invented
        // kind is stripped from the projection below rather than guessed at.
        TaskExecutionState::Interrupted => {
            ConsultLadderState::Interrupted(crate::consult_ladder::InterruptedState {
                kind: crate::consult_ladder::InterruptionKind::Contested,
                consent_required: true,
                case_ref: task_ref,
                interrupted_at: body.created_at,
            })
        }
        TaskExecutionState::Terminal(record) => match ladder_terminal_from_task_terminal(record) {
            Ok(terminal) => ConsultLadderState::Terminal(terminal),
            Err(_) => return Ok(None),
        },
    };
    let mut projection = project_to_a2a(
        task_ref,
        &ladder,
        body.consult.as_ref().and_then(|consult| consult.lineage),
    );
    projection.extensions.interruption_kind = None;
    // An UNSTAMPED ONE-1699 terminal has no ladder outcome to project, so its
    // own disposition rides through verbatim: `expired` stays expired rather
    // than being rounded to the nearest ladder word.
    if let TaskExecutionState::Terminal(record) = state
        && record.ladder.is_none()
    {
        projection.extensions.terminal_disposition = Some(record.disposition.as_str().to_owned());
    }
    Ok(Some(projection))
}

/// Binds one durable ref to the typed consult-ref kind it actually is.
fn consult_payload_ref_for(vault: &Vault, entity_ref: EntityId) -> FacadeResult<ConsultPayloadRef> {
    match vault.get_entity_type(&entity_ref)? {
        Some(ENTITY_TYPE_CLAIM) => Ok(ConsultPayloadRef::Claim(entity_ref)),
        Some(ENTITY_TYPE_TURN) => Ok(ConsultPayloadRef::Turn(entity_ref)),
        _ => Err(FacadeError::bad_request(
            "a consult ref must resolve to a stored CLAIM or TURN entity",
        )),
    }
}

/// Resolves the AUTHORITATIVE owning actor of one target from durable state.
///
/// A TASK's owner is the record stamped atomically by the verified
/// `tasks.create` path; a CLAIM's owner is the actor its write envelope
/// recorded. Anything else has no recorded owner, and an unresolvable owner is
/// a pathology, not a licence to trust the caller (ARCH-0043: actor = WHO).
fn resolve_owning_actor(vault: &Vault, target_ref: EntityId) -> Result<Option<EntityId>> {
    match vault.get_entity_type(&target_ref)? {
        Some(ENTITY_TYPE_TASK) => task_create_owner(vault, target_ref),
        Some(ENTITY_TYPE_CLAIM) => {
            Ok(claim_envelope_actor(vault, target_ref)?.map(|env| env.actor))
        }
        _ => Ok(None),
    }
}

/// The durable counter-lineage artifact one countered TASK keeps as its
/// `result_ref`. Typed refs only.
fn counter_lineage_artifact_value(
    parent_task_ref: EntityId,
    counter_task_ref: EntityId,
    occurred_at: u64,
) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("consult.counter")),
        (
            Value::from("parent_task_ref"),
            entity_ref_value(parent_task_ref),
        ),
        (
            Value::from("counter_task_ref"),
            entity_ref_value(counter_task_ref),
        ),
        (Value::from("occurred_at"), Value::from(occurred_at)),
    ])
}

// ── Dreamer magistrate bridge (ONE-1888) ────────────────────────────────

/// The write-envelope provenance keys that mark a Dreamer-run write. They
/// mirror `gate.rs`'s private reader over the SAME wire map that
/// `dreamer_promotion` stamps; the gate owns its copy and this module owns
/// this one, because 1888 consumes gate.rs read-only.
const DREAMER_PROVENANCE_SURFACE_KEYS: [&str; 2] = ["surface", "runner"];

/// The write actor and provenance one stored claim recorded.
struct ClaimEnvelopeAttribution {
    actor: EntityId,
    actor_class: EdgeActorClass,
    provenance: Value,
}

/// Recovers the write-envelope attribution stamped on one stored claim.
fn claim_envelope_actor(
    vault: &Vault,
    claim_ref: EntityId,
) -> Result<Option<ClaimEnvelopeAttribution>> {
    let Some(body) = vault.get_claim(&claim_ref)? else {
        return Ok(None);
    };
    Ok(claim_envelope_attribution(&body))
}

fn claim_envelope_attribution(body: &ClaimBody) -> Option<ClaimEnvelopeAttribution> {
    let Some(Value::Map(entries)) = &body.evidence else {
        return None;
    };
    let mut actor = None;
    let mut actor_class = None;
    let mut provenance = None;
    for (key, value) in entries {
        match key.as_str() {
            Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) => {
                if let Value::Binary(bytes) = value
                    && let Ok(raw) = <[u8; 16]>::try_from(bytes.as_slice())
                {
                    actor = EntityId::from_bytes(raw).ok();
                }
            }
            Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY) => {
                actor_class = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .and_then(EdgeActorClass::try_from_u8);
            }
            Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY) => {
                provenance = Some(value.clone());
            }
            _ => {}
        }
    }
    Some(ClaimEnvelopeAttribution {
        actor: actor?,
        actor_class: actor_class?,
        provenance: provenance?,
    })
}

/// Whether one write-envelope provenance map names the Dreamer runner surface.
fn provenance_is_dreamer(provenance: &Value) -> bool {
    let Value::Map(entries) = provenance else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str()
            .is_some_and(|key| DREAMER_PROVENANCE_SURFACE_KEYS.contains(&key))
            && value.as_str() == Some(DREAMER_RUNNER_ATTEMPT_KIND)
    })
}

/// Derives WHO authored the contested state, from the vault alone.
///
/// The traversal is deliberately unforgeable: it loads the contested state and
/// delta claims, reads their write-envelope attribution, VALIDATES the
/// recorded actor class against the actor entity's own kind, and only then
/// classifies. No caller field participates, because `MagistrateCase` carries
/// none — a summary a caller can write is a summary a caller can forge.
///
/// `ClaimSource::Generated` alone is NOT the test: dispatched agents generate
/// state too. The discriminator is the Dreamer RUN surface on the envelope
/// provenance, and Dreamer authorship of EITHER the contested state or the
/// contested delta recuses — recusal is the conservative direction.
///
/// # Errors
///
/// Fails closed when the contested state carries no recoverable attribution:
/// an unattributable state is not one the writer may rule on.
pub(crate) fn derive_state_authorship(
    vault: &Vault,
    case: &MagistrateCase,
) -> Result<StateAuthorship> {
    let state = resolve_authorship(vault, case.contested_state_ref)?
        .ok_or(Error::InvalidClaimBody("magistrate.state_authorship"))?;
    if state == StateAuthorship::Dreamer {
        return Ok(state);
    }
    match resolve_authorship(vault, case.contested_delta_ref)? {
        Some(StateAuthorship::Dreamer) => Ok(StateAuthorship::Dreamer),
        _ => Ok(state),
    }
}

fn resolve_authorship(vault: &Vault, claim_ref: EntityId) -> Result<Option<StateAuthorship>> {
    let Some(attribution) = claim_envelope_actor(vault, claim_ref)? else {
        return Ok(None);
    };
    let Some(actor_entity_type) = vault.get_entity_type(&attribution.actor)? else {
        return Ok(None);
    };
    // D13: the recorded class must be one the actor entity's kind admits. A
    // row claiming `human` over a MACHINE actor is rejected, not defaulted.
    validate_actor_class(actor_entity_type, attribution.actor_class)?;
    if provenance_is_dreamer(&attribution.provenance) {
        return Ok(Some(StateAuthorship::Dreamer));
    }
    Ok(Some(match attribution.actor_class {
        EdgeActorClass::Human => StateAuthorship::Human,
        EdgeActorClass::Agent => StateAuthorship::OtherAgent,
        EdgeActorClass::System => StateAuthorship::System,
    }))
}

/// Rules on one contested case.
///
/// Authorship is re-derived from the vault BEFORE any evidence is weighed, so
/// a forged "other agent" summary cannot buy a Dreamer-authored case a ruling.
///
/// # Errors
///
/// Propagates the authorship derivation's fail-closed errors.
pub fn decide_magistrate(vault: &Vault, case: &MagistrateCase) -> Result<MagistrateVerdict> {
    let authorship = derive_state_authorship(vault, case)?;
    Ok(decide_magistrate_from_derived_authorship(case, authorship))
}

/// Applies one magistrate verdict and writes its durable receipt.
///
/// The effector floor is STRUCTURAL, not a checklist: the whole write set is
/// (a) the receipt artifact, (b) an existing `Vault::supersede_claim` call
/// when a claim is replaced, and (c) an existing `core.conflict.open` claim
/// when competing live claims remain. No connector, no outbound intent, no
/// destructive delete, no grant widening, no authority edit — none of those
/// APIs is reachable from here.
///
/// Advice, recusal, and pathology write the receipt and NOTHING else: a
/// critical case cannot be terminalized by the Dreamer at all.
///
/// # Errors
///
/// Propagates claim/write failures; nothing partial is committed.
pub fn apply_magistrate_verdict(
    vault: &Vault,
    magistrate_actor: WriteActor,
    case: &MagistrateCase,
    verdict: &MagistrateVerdict,
) -> Result<MagistrateReceipt> {
    let receipt = MagistrateReceipt {
        receipt_ref: EntityId::now(),
        task_ref: case.task_ref,
        verdict: *verdict,
        decisive_layer: magistrate_decision_layer(case, *verdict),
        considered_policy_refs: case.policy.iter().map(|entry| entry.policy_ref).collect(),
        considered_authority_refs: case
            .authority
            .iter()
            .map(|entry| entry.authoritative_actor_ref)
            .collect(),
        considered_temporal_refs: case
            .temporal
            .iter()
            .filter_map(|entry| entry.selected_delta_ref)
            .collect(),
        dreamer_attempt_ref: case.dreamer_attempt_ref,
        // Appeals are filed against the TASK the ruling settled.
        appeal_handle: case.task_ref,
        reversible: true,
        occurred_at: case.now,
    };
    let selected = match verdict {
        MagistrateVerdict::Rule {
            selected_delta_ref, ..
        } => Some(*selected_delta_ref),
        _ => None,
    };
    let envelope = magistrate_envelope(magistrate_actor)?;
    let occurred = TimeRange {
        start: case.now,
        end: case.now,
    };
    let body = canonical_bytes(&magistrate_receipt_value(&receipt));
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put(
                &receipt.receipt_ref,
                ENTITY_TYPE_TURN,
                occurred,
                case.now,
                &body,
            )
            .apply(wtxn)?;
        let Some(selected) = selected else {
            return Ok(());
        };
        apply_magistrate_selection_in_txn(vault, wtxn, case, selected, &envelope)
    })?;
    Ok(receipt)
}

/// The reversible half of a ruling: supersede the replaced head, and open a
/// conflict claim when other live candidates survive the choice.
fn apply_magistrate_selection_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    case: &MagistrateCase,
    selected: EntityId,
    envelope: &WriteEnvelope,
) -> Result<()> {
    if selected != case.contested_state_ref
        && claim_is_active(vault, selected)?
        && claim_is_active(vault, case.contested_state_ref)?
    {
        vault.supersede_claim_in_txn(wtxn, &selected, &case.contested_state_ref, case.now)?;
    }
    let mut competing: Vec<EntityId> = Vec::new();
    for candidate in &case.candidate_delta_refs {
        if *candidate != selected
            && *candidate != case.contested_state_ref
            && claim_is_active(vault, *candidate)?
        {
            competing.push(*candidate);
        }
    }
    if competing.is_empty() {
        return Ok(());
    }
    vault
        .batch_in()
        .conflict_open_claim(
            &EntityId::now(),
            case.contested_state_ref,
            magistrate_conflict_value(case, selected, &competing),
            1.0,
            envelope,
            TimeRange {
                start: case.now,
                end: case.now,
            },
            case.now,
        )
        .apply(wtxn)?;
    Ok(())
}

fn claim_is_active(vault: &Vault, claim_ref: EntityId) -> Result<bool> {
    Ok(vault
        .get_claim(&claim_ref)?
        .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active))
}

/// The conflict value. Deliberately avoids the `kind`/`schema_version` keys —
/// `claim.rs` reads those as the repo-mutation conflict schema.
fn magistrate_conflict_value(
    case: &MagistrateCase,
    selected: EntityId,
    competing: &[EntityId],
) -> Value {
    Value::Map(vec![
        (
            Value::from("conflict_kind"),
            Value::from("consult_ladder.magistrate"),
        ),
        (Value::from("task_ref"), entity_ref_value(case.task_ref)),
        (
            Value::from("contested_state_ref"),
            entity_ref_value(case.contested_state_ref),
        ),
        (
            Value::from("selected_delta_ref"),
            entity_ref_value(selected),
        ),
        (
            Value::from("competing_delta_refs"),
            Value::Array(competing.iter().copied().map(entity_ref_value).collect()),
        ),
    ])
}

fn magistrate_envelope(magistrate_actor: WriteActor) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        magistrate_actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("surface"),
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (
                Value::from("attempt_type"),
                Value::from(DREAMER_MAGISTRATE_ATTEMPT_TYPE),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
    ))
}

/// Enqueues one magistrate attempt onto the EXISTING Dreamer runner queue as a
/// payload-level attempt type — the `AGENT_DISPATCH_ATTEMPT_TYPE` pattern. No
/// new queue kind, admission rule, lease, or budget.
///
/// # Errors
///
/// Propagates the runner's enqueue failures.
pub fn enqueue_magistrate(
    store: &DreamerRunnerStore<'_>,
    case: &MagistrateCase,
    parent_attempt: Option<AttemptId>,
    run_id: Option<String>,
) -> Result<EnqueueDreamerAttemptOutcome> {
    store.enqueue(EnqueueDreamerAttempt {
        attempt_type: DREAMER_MAGISTRATE_ATTEMPT_TYPE.to_owned(),
        input: magistrate_case_value(case),
        parent_attempt,
        dedupe_key: Some(format!(
            "{DREAMER_MAGISTRATE_ATTEMPT_TYPE}:{}",
            case.task_ref.to_hex()
        )),
        run_id,
        now: case.now,
    })
}

/// Persists one overturn record — the COMPLETE ED training-signal handoff.
/// The ED lane may consume it later; this ticket calls no ED code, enqueues no
/// ED job, and adds no ED dependency.
///
/// # Errors
///
/// Propagates the entity write failure.
pub fn record_magistrate_overturn(
    vault: &Vault,
    record: &MagistrateOverturnRecord,
) -> Result<EntityId> {
    let overturn_ref = EntityId::now();
    let body = canonical_bytes(&magistrate_overturn_value(record));
    let occurred = TimeRange {
        start: record.occurred_at,
        end: record.occurred_at,
    };
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put(
                &overturn_ref,
                ENTITY_TYPE_TURN,
                occurred,
                record.occurred_at,
                &body,
            )
            .apply(wtxn)
    })?;
    Ok(overturn_ref)
}

fn magistrate_verdict_value(verdict: MagistrateVerdict) -> Value {
    let mut entries = vec![(Value::from("verdict"), Value::from(verdict.as_str()))];
    match verdict {
        MagistrateVerdict::Rule {
            selected_delta_ref,
            rationale_ref,
        } => {
            entries.push((
                Value::from("selected_delta_ref"),
                entity_ref_value(selected_delta_ref),
            ));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        MagistrateVerdict::Reject { rationale_ref }
        | MagistrateVerdict::EscalatePathology { rationale_ref } => {
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        MagistrateVerdict::AdviceOnly {
            recommended_delta_ref,
            rationale_ref,
        } => {
            entries.push((
                Value::from("recommended_delta_ref"),
                recommended_delta_ref.map_or(Value::Nil, entity_ref_value),
            ));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        MagistrateVerdict::Recused { reason } => {
            entries.push((Value::from("reason"), Value::from(reason.as_str())));
        }
    }
    Value::Map(entries)
}

fn magistrate_receipt_value(receipt: &MagistrateReceipt) -> Value {
    let refs = |entries: &[EntityId]| {
        Value::Array(entries.iter().copied().map(entity_ref_value).collect())
    };
    Value::Map(vec![
        (
            Value::from("kind"),
            Value::from("consult.magistrate_receipt"),
        ),
        (
            Value::from("receipt_ref"),
            entity_ref_value(receipt.receipt_ref),
        ),
        (Value::from("task_ref"), entity_ref_value(receipt.task_ref)),
        (
            Value::from("verdict"),
            magistrate_verdict_value(receipt.verdict),
        ),
        (
            Value::from("decisive_layer"),
            Value::from(receipt.decisive_layer.as_str()),
        ),
        (
            Value::from("considered_policy_refs"),
            refs(&receipt.considered_policy_refs),
        ),
        (
            Value::from("considered_authority_refs"),
            refs(&receipt.considered_authority_refs),
        ),
        (
            Value::from("considered_temporal_refs"),
            refs(&receipt.considered_temporal_refs),
        ),
        (
            Value::from("dreamer_attempt_ref"),
            receipt
                .dreamer_attempt_ref
                .map_or(Value::Nil, |attempt| Value::from(attempt_hex(attempt))),
        ),
        (
            Value::from("appeal_handle"),
            entity_ref_value(receipt.appeal_handle),
        ),
        (Value::from("reversible"), Value::from(receipt.reversible)),
        (Value::from("occurred_at"), Value::from(receipt.occurred_at)),
    ])
}

fn magistrate_overturn_value(record: &MagistrateOverturnRecord) -> Value {
    Value::Map(vec![
        (
            Value::from("kind"),
            Value::from("consult.magistrate_overturn"),
        ),
        (
            Value::from("original_receipt_ref"),
            entity_ref_value(record.original_receipt_ref),
        ),
        (
            Value::from("overturning_verdict_ref"),
            entity_ref_value(record.overturning_verdict_ref),
        ),
        (
            Value::from("corrected_delta_ref"),
            record
                .corrected_delta_ref
                .map_or(Value::Nil, entity_ref_value),
        ),
        (
            Value::from("rationale_ref"),
            entity_ref_value(record.rationale_ref),
        ),
        (Value::from("occurred_at"), Value::from(record.occurred_at)),
    ])
}

fn magistrate_case_value(case: &MagistrateCase) -> Value {
    Value::Map(vec![
        (Value::from("task_ref"), entity_ref_value(case.task_ref)),
        (
            Value::from("contested_state_ref"),
            entity_ref_value(case.contested_state_ref),
        ),
        (
            Value::from("contested_delta_ref"),
            entity_ref_value(case.contested_delta_ref),
        ),
        (
            Value::from("criticality"),
            Value::from(match case.criticality {
                crate::consult_ladder::CaseCriticality::Normal => "normal",
                crate::consult_ladder::CaseCriticality::Critical => "critical",
            }),
        ),
        (
            Value::from("candidate_delta_refs"),
            Value::Array(
                case.candidate_delta_refs
                    .iter()
                    .copied()
                    .map(entity_ref_value)
                    .collect(),
            ),
        ),
        (Value::from("now"), Value::from(case.now)),
    ])
}

/// Canonical codec for one typed human verdict.
///
/// Override is unrepresentable without BOTH a durable delta and a durable
/// rationale — the enum says so, and the decoder refuses a map that omits
/// either rather than defaulting one.
#[must_use]
pub fn human_verdict_value(verdict: HumanVerdict) -> Value {
    let mut entries = vec![(Value::from("verdict"), Value::from(verdict.as_str()))];
    match verdict {
        HumanVerdict::Approve { rationale_ref } | HumanVerdict::Reject { rationale_ref } => {
            entries.push((
                Value::from("rationale_ref"),
                rationale_ref.map_or(Value::Nil, entity_ref_value),
            ));
        }
        HumanVerdict::OverrideWithDiff {
            delta_ref,
            rationale_ref,
        } => {
            entries.push((Value::from("delta_ref"), entity_ref_value(delta_ref)));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        HumanVerdict::Escalate {
            assignee,
            rationale_ref,
        } => {
            entries.push((Value::from("assignee"), task_assignee_value(assignee)));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
    }
    Value::Map(entries)
}

/// Decodes one typed human verdict.
///
/// # Errors
///
/// [`Error::InvalidTaskBody`] for an unknown token, a missing required ref, or
/// an assignee that is not exactly ONE-1699's `TaskAssignee`.
pub fn decode_human_verdict(value: &Value) -> Result<HumanVerdict> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.verdict"))?;
    let required = |name| -> Result<EntityId> {
        decode_entity_ref(task_body_field(entries, name)?, "tasks.verdict")
    };
    let optional_rationale = || -> Result<Option<EntityId>> {
        task_body_optional(entries, "rationale_ref")?
            .map(|value| decode_entity_ref(value, "tasks.verdict"))
            .transpose()
    };
    match task_body_field(entries, "verdict")?.as_str() {
        Some("approve") => Ok(HumanVerdict::Approve {
            rationale_ref: optional_rationale()?,
        }),
        Some("reject") => Ok(HumanVerdict::Reject {
            rationale_ref: optional_rationale()?,
        }),
        Some("override_with_diff") => Ok(HumanVerdict::OverrideWithDiff {
            delta_ref: required("delta_ref")?,
            rationale_ref: required("rationale_ref")?,
        }),
        Some("escalate") => Ok(HumanVerdict::Escalate {
            assignee: decode_task_assignee(task_body_field(entries, "assignee")?)?,
            rationale_ref: required("rationale_ref")?,
        }),
        _ => Err(Error::InvalidTaskBody("tasks.verdict")),
    }
}

/// The attempt/run-tree job projection, shared by the bounded board scan and
/// the direct-by-id path so both see identical job identity and ordering.
struct JobBacklinks {
    /// Realizing jobs keyed by the hex TASK ref their attempt backlinks.
    realizing: BTreeMap<String, Vec<JobPresence>>,
    /// Jobs that were bare from the start — no task backlink at all.
    bare: Vec<JobPresence>,
}

fn job_backlinks(vault: &Vault) -> Result<JobBacklinks> {
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
    let mut realizing: BTreeMap<String, Vec<JobPresence>> = BTreeMap::new();
    let mut bare = Vec::new();
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
            Some(Some(task_ref)) => realizing.entry(task_ref.clone()).or_default().push(job),
            _ if node.worker_kind == BRIDGE_OUTBOUND_ATTEMPT_KIND => {}
            _ => bare.push(job),
        }
    }
    Ok(JobBacklinks { realizing, bare })
}

/// Number of TASK ids fetched per sanctioned `entities_by_type_page` call.
const TASK_PRESENCE_PAGE_SIZE: usize = 256;
/// Maximum TASK entity ids inspected for ONE board assembly. It bounds WORK;
/// `TasksSection::RENDER_ROW_CAP` bounds tokens. A row beyond this prefix is
/// hidden from the collapsed board, never gone — `tasks.expand` / `tasks.ack`
/// still reach it by id.
const TASK_PRESENCE_SCAN_CAP: usize = 4_096;

const _: () = assert!(TASK_PRESENCE_PAGE_SIZE > 0);
const _: () = assert!(TASK_PRESENCE_PAGE_SIZE <= TASK_PRESENCE_SCAN_CAP);
const _: () = assert!(TasksSection::RENDER_ROW_CAP < TASK_PRESENCE_SCAN_CAP);

#[derive(Debug)]
struct TaskEntityPageScan {
    /// Bounded pages in type-index order; page boundaries are retained so
    /// `task_presence` opens exactly one render-state transaction per page.
    pages: Vec<Vec<EntityId>>,
    scanned_task_entities: usize,
    source_exhausted: bool,
}

#[derive(Debug)]
struct TaskPresenceSnapshot {
    intents: Vec<TaskIntentPresence>,
    bare_jobs: Vec<JobPresence>,
    scanned_task_entities: usize,
    /// `false` means the scan cap stopped the walk before the TASK type index
    /// ran out, so the projection is a PREFIX, not a census. Load-bearing
    /// honesty: the renderer marks its overflow count as a lower bound.
    source_exhausted: bool,
}

/// Pure bounded cursor loop over the sanctioned page primitive.
///
/// Production passes `Vault::entities_by_type_page`; tests pass a synthetic
/// pager and small explicit limits. Unpaged `entities_by_type` is never an
/// option here: it materializes the whole TASK index and returns
/// `IndexOverflow` past `MAX_TYPE_QUERY_RESULTS`, so a `.take(cap)` after it
/// would hard-fail before the iterator ever exists.
fn scan_task_entity_pages<F>(
    page_size: usize,
    scan_cap: usize,
    mut fetch_page: F,
) -> Result<TaskEntityPageScan>
where
    F: FnMut(Option<&EntityId>, usize) -> Result<Vec<EntityId>>,
{
    // A zero page size would fetch nothing forever; clamping keeps forward
    // progress rather than reporting a false "exhausted".
    let page_size = page_size.max(1);
    let mut pages: Vec<Vec<EntityId>> = Vec::new();
    let mut after: Option<EntityId> = None;
    let mut scanned = 0_usize;
    let mut source_exhausted = false;
    let mut decided = false;

    while scanned < scan_cap {
        let remaining = scan_cap - scanned;
        // The extra row is a sentinel on the final capped page: fetching one
        // more than the budget is how "there is more" is learned without
        // spending scan work on it.
        let requested = page_size.min(remaining.saturating_add(1));
        let mut page = fetch_page(after.as_ref(), requested)?;
        if page.is_empty() {
            source_exhausted = true;
            decided = true;
            break;
        }

        let page_len = page.len();
        let process_count = page_len.min(remaining);
        let has_sentinel = page_len > process_count;
        // Defensive: nothing to process means the cursor cannot advance, so
        // stop rather than spin. The unprocessed rows still prove more exist.
        if process_count == 0 {
            decided = true;
            break;
        }
        page.truncate(process_count);

        // The cursor is an EXCLUSIVE lower bound in type-index order, so a
        // source that fails to advance it would replay rows forever; refusing
        // to continue keeps the walk finite and duplicate-free.
        let cursor = page.last().copied();
        if let (Some(previous), Some(next)) = (after, cursor)
            && next <= previous
        {
            decided = true;
            break;
        }

        scanned += process_count;
        after = cursor;
        pages.push(page);

        if has_sentinel {
            source_exhausted = false;
            decided = true;
            break;
        }
        if page_len < requested {
            source_exhausted = true;
            decided = true;
            break;
        }
    }

    if !decided {
        // The budget ran out on a page that exactly filled its request. One
        // bounded one-row probe past the cursor separates an exact census from
        // a lower bound, so a source that happens to end on the cap boundary
        // is not reported as truncated.
        source_exhausted = match after.as_ref() {
            Some(cursor) => fetch_page(Some(cursor), 1)?.is_empty(),
            // scan_cap == 0: nothing was inspected, so nothing is known.
            None => false,
        };
    }

    Ok(TaskEntityPageScan {
        pages,
        scanned_task_entities: scanned,
        source_exhausted,
    })
}

fn task_presence(vault: &Vault) -> Result<TaskPresenceSnapshot> {
    task_presence_with_limits(vault, TASK_PRESENCE_PAGE_SIZE, TASK_PRESENCE_SCAN_CAP)
}

/// Testable body: production uses the constants above; local tests inject small
/// limits to force multi-page and scan-cap behaviour without a 100k-row vault.
fn task_presence_with_limits(
    vault: &Vault,
    page_size: usize,
    scan_cap: usize,
) -> Result<TaskPresenceSnapshot> {
    let JobBacklinks {
        mut realizing,
        mut bare,
    } = job_backlinks(vault)?;
    let scan = scan_task_entity_pages(page_size, scan_cap, |after, limit| {
        vault.entities_by_type_page(ENTITY_TYPE_TASK, after, limit)
    })?;

    // Read-time clock: a consult past its deadline surfaces as expired from the
    // persisted deadline alone, so the failed row is never hidden behind
    // outbound (or reconciliation) availability.
    let now = unix_seconds_now();
    let mut intents = Vec::new();
    for page in &scan.pages {
        // ONE render-state/hydration transaction per page, replacing the two
        // state transactions per TASK the unpaged loop opened.
        let slots = {
            let rtxn = vault.store.env.read_txn()?;
            let mut slots = Vec::with_capacity(page.len());
            for &task_ref in page {
                let state = TaskIntentPresence::render_state_in(vault, &rtxn, task_ref)?;
                if state.cancelled {
                    continue;
                }
                let task_hex = task_ref.to_hex();
                let jobs = realizing.get(&task_hex).cloned().unwrap_or_default();
                // P2 F8 (board poisoning): one malformed TASK body must not
                // abort the whole board. A body that decodes badly — e.g. a
                // role byte carrying `subkind:"typed"` but missing the typed
                // fields — is skipped/degraded, never propagated as a hard
                // error that takes down `tasks.check`.
                match task_page_slot_in(vault, &rtxn, task_ref, &task_hex, jobs, state.acked, now) {
                    Ok(Some(slot)) => slots.push(slot),
                    Ok(None) | Err(_) => continue,
                }
            }
            slots
        };
        // Slot order is type-index order; resolving the deferred shapes here
        // keeps it that way while the page transaction is already closed.
        for slot in slots {
            let task_hex = slot.task_hex().to_owned();
            match slot.resolve(vault) {
                Ok(Some(intent)) => {
                    realizing.remove(&task_hex);
                    intents.push(intent);
                }
                Ok(None) | Err(_) => continue,
            }
        }
    }

    if scan.source_exhausted {
        // P2 F7 (dangling backlink): every live realizing job must render
        // exactly once. A backlink naming no surviving intent (deleted /
        // malformed / case-mismatched owner) is re-emitted as a bare job
        // instead of vanishing.
        bare.extend(realizing.into_values().flatten());
    }
    // Otherwise the leftovers belong to TASK entities the bounded scan never
    // inspected. "Not scanned" is not "dangling": draining them here would
    // mislabel live work as orphaned AND duplicate it once the owner is
    // scanned. The TASKS overflow footer carries the omission instead.

    let snapshot = TaskPresenceSnapshot {
        intents,
        bare_jobs: bare,
        scanned_task_entities: scan.scanned_task_entities,
        source_exhausted: scan.source_exhausted,
    };
    debug_assert!(
        snapshot.scanned_task_entities <= scan_cap,
        "one board assembly inspects at most the scan cap"
    );
    Ok(snapshot)
}

/// Direct-by-id projection behind `tasks.expand` / `tasks.ack`.
///
/// It hydrates the requested TASK plus the jobs backlinked to it and NEVER
/// walks the TASK type index: the board's bounded prefix bounds what is SHOWN,
/// never what a typed read by id can reach. Hidden is one call away, not gone.
fn task_presence_for_id(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskIntentPresence>> {
    if task_is_cancelled(vault, task_ref)? {
        return Ok(None);
    }
    let task_hex = task_ref.to_hex();
    let jobs = job_backlinks(vault)?
        .realizing
        .remove(&task_hex)
        .unwrap_or_default();
    let acked = task_is_acked(vault, task_ref)?;
    match task_intent_presence(vault, task_ref, &task_hex, jobs, acked, unix_seconds_now()) {
        Ok(found) => Ok(found),
        // A malformed body degrades to "not board-visible" here exactly as it
        // does in the board scan, so both doors agree on a poisoned row.
        Err(_) => Ok(None),
    }
}

/// One page row, split by whether it could be finished inside the page's
/// shared read transaction.
enum TaskPageSlot {
    /// Fully projected in-transaction: the typed TASK body path.
    Projected(TaskIntentPresence),
    /// A non-typed `Task`-role entity — connector-send subkind or role-only
    /// fold. Only `outbound`'s reader can tell them apart and it opens its own
    /// read transaction, so the row is finished after the page transaction
    /// closes, in its original slot position.
    Untyped {
        task_ref: EntityId,
        task_hex: String,
        jobs: Vec<JobPresence>,
        acked: bool,
    },
}

impl TaskPageSlot {
    fn task_hex(&self) -> &str {
        match self {
            Self::Projected(intent) => &intent.id,
            Self::Untyped { task_hex, .. } => task_hex,
        }
    }

    /// Finishes the row. Must run with no page transaction open.
    fn resolve(self, vault: &Vault) -> Result<Option<TaskIntentPresence>> {
        let Self::Untyped {
            task_ref,
            task_hex,
            jobs,
            acked,
        } = self
        else {
            let Self::Projected(intent) = self else {
                unreachable!("the untyped variant was just matched away")
            };
            return Ok(Some(intent));
        };
        if let Some(task) = vault.connector_send_task(&task_ref)? {
            let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Scheduled);
            return Ok(Some(TaskIntentPresence::from_connector_send_task_with_ack(
                &task, status, jobs, acked,
            )));
        }
        // P2 F6 (role fold): only the `Task` role folds into the TASKS section,
        // and that was already established inside the page transaction.
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued);
        Ok(Some(TaskIntentPresence::new(
            task_hex, status, None, acked, jobs,
        )))
    }
}

/// Projects one surviving (non-cancelled) TASK entity into its board intent
/// row, or `None` when the entity is not a board-visible TASK. Returns an error
/// only for that single entity; the board scan degrades one bad entity into a
/// skip so the whole board survives (P2 F8).
fn task_intent_presence(
    vault: &Vault,
    task_ref: EntityId,
    task_hex: &str,
    jobs: Vec<JobPresence>,
    acked: bool,
    now: u64,
) -> Result<Option<TaskIntentPresence>> {
    let slot = {
        let rtxn = vault.store.env.read_txn()?;
        task_page_slot_in(vault, &rtxn, task_ref, task_hex, jobs, acked, now)?
    };
    match slot {
        Some(slot) => slot.resolve(vault),
        None => Ok(None),
    }
}

/// The in-transaction half of [`task_intent_presence`]: everything the ordinary
/// typed and role-fallback paths need, read through the caller's transaction so
/// page hydration never opens a second one per id.
fn task_page_slot_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    task_hex: &str,
    jobs: Vec<JobPresence>,
    acked: bool,
    now: u64,
) -> Result<Option<TaskPageSlot>> {
    if let Some(task) = task_verb_body_in(vault, rtxn, task_ref)? {
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
        // A human assignee is qualified, because on the ONE shared TASKS
        // section the assignee column is what tells a reader that this open
        // loop is waiting on a person rather than on a worker.
        presence.assignee = task.assignee.and_then(|assignee| {
            let actor_ref = assignee.entity_ref()?;
            let handle = peer_handle_in(vault, rtxn, actor_ref)
                .ok()
                .flatten()
                .unwrap_or_else(|| actor_ref.to_hex());
            Some(match assignee {
                TaskAssignee::Human { .. } => format!("person:{handle}"),
                TaskAssignee::Dreamer
                | TaskAssignee::AgentDef { .. }
                | TaskAssignee::Peer { .. } => handle,
            })
        });
        presence.terminal_disposition = terminal_disposition;
        presence.result_ref = terminal
            .as_ref()
            .and_then(|record| record.result_ref)
            .map(|result_ref| result_ref.to_hex());
        presence.consult_result = terminal.as_ref().and_then(consult_result_presence);
        // ONE-1888: the ladder outcome is only ever read off the row that
        // actually carries one; an unstamped ONE-1699 terminal keeps rendering
        // exactly as it did.
        presence.ladder_disposition = terminal.as_ref().and_then(|record| record.ladder);
        presence.counter_task_ref = terminal
            .as_ref()
            .and_then(|record| record.counter_task_ref)
            .map(|counter_ref| counter_ref.to_hex());
        presence.interrupted = task.state == Some(TaskExecutionState::Interrupted);
        return Ok(Some(TaskPageSlot::Projected(presence)));
    }
    // P2 F6 (role fold): only the `Task` role folds into the TASKS section.
    // Goal / Milestone / Habit / HabitCheckin roles are not tasks and must not
    // render as TASKS rows (nor enter the cancel fallback below). Both
    // remaining `Task`-role shapes — connector-send and role-only — are
    // finished once this transaction closes.
    if matches!(task_entity_role_in(vault, rtxn, task_ref)?, Some(TaskRole::Task)) {
        return Ok(Some(TaskPageSlot::Untyped {
            task_ref,
            task_hex: task_hex.to_owned(),
            jobs,
            acked,
        }));
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
        TaskCreateSpec::new(Value::from("unit-task"), None, None, Some(now))
    }

    // ── consult fixtures (ONE-1699) ─────────────────────────────────────

    const CONSULT_NOW: u64 = 1_772_400_000;
    const CONSULT_DEADLINE: u64 = CONSULT_NOW + 60;

    fn consult_turn(vault: &Vault, seed: u8) -> ConsultPayloadRef {
        let turn_ref = EntityId::from_bytes([seed; 16]).expect("turn id");
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![(Value::from("role"), Value::from("question"))]),
        )
        .expect("encode turn body");
        vault
            .put_entity(
                &turn_ref,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: CONSULT_NOW,
                    end: CONSULT_NOW,
                },
                CONSULT_NOW,
                &body,
            )
            .expect("store durable turn");
        ConsultPayloadRef::parse(vault, &format!("tn_{}", turn_ref.to_hex()))
            .expect("turn parses as a typed consult ref")
    }

    fn consult_peer(vault: &Vault, seed: u8) -> EntityId {
        let actor_ref = EntityId::from_bytes([seed; 16]).expect("peer id");
        put_person(vault, actor_ref);
        actor_ref
    }

    fn consult_spec(
        question: ConsultPayloadRef,
        peer: EntityId,
        deadline_at: u64,
    ) -> TaskCreateSpec {
        TaskCreateSpec::new(Value::Nil, None, None, Some(CONSULT_NOW))
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                question,
                Vec::new(),
                EntityId::now(),
            ))
            .with_assignee(TaskAssignee::Peer { actor_ref: peer })
            .with_ttl(TaskTtl::at(deadline_at))
    }

    fn digest_route() -> ConsultDigestRoute {
        ConsultDigestRoute {
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "owner@example.test".to_owned(),
            on_behalf_of: None,
            recovery: vec![ConsultRecovery::NudgeAssignee],
        }
    }

    fn grant_outbound(vault: &Vault, actor: EntityId, seed: u8) {
        let grant_ref = EntityId::from_bytes([seed; 16]).expect("grant id");
        vault
            .mint_standing_outbound_grant(
                &grant_ref,
                &GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "consult.expiry".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "send".to_owned(),
                    },
                },
                CONSULT_NOW,
            )
            .expect("mint outbound grant");
    }

    /// A consult on its peer's board, ready to answer or expire.
    fn open_consult(vault: &Vault) -> (EntityId, EntityId, ConsultPayloadRef) {
        let asker = own_agent(vault);
        let peer = consult_peer(vault, 0xE2);
        let question = consult_turn(vault, 0x7A);
        let created = vault
            .memory_facade(asker, EdgeActorClass::Agent)
            .tasks_create(&consult_spec(question, peer, CONSULT_DEADLINE))
            .expect("consult create effects");
        (
            created.task_ref.expect("consult mints one TASK"),
            peer,
            question,
        )
    }

    fn answer_input(result_ref: EntityId, evidence: ConsultPayloadRef) -> ConsultResultInput {
        ConsultResultInput {
            kind: ConsultResultKind::Answer {
                result_ref,
                evidence_refs: vec![evidence],
            },
            completed_at: CONSULT_NOW + 10,
        }
    }

    /// A consult create mints exactly one synced TASK entity and ZERO local
    /// realizations: a node-local lease could never reach a peer's machine.
    #[test]
    fn consult_create_mints_one_task_entity_and_no_realization() {
        let (_dir, vault) = open_vault();
        let (task_ref, peer, _question) = open_consult(&vault);
        let task_hex = task_ref.to_hex();
        let realizations = AttemptQueue::new(&vault)
            .list()
            .expect("list attempts")
            .iter()
            .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
            .count();
        let body = task_verb_body(&vault, task_ref)
            .expect("decode consult body")
            .expect("consult is typed");

        assert_eq!(realizations, 0);
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .len(),
            1
        );
        assert_eq!(body.task_kind(), TaskKind::Consult);
        assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref: peer }));
        assert_eq!(body.ttl, Some(TaskTtl::at(CONSULT_DEADLINE)));
        assert_eq!(body.state, Some(TaskExecutionState::Queued));
        assert_eq!(body.spec, Value::Nil);
    }

    /// The pre-ticket constructor still compiles with exactly four arguments
    /// and still takes the legacy Dreamer-realized standard path.
    #[test]
    fn pre_ticket_create_spec_takes_the_unchanged_standard_path() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let legacy = TaskCreateSpec::new(Value::from("unit-task"), None, None, Some(120));
        let created = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&legacy)
            .expect("legacy create");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(legacy.kind, None);
        assert_eq!(legacy.consult, None);
        assert_eq!(legacy.assignee, None);
        assert_eq!(legacy.ttl, None);
        assert_eq!(body.task_kind(), TaskKind::Standard);
        assert_eq!(usize::from(body.assignee.is_none()), 1);
        assert_eq!(usize::from(body.terminal().is_none()), 1);
        assert_eq!(
            AttemptQueue::new(&vault)
                .list()
                .expect("list attempts")
                .iter()
                .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
                .count(),
            1
        );
    }

    /// A schema-v1 row — one that names none of the additive keys — decodes as
    /// a standard, implicitly Dreamer-routed task with no TTL and no terminal.
    #[test]
    fn schema_v1_body_decodes_as_standard_dreamer_task() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let task_ref = EntityId::from_bytes([0xB7; 16]).expect("task id");
        let v1_body = {
            let value = Value::Map(vec![
                (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
                (Value::from("schema_version"), Value::from(1u8)),
                (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
                (Value::from("owner_ref"), Value::from(own.to_hex())),
                (Value::from("label"), Value::from("legacy row")),
                (Value::from("spec"), Value::from("legacy-spec")),
                (Value::from("provenance"), Value::Nil),
                (Value::from("created_at"), Value::from(120u64)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode v1 body");
            bytes
        };
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &v1_body,
            )
            .expect("store schema-v1 task");

        let body = task_verb_body(&vault, task_ref)
            .expect("decode v1 body")
            .expect("v1 row is typed");
        let section = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_check()
            .expect("board reads the v1 row");

        assert_eq!(body.schema_version, 1);
        assert_eq!(body.kind, None);
        assert_eq!(body.task_kind(), TaskKind::Standard);
        assert_eq!(body.assignee, None);
        assert_eq!(body.ttl, None);
        assert_eq!(body.state, None);
        assert_eq!(usize::from(body.terminal().is_none()), 1);
        assert_eq!(body.label.as_deref(), Some("legacy row"));
        let row = section
            .rows
            .iter()
            .find(|row| row.id == task_ref.to_hex())
            .expect("v1 row renders");
        assert_eq!(row.status, TaskBoardStatus::Queued);
        assert_eq!(usize::from(row.assignee.is_none()), 1);
        assert_eq!(usize::from(row.terminal_disposition.is_none()), 1);
    }

    /// Every malformed consult shape is refused BEFORE the write transaction:
    /// no TASK entity lands, whatever the defect.
    #[test]
    fn invalid_consult_shapes_reject_before_any_write() {
        let (_dir, vault) = open_vault();
        let asker = own_agent(&vault);
        let peer = consult_peer(&vault, 0xE2);
        let question = consult_turn(&vault, 0x7A);
        let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
        let absent_peer = EntityId::from_bytes([0xEE; 16]).expect("absent peer id");
        let absent_turn =
            ConsultPayloadRef::Turn(EntityId::from_bytes([0xEF; 16]).expect("absent turn id"));

        let rejects = [
            // A consult carries its request in the typed payload; the legacy
            // free-form spec must be empty.
            consult_spec(question, peer, CONSULT_DEADLINE).with_kind(TaskKind::Consult),
            // Unresolved payload ref.
            consult_spec(absent_turn, peer, CONSULT_DEADLINE),
            // Peer actor that does not resolve.
            consult_spec(question, absent_peer, CONSULT_DEADLINE),
            // Deadline already past at create time.
            consult_spec(question, peer, CONSULT_NOW),
            // Duplicate refs inside one payload.
            TaskCreateSpec::new(Value::Nil, None, None, Some(CONSULT_NOW))
                .with_kind(TaskKind::Consult)
                .with_consult(ConsultPayload::question(
                    question,
                    vec![question],
                    EntityId::now(),
                ))
                .with_assignee(TaskAssignee::Peer { actor_ref: peer })
                .with_ttl(TaskTtl::at(CONSULT_DEADLINE)),
            // Consult kind without a peer assignee.
            TaskCreateSpec::new(Value::Nil, None, None, Some(CONSULT_NOW))
                .with_kind(TaskKind::Consult)
                .with_consult(ConsultPayload::question(
                    question,
                    Vec::new(),
                    EntityId::now(),
                ))
                .with_assignee(TaskAssignee::Dreamer)
                .with_ttl(TaskTtl::at(CONSULT_DEADLINE)),
        ];
        // The first case is the non-Nil spec; rebuild it with a real payload.
        let mut cases = rejects.to_vec();
        cases[0] = TaskCreateSpec::new(Value::from("raw question"), None, None, Some(CONSULT_NOW))
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                question,
                Vec::new(),
                EntityId::now(),
            ))
            .with_assignee(TaskAssignee::Peer { actor_ref: peer })
            .with_ttl(TaskTtl::at(CONSULT_DEADLINE));

        let outcomes: Vec<String> = cases
            .iter()
            .map(|case| {
                facade
                    .tasks_create(case)
                    .expect_err("invalid consult shape rejects")
                    .code
            })
            .collect();

        assert_eq!(outcomes.len(), 6);
        assert_eq!(
            outcomes
                .iter()
                .filter(|code| *code == crate::facade::FACADE_CODE_BAD_REQUEST
                    || *code == crate::facade::FACADE_CODE_NOT_FOUND)
                .count(),
            6
        );
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .len(),
            0
        );
        assert_eq!(AttemptQueue::new(&vault).list().expect("attempts").len(), 0);
    }

    /// Only the addressed peer may answer, exactly one of evidence-answer or
    /// reasoned-abstention lands, and neither/both is unrepresentable.
    #[test]
    fn result_contract_is_addressed_and_partitioned() {
        let (_dir, vault) = open_vault();
        let (task_ref, peer, question) = open_consult(&vault);
        let stranger = consult_peer(&vault, 0xE9);
        let result_ref = consult_turn(&vault, 0x80).entity_ref();

        let by_stranger = vault
            .memory_facade(stranger, EdgeActorClass::Agent)
            .land_consult_result(task_ref, &answer_input(result_ref, question))
            .expect_err("a stranger may not answer an addressed consult");
        let evidence_free = vault
            .memory_facade(peer, EdgeActorClass::Agent)
            .land_consult_result(
                task_ref,
                &ConsultResultInput {
                    kind: ConsultResultKind::Answer {
                        result_ref,
                        evidence_refs: Vec::new(),
                    },
                    completed_at: CONSULT_NOW + 10,
                },
            )
            .expect_err("an answer without evidence is not an answer");
        let landed = vault
            .memory_facade(peer, EdgeActorClass::Agent)
            .land_consult_result(task_ref, &answer_input(result_ref, question))
            .expect("the addressed peer answers");
        let stored = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(by_stranger.code, crate::facade::FACADE_CODE_FORBIDDEN);
        assert_eq!(evidence_free.code, crate::facade::FACADE_CODE_BAD_REQUEST);
        assert_eq!(usize::from(landed.idempotent_replay), 0);
        assert_eq!(
            landed.terminal.disposition,
            TaskTerminalDisposition::Completed
        );
        assert_eq!(landed.terminal.result_ref, Some(result_ref));
        assert_eq!(
            stored.terminal().map(|record| record.summary.clone()),
            Some(Some(ConsultResultSummary::Answer {
                evidence_refs: vec![question],
            }))
        );
    }

    /// One replica settles a task once. A byte-identical replay reports the
    /// winner; a DIFFERENT second result is refused as terminal-immutable and
    /// mutates nothing.
    #[test]
    fn one_replica_settles_once_and_replays_idempotently() {
        let (_dir, vault) = open_vault();
        let (task_ref, peer, question) = open_consult(&vault);
        let result_ref = consult_turn(&vault, 0x80).entity_ref();
        let other_result = consult_turn(&vault, 0x81).entity_ref();
        let facade = vault.memory_facade(peer, EdgeActorClass::Agent);

        let first = facade
            .land_consult_result(task_ref, &answer_input(result_ref, question))
            .expect("first answer settles");
        let replay = facade
            .land_consult_result(task_ref, &answer_input(result_ref, question))
            .expect("identical replay is idempotent");
        let conflicting = facade
            .land_consult_result(task_ref, &answer_input(other_result, question))
            .expect_err("a different second result is refused");
        let stored = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(usize::from(first.idempotent_replay), 0);
        assert_eq!(usize::from(replay.idempotent_replay), 1);
        assert_eq!(replay.terminal, first.terminal);
        assert_eq!(conflicting.code, crate::facade::FACADE_CODE_INVALID_STATE);
        assert_eq!(stored.terminal(), Some(&first.terminal));
    }

    /// An answer that beat the sweep keeps the task out of the expiry path,
    /// and an expired task refuses a later answer — one local transition.
    #[test]
    fn answer_and_expiry_contend_for_one_local_transition() {
        let (_dir, vault) = open_vault();
        let asker = own_agent(&vault);
        grant_outbound(&vault, asker, 0xD1);
        let (answered, peer, question) = open_consult(&vault);
        let expired = vault
            .memory_facade(asker, EdgeActorClass::Agent)
            .tasks_create(&consult_spec(question, peer, CONSULT_DEADLINE))
            .expect("second consult")
            .task_ref
            .expect("second task ref");
        let result_ref = consult_turn(&vault, 0x80).entity_ref();
        let peer_facade = vault.memory_facade(peer, EdgeActorClass::Agent);
        peer_facade
            .land_consult_result(answered, &answer_input(result_ref, question))
            .expect("the first consult is answered before the deadline");

        let report = vault
            .memory_facade(asker, EdgeActorClass::Agent)
            .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
            .expect("sweep the due consults");
        let late = peer_facade
            .land_consult_result(
                expired,
                &answer_input(consult_turn(&vault, 0x81).entity_ref(), question),
            )
            .expect_err("an expired consult refuses a late answer");
        let answered_body = task_verb_body(&vault, answered)
            .expect("decode answered")
            .expect("typed");
        let expired_body = task_verb_body(&vault, expired)
            .expect("decode expired")
            .expect("typed");

        assert_eq!(report.expired_task_refs, vec![expired]);
        assert_eq!(late.code, crate::facade::FACADE_CODE_INVALID_STATE);
        assert_eq!(
            answered_body.terminal().map(|record| record.disposition),
            Some(TaskTerminalDisposition::Completed)
        );
        assert_eq!(
            expired_body.terminal().map(|record| record.disposition),
            Some(TaskTerminalDisposition::Expired)
        );
        // The expiry transition is never result-less.
        assert_eq!(
            usize::from(
                expired_body
                    .terminal()
                    .is_some_and(|record| record.result_ref.is_some())
            ),
            1
        );
    }

    /// The terminal register is ONE value: later `finished_at` wins, and
    /// `Completed` dominates `Expired` on an exact tie — in both merge orders.
    #[test]
    fn terminal_register_converges_identically_in_both_merge_orders() {
        let completed = |finished_at| TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: Some(EntityId::from_bytes([0xA1; 16]).expect("result id")),
            summary: Some(ConsultResultSummary::Answer {
                evidence_refs: vec![ConsultPayloadRef::Turn(
                    EntityId::from_bytes([0xA2; 16]).expect("evidence id"),
                )],
            }),
            finished_at,
            ladder: None,
            counter_task_ref: None,
        };
        let expired = |finished_at| TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Expired,
            result_ref: Some(EntityId::from_bytes([0xA3; 16]).expect("expiry id")),
            summary: None,
            finished_at,
            ladder: None,
            counter_task_ref: None,
        };
        let cases = [
            // Later answer beats an earlier expiry.
            (completed(200), expired(100), completed(200)),
            // Later expiry beats an earlier answer.
            (completed(100), expired(200), expired(200)),
            // Exact tie: the answer dominates.
            (completed(150), expired(150), completed(150)),
        ];

        for (index, (left, right, expected)) in cases.into_iter().enumerate() {
            let forward = merge_task_terminal_register(Some(&left), Some(&right));
            let backward = merge_task_terminal_register(Some(&right), Some(&left));
            assert_eq!(forward, backward, "case {index} must be order-free");
            assert_eq!(forward, Some(expected), "case {index} winner");
        }
        // An empty register merges to the one side that has a record.
        let only = completed(10);
        assert_eq!(
            merge_task_terminal_register(Some(&only), None),
            Some(only.clone())
        );
        assert_eq!(merge_task_terminal_register(None, Some(&only)), Some(only));
        assert_eq!(merge_task_terminal_register(None, None), None);
    }

    /// `Expired` and `Abandoned` are distinct causes that survive a body
    /// round-trip, even though both project onto the failed lane.
    #[test]
    fn expired_and_abandoned_stay_distinct_through_the_codec() {
        let dispositions = [
            TaskTerminalDisposition::Completed,
            TaskTerminalDisposition::Rejected,
            TaskTerminalDisposition::Failed,
            TaskTerminalDisposition::Expired,
            TaskTerminalDisposition::Abandoned,
            TaskTerminalDisposition::Cancelled,
        ];
        let round_tripped: Vec<TaskTerminalDisposition> = dispositions
            .into_iter()
            .map(|disposition| {
                let record = TaskTerminalRecord {
                    disposition,
                    result_ref: Some(EntityId::from_bytes([0xA1; 16]).expect("result id")),
                    summary: None,
                    finished_at: 42,
                    ladder: None,
                    counter_task_ref: None,
                };
                let decoded = decode_task_terminal_record(&task_terminal_record_value(&record))
                    .expect("terminal record round-trips");
                assert_eq!(decoded, record);
                decoded.disposition
            })
            .collect();

        assert_eq!(round_tripped, dispositions);
        assert_eq!(
            board_status_for_disposition(TaskTerminalDisposition::Expired),
            TaskBoardStatus::Failed
        );
        assert_eq!(
            board_status_for_disposition(TaskTerminalDisposition::Abandoned),
            TaskBoardStatus::Failed
        );
        assert_eq!(
            usize::from(
                TaskTerminalDisposition::Expired.as_str()
                    == TaskTerminalDisposition::Abandoned.as_str()
            ),
            0
        );
    }

    /// Fan-out mints N independent tasks under ONE correlation ref, refuses a
    /// repeated peer deterministically, and never mints a partial subset.
    #[test]
    fn fan_out_mints_one_task_per_distinct_peer_under_one_correlation() {
        let (_dir, vault) = open_vault();
        let asker = own_agent(&vault);
        let peers: Vec<EntityId> = [0xE2, 0xE4, 0xE5]
            .into_iter()
            .map(|seed| consult_peer(&vault, seed))
            .collect();
        let question = consult_turn(&vault, 0x7A);
        let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
        let fan_out = |assignees: Vec<EntityId>| ConsultFanOutSpec {
            question_ref: question,
            context_refs: Vec::new(),
            assignees,
            deadline_at: CONSULT_DEADLINE,
            label: None,
            now: Some(CONSULT_NOW),
        };

        let duplicated = facade
            .fan_out_consults(&fan_out(vec![peers[0], peers[1], peers[0]]))
            .expect_err("a repeated peer is refused, never collapsed");
        let after_refusal = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .len();
        let empty = facade
            .fan_out_consults(&fan_out(Vec::new()))
            .expect_err("a fan-out addresses at least one peer");
        let receipt = facade
            .fan_out_consults(&fan_out(peers.clone()))
            .expect("fan out to three distinct peers");
        let correlations: Vec<EntityId> = receipt
            .task_refs
            .iter()
            .map(|task_ref| {
                task_verb_body(&vault, *task_ref)
                    .expect("decode consult")
                    .expect("typed consult")
                    .consult
                    .expect("consult payload")
                    .correlation_ref
            })
            .collect();
        let mut unique_tasks = receipt.task_refs.clone();
        unique_tasks.sort_unstable();
        unique_tasks.dedup();
        let mut sorted_peers = peers;
        sorted_peers.sort_unstable();
        let assignees: Vec<EntityId> = receipt
            .task_refs
            .iter()
            .filter_map(|task_ref| {
                task_verb_body(&vault, *task_ref)
                    .expect("decode consult")
                    .expect("typed consult")
                    .assignee
                    .and_then(TaskAssignee::entity_ref)
            })
            .collect();

        assert_eq!(duplicated.code, crate::facade::FACADE_CODE_BAD_REQUEST);
        assert_eq!(empty.code, crate::facade::FACADE_CODE_BAD_REQUEST);
        assert_eq!(after_refusal, 0);
        assert_eq!(receipt.task_refs.len(), 3);
        assert_eq!(unique_tasks.len(), 3);
        assert_eq!(correlations, vec![receipt.correlation_ref; 3]);
        // Deterministic assignee order, independent of how the caller listed
        // them, so a fan-out receipt is comparable across replicas.
        assert_eq!(assignees, sorted_peers);
        assert_eq!(AttemptQueue::new(&vault).list().expect("attempts").len(), 0);
    }

    /// Expiry notification is exactly-once per `(task_ref, stage)` and
    /// survives a crash between terminalization and the outbound schedule.
    #[test]
    fn expiry_digest_is_once_per_task_and_recovers_from_the_crash_window() {
        let (_dir, vault) = open_vault();
        let asker = own_agent(&vault);
        grant_outbound(&vault, asker, 0xD1);
        let (task_ref, _peer, _question) = open_consult(&vault);
        let facade = vault.memory_facade(asker, EdgeActorClass::Agent);

        let first = facade
            .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
            .expect("first sweep expires and notifies");
        let second = facade
            .settle_due_consults(CONSULT_DEADLINE + 2, &digest_route())
            .expect("second sweep is a no-op");
        let sends_after_two_sweeps = vault.connector_send_tasks().expect("connector sends").len();

        // Simulated crash: the task terminalized, but the process died before
        // the follow-up marker landed.
        {
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            vault
                .store
                .vault_meta
                .delete(
                    &mut wtxn,
                    task_follow_up_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED).as_slice(),
                )
                .expect("clear the follow-up marker");
            wtxn.commit().expect("commit");
        }
        let recovered = facade
            .settle_due_consults(CONSULT_DEADLINE + 3, &digest_route())
            .expect("the sweep re-drives an undigested expiry");
        let sends_after_recovery = vault.connector_send_tasks().expect("connector sends").len();

        assert_eq!(first.expired_task_refs, vec![task_ref]);
        assert_eq!(first.digest_intent_refs.len(), 1);
        assert_eq!(first.already_settled, 0);
        assert_eq!(second.expired_task_refs.len(), 0);
        assert_eq!(second.digest_intent_refs.len(), 0);
        assert_eq!(second.already_settled, 1);
        assert_eq!(sends_after_two_sweeps, 1);
        // The re-drive re-schedules, and the shared namespace key coalesces it
        // onto the SAME outbound intent rather than double-notifying.
        assert_eq!(recovered.expired_task_refs.len(), 0);
        assert_eq!(recovered.digest_intent_refs.len(), 1);
        assert_eq!(sends_after_recovery, 1);
        assert_eq!(
            recovered.digest_intent_refs, first.digest_intent_refs,
            "the coalesced retry names the first intent"
        );
        // The namespace is shared with ONE-1708's human follow-up stages.
        assert_eq!(
            task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED),
            format!("tasks.followup.v1:{}:consult_expired", task_ref.to_hex())
        );
        assert_eq!(
            usize::from(
                task_follow_up_dedupe_key(task_ref, "human_reminder")
                    != task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED)
            ),
            1
        );
    }

    /// The asker's failed lane keeps an expired consult until it is acked, and
    /// the row names `expired` distinctly from the bare `failed` status.
    #[test]
    fn expired_consult_holds_the_failed_lane_until_acked() {
        let (_dir, vault) = open_vault();
        let asker = own_agent(&vault);
        grant_outbound(&vault, asker, 0xD1);
        let (task_ref, _peer, _question) = open_consult(&vault);
        let task_hex = task_ref.to_hex();
        let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
        facade
            .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
            .expect("settle the expired consult");

        let before = facade.tasks_check().expect("board before ack");
        let lane = crate::context_board::failed_lane(&before);
        let acked = facade.tasks_ack(task_ref).expect("ack the expired consult");
        let after = facade.tasks_check().expect("board after ack");

        assert_eq!(lane.len(), 1);
        assert_eq!(lane[0].id, task_hex);
        assert_eq!(lane[0].status, TaskBoardStatus::Failed);
        assert_eq!(
            lane[0].terminal_disposition,
            Some(TaskTerminalDisposition::Expired)
        );
        assert_eq!(
            lane[0]
                .line
                .split_whitespace()
                .filter(|token| *token == "expired")
                .count(),
            1
        );
        assert_eq!(
            lane[0]
                .line
                .split_whitespace()
                .filter(|token| *token == "failed")
                .count(),
            1
        );
        assert_eq!(usize::from(acked.acked), 1);
        assert_eq!(
            after.rows.iter().filter(|row| row.id == task_hex).count(),
            0
        );
    }

    /// A board read derives expiry from the persisted deadline alone, so the
    /// failed row is never hidden behind reconciliation or outbound
    /// availability.
    #[test]
    fn board_reads_expiry_from_the_deadline_before_the_sweep_runs() {
        let (_dir, vault) = open_vault();
        let asker = own_agent(&vault);
        let peer = consult_peer(&vault, 0xE2);
        let question = consult_turn(&vault, 0x7A);
        let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
        // A deadline one second into the past of the READ clock; nothing has
        // settled it, and no digest has been scheduled.
        let now = unix_seconds_now();
        let created = facade
            .tasks_create(
                &TaskCreateSpec::new(Value::Nil, None, None, Some(now))
                    .with_kind(TaskKind::Consult)
                    .with_consult(ConsultPayload::question(
                        question,
                        Vec::new(),
                        EntityId::now(),
                    ))
                    .with_assignee(TaskAssignee::Peer { actor_ref: peer })
                    .with_ttl(TaskTtl::at(now + 1)),
            )
            .expect("consult create effects");
        let task_ref = created.task_ref.expect("task ref");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        let row = task_intent_presence(
            &vault,
            task_ref,
            &task_ref.to_hex(),
            Vec::new(),
            false,
            now + 2,
        )
        .expect("project the overdue consult")
        .expect("consult projects");

        assert_eq!(usize::from(body.terminal().is_none()), 1);
        assert_eq!(row.status, TaskBoardStatus::Failed);
        assert_eq!(
            row.terminal_disposition,
            Some(TaskTerminalDisposition::Expired)
        );
        assert_eq!(usize::from(row.result_ref.is_none()), 1);
        assert_eq!(vault.connector_send_tasks().expect("sends").len(), 0);
    }

    /// The synced entity reaches a peer wherever it connects; the lease-bearing
    /// plane never leaves this node.
    #[cfg(feature = "sync")]
    #[test]
    fn consult_task_syncs_and_no_attempt_row_follows_it() {
        use crate::config::VaultConfig;
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::reverse_rematerialize;
        use loro::{ExportMode, LoroDoc};

        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open device vault");
        let (task_ref, _peer, _question) = open_consult(&vault);
        // A node-local job unrelated to the consult, to prove the export
        // excludes the whole attempt plane and not merely an empty one.
        let EnqueueOutcome::Enqueued(_) = AttemptQueue::new(&vault)
            .enqueue(EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: b"node-local".to_vec(),
                dedupe_key: None,
                run_id: None,
                now: CONSULT_NOW,
            })
            .expect("enqueue node-local job")
        else {
            panic!("job must enqueue");
        };

        let window_key = WindowKey::new("2026-03");
        let sync_doc = create_window_doc("test-user", &window_key);
        reverse_rematerialize(&vault, &sync_doc, &window_key).expect("mirror into sync document");
        let snapshot = sync_doc
            .export(ExportMode::Snapshot)
            .expect("export sync snapshot");
        let exported = LoroDoc::from_snapshot(&snapshot).expect("read sync snapshot");
        let mut synced_attempt_rows = 0;
        exported
            .get_map("attempt_records")
            .for_each(|_, _| synced_attempt_rows += 1);

        assert_eq!(
            usize::from(
                exported
                    .get_map("entities")
                    .get(task_ref.to_hex().as_str())
                    .is_some()
            ),
            1
        );
        assert_eq!(synced_attempt_rows, 0);
        let payload: &[u8] = b"node-local";
        assert_eq!(
            usize::from(
                snapshot
                    .windows(payload.len())
                    .any(|window| window == payload)
            ),
            0
        );
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
        let forged_body = encode_task_verb_body(forged_body);
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

    // ── ONE-1888: consult ladder, routing, magistrate ───────────────────

    use crate::claim::PREDICATE_CONFLICT_OPEN;
    use crate::consult_ladder::{
        A2aBaseTaskState, AuthorityEvidence, CaseCriticality, DeltaShapeFingerprint,
        GraduationLookup, GraduationScope, InterruptedState, InterruptionKind, MagistrateRecusal,
        PolicyEvidence, WorkingState, terminal_for_human_verdict,
    };
    use crate::write_envelope::ClaimCandidate as EnvelopeClaimCandidate;

    const LADDER_NOW: u64 = CONSULT_NOW;
    const LADDER_DEADLINE: u64 = CONSULT_NOW + 3_600;
    /// The default policy manifest gives `agent` an auto ceiling for exactly
    /// one actor ref, and `own_agent` is it — so every acting facade in these
    /// tests is that actor and the OWNERSHIP under test varies instead.
    const OTHER_ACTOR_SEED: u8 = 0xE3;

    fn ladder_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("ladder test id")
    }

    /// A second human actor: the owner of the state an agent wants to change.
    fn other_actor(vault: &Vault) -> EntityId {
        let actor = ladder_id(OTHER_ACTOR_SEED);
        put_person(vault, actor);
        actor
    }

    /// Writes one CLAIM through the normal envelope-stamped door so its
    /// authoring actor and run surface are recoverable exactly as production
    /// writes them.
    fn put_envelope_claim(
        vault: &Vault,
        claim_ref: EntityId,
        subject: EntityId,
        actor: EntityId,
        actor_class: EdgeActorClass,
        provenance: Value,
    ) {
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, actor_class),
            ClaimSource::Observed,
            WriteProvenance::new(provenance).expect("provenance is not nil"),
            ClaimApprovalStatus::Proposed,
        );
        let candidate = EnvelopeClaimCandidate::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            Value::from("state"),
            1.0,
        );
        vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .claim_candidate(
                        &claim_ref,
                        candidate.clone(),
                        &envelope,
                        TimeRange {
                            start: LADDER_NOW,
                            end: LADDER_NOW,
                        },
                        LADDER_NOW,
                    )
                    .apply(wtxn)
            })
            .expect("claim write lands");
    }

    fn dreamer_provenance() -> Value {
        Value::Map(vec![
            (
                Value::from("surface"),
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (Value::from("run"), Value::from("run-1")),
        ])
    }

    fn agent_provenance() -> Value {
        Value::Map(vec![
            (Value::from("surface"), Value::from("agent.dispatch")),
            (Value::from("run"), Value::from("run-2")),
        ])
    }

    /// One CLAIM owned by `owner` — the cross-actor target under test.
    fn owned_claim(
        vault: &Vault,
        seed: u8,
        owner: EntityId,
        actor_class: EdgeActorClass,
    ) -> EntityId {
        let claim_ref = ladder_id(seed);
        put_envelope_claim(
            vault,
            claim_ref,
            owner,
            owner,
            actor_class,
            agent_provenance(),
        );
        claim_ref
    }

    fn ladder_shape() -> EntityDeltaShape {
        EntityDeltaShape {
            operation_kind: "claim.replace".to_owned(),
            target_entity_type: ENTITY_TYPE_CLAIM,
            normalized_paths: vec!["profile.note".to_owned()],
        }
    }

    fn ladder_delta(
        target_ref: EntityId,
        delta_ref: EntityId,
        proposer: EntityId,
        owner: EntityId,
    ) -> EntityDeltaArtifact {
        EntityDeltaArtifact {
            target_ref,
            base_state_ref: None,
            delta_ref,
            shape: ladder_shape(),
            proposer_actor_ref: proposer,
            owning_actor_ref: owner,
            message_thread_ref: None,
        }
    }

    struct AlwaysGraduated;

    impl GraduationLookup for AlwaysGraduated {
        fn scope_is_graduated(
            &self,
            _scope: &GraduationScope,
        ) -> std::result::Result<bool, String> {
            Ok(true)
        }

        fn shape_was_approved(
            &self,
            _scope: &GraduationScope,
            _fingerprint: DeltaShapeFingerprint,
        ) -> std::result::Result<bool, String> {
            Ok(true)
        }
    }

    fn ladder_scope(proposer: EntityId, owner: EntityId) -> GraduationScope {
        GraduationScope {
            proposer_actor_ref: proposer,
            owning_actor_ref: owner,
            operation_kind: "claim.replace".to_owned(),
            target_entity_type: ENTITY_TYPE_CLAIM,
            skill_or_agent_ref: None,
            standing_grant_ref: ladder_id(0xB1),
        }
    }

    /// The whole cross-actor fixture: the acting agent, the state's owner, the
    /// owned CLAIM target, and a durable delta artifact.
    struct CrossActorFixture {
        proposer: EntityId,
        owner: EntityId,
        target: EntityId,
        delta_ref: EntityId,
    }

    fn cross_actor_fixture(vault: &Vault) -> CrossActorFixture {
        let proposer = own_agent(vault);
        let owner = other_actor(vault);
        let target = owned_claim(vault, 0xB4, owner, EdgeActorClass::Human);
        let delta_ref = consult_turn(vault, 0x7B).entity_ref();
        CrossActorFixture {
            proposer,
            owner,
            target,
            delta_ref,
        }
    }

    // ── additive payload ────────────────────────────────────────────────

    /// The ONE-1699 payload keeps decoding as the legacy question shape, and
    /// the three ONE-1888 additions survive a body round-trip.
    #[test]
    fn consult_payload_additions_are_optional_and_round_trip() {
        let question = ConsultPayloadRef::Turn(ladder_id(0xC1));
        let legacy = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
        let decoded_legacy = decode_consult_payload(&consult_payload_value(&legacy))
            .expect("legacy payload decodes");

        assert_eq!(decoded_legacy, legacy);
        assert_eq!(decoded_legacy.purpose, None);
        assert_eq!(decoded_legacy.consult_purpose(), ConsultPurpose::Question);
        assert_eq!(decoded_legacy.entity_delta, None);
        assert_eq!(decoded_legacy.lineage, None);

        let extended = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2))
            .with_entity_delta(ladder_delta(
                ladder_id(0xC3),
                ladder_id(0xC4),
                ladder_id(0xC5),
                ladder_id(0xC6),
            ))
            .with_lineage(ConsultLineage {
                relation: ConsultLineageRelation::Counter,
                parent_task_ref: ladder_id(0xC7),
            });
        let decoded =
            decode_consult_payload(&consult_payload_value(&extended)).expect("payload decodes");

        assert_eq!(decoded, extended);
        assert_eq!(decoded.consult_purpose(), ConsultPurpose::EntityDelta);
    }

    /// The purpose and the artifact must agree, and a self-owned "cross-actor"
    /// delta is the auto path taking the wrong door.
    #[test]
    fn consult_payload_refuses_contradictory_purposes() {
        let question = ConsultPayloadRef::Turn(ladder_id(0xC1));
        let mut delta_without_artifact =
            ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
        delta_without_artifact.purpose = Some(ConsultPurpose::EntityDelta);

        let mut artifact_without_purpose =
            ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
        artifact_without_purpose.entity_delta = Some(ladder_delta(
            ladder_id(0xC3),
            ladder_id(0xC4),
            ladder_id(0xC5),
            ladder_id(0xC6),
        ));

        let same_actor = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2))
            .with_entity_delta(ladder_delta(
                ladder_id(0xC3),
                ladder_id(0xC4),
                ladder_id(0xC5),
                ladder_id(0xC5),
            ));

        for (index, payload) in [delta_without_artifact, artifact_without_purpose, same_actor]
            .into_iter()
            .enumerate()
        {
            assert!(
                decode_consult_payload(&consult_payload_value(&payload)).is_err(),
                "case {index} must be refused"
            );
        }
    }

    // ── ladder projection ───────────────────────────────────────────────

    /// The ladder projects onto ONE-1699's persisted vocabulary exactly as the
    /// disposition table says, and `Escalated` is deliberately NOT terminal.
    #[test]
    fn ladder_states_project_onto_the_one_1699_task_vocabulary() {
        let ladder_terminal = |disposition: LadderTerminalDisposition| LadderTerminalState {
            disposition,
            result_ref: ladder_id(0xD1),
            counter_task_ref: matches!(disposition, LadderTerminalDisposition::Countered)
                .then(|| ladder_id(0xD2)),
            finished_at: 900,
        };
        let table = [
            (
                LadderTerminalDisposition::Approved,
                Some(TaskTerminalDisposition::Completed),
            ),
            (
                LadderTerminalDisposition::Overridden,
                Some(TaskTerminalDisposition::Completed),
            ),
            (
                LadderTerminalDisposition::Rejected,
                Some(TaskTerminalDisposition::Rejected),
            ),
            (
                LadderTerminalDisposition::Failed,
                Some(TaskTerminalDisposition::Failed),
            ),
            (LadderTerminalDisposition::Escalated, None),
            (
                LadderTerminalDisposition::Countered,
                Some(TaskTerminalDisposition::Rejected),
            ),
            (
                LadderTerminalDisposition::Abandoned,
                Some(TaskTerminalDisposition::Abandoned),
            ),
        ];

        for (disposition, expected) in table {
            let projected = project_consult_ladder_state(&ConsultLadderState::Terminal(
                ladder_terminal(disposition),
            ));
            match expected {
                Some(task_disposition) => {
                    let TaskExecutionState::Terminal(record) = &projected else {
                        panic!("{} projects terminal", disposition.as_str());
                    };
                    assert_eq!(record.disposition, task_disposition);
                    assert_eq!(record.ladder, Some(disposition));
                    assert_eq!(record.result_ref, Some(ladder_id(0xD1)));
                    // The finer ladder outcome survives a body round-trip.
                    let decoded = decode_task_terminal_record(&task_terminal_record_value(record))
                        .expect("terminal record round-trips");
                    assert_eq!(decoded, *record);
                    assert_eq!(
                        ladder_terminal_from_task_terminal(&decoded)
                            .expect("ladder terminal lifts back")
                            .disposition,
                        disposition
                    );
                }
                None => assert_eq!(
                    projected,
                    TaskExecutionState::Interrupted,
                    "escalation waits on its follow-on rather than settling"
                ),
            }
        }

        assert_eq!(
            project_consult_ladder_state(&ConsultLadderState::Working(WorkingState {
                started_at: 5,
                decision_round: 2,
            })),
            TaskExecutionState::Working { started_at: 5 }
        );
        assert_eq!(
            project_consult_ladder_state(&ConsultLadderState::Interrupted(InterruptedState {
                kind: InterruptionKind::Critical,
                consent_required: true,
                case_ref: ladder_id(0xD3),
                interrupted_at: 7,
            })),
            TaskExecutionState::Interrupted
        );
    }

    /// A persisted ONE-1699 terminal without a `result_ref` cannot become a
    /// ladder terminal at all: the ladder's result is not optional.
    #[test]
    fn a_result_less_legacy_terminal_fails_closed() {
        let legacy = TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: None,
            summary: None,
            finished_at: 10,
            ladder: None,
            counter_task_ref: None,
        };

        assert_eq!(
            ladder_terminal_from_task_terminal(&legacy),
            Err(LadderTransitionError::MissingResultRef)
        );
    }

    /// Two replicas converge on the same terminal register in either merge
    /// order: later `finished_at` wins, and a SUBSTANTIVE decision beats an
    /// expiry-like sweep on an exact tie.
    #[test]
    fn substantive_terminals_dominate_expiry_like_ones_on_an_exact_tie() {
        let record = |disposition, finished_at| TaskTerminalRecord {
            disposition,
            result_ref: Some(ladder_id(0xE1)),
            summary: None,
            finished_at,
            ladder: None,
            counter_task_ref: None,
        };
        let cases = [
            // A rejection that landed at the deadline instant is still an
            // answer: it beats the expiry sweep.
            (
                record(TaskTerminalDisposition::Rejected, 150),
                record(TaskTerminalDisposition::Expired, 150),
                record(TaskTerminalDisposition::Rejected, 150),
            ),
            (
                record(TaskTerminalDisposition::Rejected, 150),
                record(TaskTerminalDisposition::Abandoned, 150),
                record(TaskTerminalDisposition::Rejected, 150),
            ),
            (
                record(TaskTerminalDisposition::Completed, 150),
                record(TaskTerminalDisposition::Abandoned, 150),
                record(TaskTerminalDisposition::Completed, 150),
            ),
            // Time still dominates class.
            (
                record(TaskTerminalDisposition::Rejected, 100),
                record(TaskTerminalDisposition::Expired, 200),
                record(TaskTerminalDisposition::Expired, 200),
            ),
        ];

        for (index, (left, right, expected)) in cases.into_iter().enumerate() {
            let forward = merge_task_terminal_register(Some(&left), Some(&right));
            let backward = merge_task_terminal_register(Some(&right), Some(&left));
            assert_eq!(forward, backward, "case {index} must be order-free");
            assert_eq!(forward, Some(expected), "case {index} winner");
        }

        // Two substantive terminals at one instant fall to canonical bytes,
        // which both replicas compute identically.
        let completed = record(TaskTerminalDisposition::Completed, 150);
        let rejected = record(TaskTerminalDisposition::Rejected, 150);
        assert_eq!(
            merge_task_terminal_register(Some(&completed), Some(&rejected)),
            merge_task_terminal_register(Some(&rejected), Some(&completed))
        );
    }

    // ── ownership routing ───────────────────────────────────────────────

    /// A target the acting actor owns routes auto and writes nothing; a target
    /// owned by another actor mints exactly ONE owner-assigned consult and
    /// leaves the target byte-untouched.
    #[test]
    fn own_writes_route_auto_and_cross_actor_writes_mint_one_owner_consult() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
        let own_task = facade
            .tasks_create(&spec(LADDER_NOW))
            .expect("own task create effects")
            .task_ref
            .expect("own task minted");

        let own_route = facade
            .route_entity_delta(
                ladder_delta(
                    own_task,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.proposer,
                ),
                None,
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect("own delta routes");
        assert_eq!(own_route, CrossActorRoute::AutoOwn);

        let tasks_before = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task census")
            .len();
        let target_before = vault
            .get_raw(&fixture.target)
            .expect("target read")
            .expect("target stored");
        let cross_route = facade
            .route_entity_delta(
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.owner,
                ),
                None,
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect("cross-actor delta routes");
        let tasks_after = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task census")
            .len();

        let CrossActorRoute::ConsultOwner { receipt } = cross_route else {
            panic!("a non-graduated cross-actor write consults the owner");
        };
        let consult_ref = receipt.task_ref.expect("consult minted");
        let body = task_verb_body(&vault, consult_ref)
            .expect("decode consult")
            .expect("consult is typed");
        let payload = body.consult.as_ref().expect("consult payload");

        assert_eq!(tasks_after - tasks_before, 1, "exactly one TASK is written");
        assert_eq!(body.task_kind(), TaskKind::Consult);
        assert_eq!(
            body.assignee,
            Some(TaskAssignee::Peer {
                actor_ref: fixture.owner
            }),
            "the OWNING actor is the first adjudicator"
        );
        assert_eq!(payload.consult_purpose(), ConsultPurpose::EntityDelta);
        assert_eq!(
            payload
                .entity_delta
                .as_ref()
                .map(|delta| delta.proposer_actor_ref),
            Some(fixture.proposer)
        );
        // Routing proposes; it never writes the state it is asking about.
        assert_eq!(
            vault
                .get_raw(&fixture.target)
                .expect("target read")
                .expect("target stored"),
            target_before
        );
    }

    /// Ownership is resolved from durable state, never asserted: a forged
    /// owning actor and an unattributed proposer are both refused.
    #[test]
    fn a_forged_owner_or_proposer_is_refused() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);

        let forged_owner = facade
            .route_entity_delta(
                // Claims the proposer owns state the vault attributes to
                // another actor.
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.proposer,
                ),
                None,
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect_err("a forged owner is refused");
        let forged_proposer = facade
            .route_entity_delta(
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.owner,
                    fixture.owner,
                ),
                None,
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect_err("an unattributed proposer is refused");
        let unresolvable = facade
            .route_entity_delta(
                ladder_delta(
                    fixture.delta_ref,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.owner,
                ),
                None,
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect_err("a target with no recorded owner is refused");

        assert_eq!(forged_owner.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(forged_proposer.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(unresolvable.code, FACADE_CODE_INVALID_STATE);
    }

    /// A graduated pair on an already-receipted shape rides its existing
    /// standing grant instead of minting a second consult.
    #[test]
    fn a_graduated_known_shape_routes_through_its_standing_grant() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
        let scope = ladder_scope(fixture.proposer, fixture.owner);

        let before = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task census")
            .len();
        let route = facade
            .route_entity_delta(
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.owner,
                ),
                Some((&AlwaysGraduated, &scope)),
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect("graduated delta routes");
        let after = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task census")
            .len();

        assert_eq!(
            route,
            CrossActorRoute::AutoViaStandingGrant {
                standing_grant_ref: ladder_id(0xB1)
            }
        );
        assert_eq!(after, before, "an auto route mints no consult");

        // A grant for a DIFFERENT pair cannot be borrowed.
        let wrong_pair = ladder_scope(fixture.owner, fixture.proposer);
        let borrowed = facade
            .route_entity_delta(
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.owner,
                ),
                Some((&AlwaysGraduated, &wrong_pair)),
                LADDER_DEADLINE,
                LADDER_NOW,
            )
            .expect("mismatched grant still routes");
        assert!(matches!(borrowed, CrossActorRoute::ConsultOwner { .. }));
    }

    // ── counter lineage ─────────────────────────────────────────────────

    /// A counter is a NEW task with `Counter` lineage. The open original
    /// terminalizes as rejected-with-counter-lineage in the same transaction;
    /// an already-terminal original is left exactly as it was.
    #[test]
    fn counter_mints_a_new_task_and_never_reopens_the_original() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
        let delta = ladder_delta(
            fixture.target,
            fixture.delta_ref,
            fixture.proposer,
            fixture.owner,
        );
        let CrossActorRoute::ConsultOwner { receipt } = facade
            .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
            .expect("cross-actor delta routes")
        else {
            panic!("expected an owner consult");
        };
        let original = receipt.task_ref.expect("consult minted");

        let counter = facade
            .mint_counter_task(original, delta.clone(), LADDER_DEADLINE, LADDER_NOW + 5)
            .expect("counter mints")
            .task_ref
            .expect("counter task minted");
        let original_body = task_verb_body(&vault, original)
            .expect("decode original")
            .expect("original is typed");
        let counter_body = task_verb_body(&vault, counter)
            .expect("decode counter")
            .expect("counter is typed");

        assert_ne!(counter, original);
        assert_eq!(
            counter_body
                .consult
                .as_ref()
                .and_then(|payload| payload.lineage),
            Some(ConsultLineage {
                relation: ConsultLineageRelation::Counter,
                parent_task_ref: original,
            })
        );
        let terminal = original_body.terminal().expect("original terminalized");
        assert_eq!(terminal.disposition, TaskTerminalDisposition::Rejected);
        assert_eq!(terminal.ladder, Some(LadderTerminalDisposition::Countered));
        assert_eq!(terminal.counter_task_ref, Some(counter));
        assert!(terminal.result_ref.is_some(), "counter lineage is durable");

        // A SECOND counter finds the original already terminal and leaves it
        // byte-identical.
        let before = vault
            .get_raw(&original)
            .expect("original read")
            .expect("original stored");
        let second = facade
            .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 9)
            .expect("a second counter still mints")
            .task_ref
            .expect("second counter minted");

        assert_ne!(second, counter);
        assert_eq!(
            vault
                .get_raw(&original)
                .expect("original read")
                .expect("original stored"),
            before,
            "a terminal original is never rewritten"
        );
    }

    // ── durable ladder CAS ──────────────────────────────────────────────

    /// Seeds one consult's persisted state to the projection of `state` so the
    /// CAS has a ladder row to move.
    fn seed_ladder_state(vault: &Vault, task_ref: EntityId, state: &ConsultLadderState) {
        vault
            .with_write_txn(|wtxn| {
                let mut body =
                    task_verb_body_in(vault, &*wtxn, task_ref)?.expect("consult is typed");
                body.state = Some(project_consult_ladder_state(state));
                let encoded = encode_task_verb_body(body);
                vault
                    .batch_in()
                    .put(
                        &task_ref,
                        ENTITY_TYPE_TASK,
                        TimeRange {
                            start: LADDER_NOW,
                            end: LADDER_NOW,
                        },
                        LADDER_NOW,
                        &encoded,
                    )
                    .apply(wtxn)
            })
            .expect("seed the ladder projection");
    }

    /// The CAS decides against the PERSISTED projection, not the caller's
    /// optimism: a freshly-minted `Queued` consult has no ladder row yet.
    #[test]
    fn the_durable_ladder_cas_refuses_a_stale_expectation() {
        let (_dir, vault) = open_vault();
        let (task_ref, _peer, _question) = open_consult(&vault);
        let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);

        let conflict = facade
            .compare_and_set_consult_ladder(
                task_ref,
                &ConsultLadderState::Working(WorkingState {
                    started_at: LADDER_NOW,
                    decision_round: 0,
                }),
                LadderTransition::Interrupt(InterruptedState {
                    kind: InterruptionKind::Contested,
                    consent_required: false,
                    case_ref: ladder_id(0xF1),
                    interrupted_at: LADDER_NOW + 1,
                }),
            )
            .expect_err("a stale expectation is refused");

        assert_eq!(conflict.code, FACADE_CODE_INVALID_STATE);
    }

    /// A working ladder escalates to the persisted `Interrupted` state, then
    /// refuses every further move: the pure rule and the durable projection
    /// agree that terminal is immutable.
    #[test]
    fn a_working_ladder_escalates_then_becomes_immutable() {
        let (_dir, vault) = open_vault();
        let (task_ref, _peer, _question) = open_consult(&vault);
        let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
        let working = ConsultLadderState::Working(WorkingState {
            started_at: LADDER_NOW,
            decision_round: 0,
        });
        seed_ladder_state(&vault, task_ref, &working);

        let escalated = LadderTerminalState {
            disposition: LadderTerminalDisposition::Escalated,
            result_ref: ladder_id(0xF3),
            counter_task_ref: None,
            finished_at: LADDER_NOW + 3,
        };
        let receipt = facade
            .compare_and_set_consult_ladder(task_ref, &working, LadderTransition::Finish(escalated))
            .expect("a working ladder may escalate");
        let refused = facade
            .compare_and_set_consult_ladder(
                task_ref,
                &ConsultLadderState::Terminal(escalated),
                LadderTransition::Finish(LadderTerminalState {
                    disposition: LadderTerminalDisposition::Approved,
                    result_ref: ladder_id(0xF4),
                    counter_task_ref: None,
                    finished_at: LADDER_NOW + 4,
                }),
            )
            .expect_err("a terminal ladder is immutable");

        assert_eq!(receipt.task_state, TaskExecutionState::Interrupted);
        assert_eq!(
            receipt.ladder_state,
            ConsultLadderState::Terminal(escalated)
        );
        assert_eq!(refused.code, FACADE_CODE_INVALID_STATE);
        // An escalation is NOT a terminal TASK row, so the board keeps it live.
        let body = task_verb_body(&vault, task_ref)
            .expect("decode consult")
            .expect("consult is typed");
        assert_eq!(body.state, Some(TaskExecutionState::Interrupted));
        assert_eq!(body.terminal(), None);
    }

    /// A consent-required interruption resumes only through a human verdict —
    /// enforced on the durable path, not just the pure one.
    #[test]
    fn a_consent_required_interruption_cannot_be_resumed_durably() {
        let (_dir, vault) = open_vault();
        let (task_ref, _peer, _question) = open_consult(&vault);
        let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
        let waiting = ConsultLadderState::Interrupted(InterruptedState {
            kind: InterruptionKind::Critical,
            consent_required: true,
            case_ref: ladder_id(0xF5),
            interrupted_at: LADDER_NOW,
        });
        seed_ladder_state(&vault, task_ref, &waiting);

        let refused = facade
            .compare_and_set_consult_ladder(
                task_ref,
                &waiting,
                LadderTransition::Resume(WorkingState {
                    started_at: LADDER_NOW + 1,
                    decision_round: 1,
                }),
            )
            .expect_err("consent-required work does not resume itself");
        // The human verdict path DOES settle it.
        let approved = facade
            .compare_and_set_consult_ladder(
                task_ref,
                &waiting,
                LadderTransition::Finish(LadderTerminalState {
                    disposition: terminal_for_human_verdict(HumanVerdict::Approve {
                        rationale_ref: Some(ladder_id(0xF6)),
                    }),
                    result_ref: ladder_id(0xF7),
                    counter_task_ref: None,
                    finished_at: LADDER_NOW + 2,
                }),
            )
            .expect("a human verdict settles the case");

        assert_eq!(refused.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(
            approved
                .ladder_state
                .terminal()
                .map(|state| state.disposition),
            Some(LadderTerminalDisposition::Approved)
        );
    }

    // ── human verdict codec ─────────────────────────────────────────────

    /// All four verdicts round-trip, escalation carries ONE-1699's assignee
    /// enum, and an override missing either durable ref is refused rather than
    /// defaulted.
    #[test]
    fn human_verdicts_round_trip_and_override_requires_both_refs() {
        let verdicts = [
            HumanVerdict::Approve {
                rationale_ref: None,
            },
            HumanVerdict::Approve {
                rationale_ref: Some(ladder_id(0xA4)),
            },
            HumanVerdict::Reject {
                rationale_ref: Some(ladder_id(0xA5)),
            },
            HumanVerdict::OverrideWithDiff {
                delta_ref: ladder_id(0xA6),
                rationale_ref: ladder_id(0xA7),
            },
            HumanVerdict::Escalate {
                assignee: TaskAssignee::Human {
                    actor_ref: ladder_id(0xA8),
                },
                rationale_ref: ladder_id(0xA9),
            },
            HumanVerdict::Escalate {
                assignee: TaskAssignee::Dreamer,
                rationale_ref: ladder_id(0xAA),
            },
        ];
        for (index, verdict) in verdicts.into_iter().enumerate() {
            assert_eq!(
                decode_human_verdict(&human_verdict_value(verdict)).expect("verdict decodes"),
                verdict,
                "case {index}"
            );
        }

        let missing_rationale = Value::Map(vec![
            (Value::from("verdict"), Value::from("override_with_diff")),
            (Value::from("delta_ref"), entity_ref_value(ladder_id(0xA6))),
        ]);
        let missing_delta = Value::Map(vec![
            (Value::from("verdict"), Value::from("override_with_diff")),
            (
                Value::from("rationale_ref"),
                entity_ref_value(ladder_id(0xA7)),
            ),
        ]);
        let unknown = Value::Map(vec![(Value::from("verdict"), Value::from("maybe"))]);
        for (index, malformed) in [missing_rationale, missing_delta, unknown]
            .into_iter()
            .enumerate()
        {
            assert!(
                decode_human_verdict(&malformed).is_err(),
                "case {index} must be refused"
            );
        }
    }

    // ── magistrate provenance ───────────────────────────────────────────

    fn magistrate_case(
        state_ref: EntityId,
        delta_ref: EntityId,
        criticality: CaseCriticality,
    ) -> MagistrateCase {
        MagistrateCase {
            task_ref: ladder_id(0x91),
            contested_state_ref: state_ref,
            contested_delta_ref: delta_ref,
            criticality,
            policy: vec![PolicyEvidence {
                policy_ref: ladder_id(0x92),
                selected_delta_ref: Some(delta_ref),
            }],
            authority: vec![AuthorityEvidence {
                authoritative_actor_ref: ladder_id(0x93),
                state_ref,
                selected_delta_ref: Some(delta_ref),
            }],
            temporal: Vec::new(),
            candidate_delta_refs: vec![delta_ref],
            dreamer_attempt_ref: None,
            now: LADDER_NOW,
        }
    }

    /// Authorship is re-derived from the vault's own claim/provenance
    /// envelopes: a contested state written under the Dreamer run surface
    /// recuses, and the SAME case shape over agent-authored state rules.
    #[test]
    fn magistrate_recuses_on_vault_derived_dreamer_authorship() {
        let (_dir, vault) = open_vault();
        let actor = own_agent(&vault);
        let subject = other_actor(&vault);
        let dreamer_state = ladder_id(0x94);
        let agent_state = ladder_id(0x95);
        let delta = ladder_id(0x96);
        put_envelope_claim(
            &vault,
            dreamer_state,
            subject,
            actor,
            EdgeActorClass::Agent,
            dreamer_provenance(),
        );
        put_envelope_claim(
            &vault,
            agent_state,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
        put_envelope_claim(
            &vault,
            delta,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );

        let dreamer_case = magistrate_case(dreamer_state, delta, CaseCriticality::Normal);
        let agent_case = magistrate_case(agent_state, delta, CaseCriticality::Normal);

        assert_eq!(
            derive_state_authorship(&vault, &dreamer_case).expect("authorship derives"),
            StateAuthorship::Dreamer
        );
        assert_eq!(
            derive_state_authorship(&vault, &agent_case).expect("authorship derives"),
            StateAuthorship::OtherAgent
        );
        assert_eq!(
            decide_magistrate(&vault, &dreamer_case).expect("verdict"),
            MagistrateVerdict::Recused {
                reason: MagistrateRecusal::DreamerAuthoredState
            }
        );
        // The recusal is the provenance talking, not a blanket refusal.
        assert_eq!(
            decide_magistrate(&vault, &agent_case).expect("verdict"),
            MagistrateVerdict::Rule {
                selected_delta_ref: delta,
                rationale_ref: ladder_id(0x92),
            }
        );
    }

    /// A caller cannot buy a ruling with a forged summary: with every case
    /// field naming another agent, Dreamer authorship of the contested DELTA
    /// still recuses, and unattributable state fails closed.
    #[test]
    fn forged_authorship_cannot_defeat_the_provenance_derivation() {
        let (_dir, vault) = open_vault();
        let actor = own_agent(&vault);
        let subject = other_actor(&vault);
        let agent_state = ladder_id(0x97);
        let dreamer_delta = ladder_id(0x98);
        put_envelope_claim(
            &vault,
            agent_state,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
        put_envelope_claim(
            &vault,
            dreamer_delta,
            subject,
            actor,
            EdgeActorClass::Agent,
            dreamer_provenance(),
        );

        let forged = magistrate_case(agent_state, dreamer_delta, CaseCriticality::Normal);
        let unattributable =
            magistrate_case(ladder_id(0x99), dreamer_delta, CaseCriticality::Normal);

        assert_eq!(
            decide_magistrate(&vault, &forged).expect("verdict"),
            MagistrateVerdict::Recused {
                reason: MagistrateRecusal::DreamerAuthoredState
            }
        );
        assert!(
            decide_magistrate(&vault, &unattributable).is_err(),
            "state with no recoverable attribution is not ruled on"
        );
    }

    /// The magistrate's whole write set is receipt + supersession + conflict
    /// claim. It enqueues no work, schedules no outbound, and deletes nothing.
    #[test]
    fn applying_a_ruling_writes_only_reversible_records() {
        let (_dir, vault) = open_vault();
        let actor = own_agent(&vault);
        let subject = other_actor(&vault);
        let state = ladder_id(0x9A);
        let selected = ladder_id(0x9B);
        let competing = ladder_id(0x9C);
        for claim_ref in [state, selected, competing] {
            put_envelope_claim(
                &vault,
                claim_ref,
                subject,
                actor,
                EdgeActorClass::Agent,
                agent_provenance(),
            );
        }
        let mut case = magistrate_case(state, selected, CaseCriticality::Normal);
        case.candidate_delta_refs = vec![selected, competing];

        let attempts_before = AttemptQueue::new(&vault).list().expect("attempts").len();
        let conflicts_before = open_conflict_count(&vault);
        let verdict = decide_magistrate(&vault, &case).expect("verdict");
        let receipt = apply_magistrate_verdict(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            &case,
            &verdict,
        )
        .expect("ruling applies");
        let attempts_after = AttemptQueue::new(&vault).list().expect("attempts").len();

        assert_eq!(
            verdict,
            MagistrateVerdict::Rule {
                selected_delta_ref: selected,
                rationale_ref: ladder_id(0x92),
            }
        );
        assert!(receipt.reversible);
        assert_eq!(receipt.appeal_handle, case.task_ref);
        assert_eq!(
            attempts_after, attempts_before,
            "a ruling enqueues no work of any kind"
        );
        assert_eq!(
            vault
                .get_entity_type(&receipt.receipt_ref)
                .expect("receipt type"),
            Some(ENTITY_TYPE_TURN)
        );
        // The replaced head was superseded through the EXISTING claim API, and
        // the surviving competitor surfaced as the existing conflict predicate.
        assert_eq!(
            vault
                .get_claim(&state)
                .expect("state claim")
                .expect("stored")
                .lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        assert_eq!(open_conflict_count(&vault) - conflicts_before, 1);
    }

    fn open_conflict_count(vault: &Vault) -> usize {
        vault
            .entities_by_type(ENTITY_TYPE_CLAIM)
            .expect("claim census")
            .into_iter()
            .filter_map(|claim_ref| vault.get_claim(&claim_ref).ok().flatten())
            .filter(|body| body.predicate == PREDICATE_CONFLICT_OPEN)
            .count()
    }

    /// Advice is receipted but never applied: a critical case leaves the
    /// contested head exactly where it was.
    #[test]
    fn a_critical_case_is_advised_and_never_applied() {
        let (_dir, vault) = open_vault();
        let actor = own_agent(&vault);
        let subject = other_actor(&vault);
        let state = ladder_id(0x9D);
        let delta = ladder_id(0x9E);
        for claim_ref in [state, delta] {
            put_envelope_claim(
                &vault,
                claim_ref,
                subject,
                actor,
                EdgeActorClass::Agent,
                agent_provenance(),
            );
        }
        let case = magistrate_case(state, delta, CaseCriticality::Critical);

        let verdict = decide_magistrate(&vault, &case).expect("verdict");
        apply_magistrate_verdict(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            &case,
            &verdict,
        )
        .expect("advice is receipted");

        assert_eq!(
            verdict,
            MagistrateVerdict::AdviceOnly {
                recommended_delta_ref: Some(delta),
                rationale_ref: ladder_id(0x92),
            }
        );
        assert_eq!(
            vault
                .get_claim(&state)
                .expect("state claim")
                .expect("stored")
                .lifecycle,
            ClaimLifecycleStatus::Active,
            "advice cannot terminalize the contested state"
        );
    }

    /// An overturn leaves the original receipt intact and writes exactly one
    /// typed record — the complete ED handoff, with no ED call.
    #[test]
    fn an_overturn_preserves_the_original_receipt() {
        let (_dir, vault) = open_vault();
        let actor = own_agent(&vault);
        let subject = other_actor(&vault);
        let state = ladder_id(0x6A);
        let delta = ladder_id(0x6B);
        for claim_ref in [state, delta] {
            put_envelope_claim(
                &vault,
                claim_ref,
                subject,
                actor,
                EdgeActorClass::Agent,
                agent_provenance(),
            );
        }
        let case = magistrate_case(state, delta, CaseCriticality::Normal);
        let verdict = decide_magistrate(&vault, &case).expect("verdict");
        let receipt = apply_magistrate_verdict(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            &case,
            &verdict,
        )
        .expect("ruling applies");
        let receipt_bytes = vault
            .get_raw(&receipt.receipt_ref)
            .expect("receipt read")
            .expect("receipt stored");

        let overturn_ref = record_magistrate_overturn(
            &vault,
            &MagistrateOverturnRecord {
                original_receipt_ref: receipt.receipt_ref,
                overturning_verdict_ref: ladder_id(0xA3),
                corrected_delta_ref: Some(delta),
                rationale_ref: ladder_id(0xA4),
                occurred_at: LADDER_NOW + 10,
            },
        )
        .expect("overturn records");

        assert_ne!(overturn_ref, receipt.receipt_ref);
        assert_eq!(
            vault
                .get_raw(&receipt.receipt_ref)
                .expect("receipt read")
                .expect("receipt stored"),
            receipt_bytes,
            "the original receipt is never erased or rewritten"
        );
        assert_eq!(
            vault.get_entity_type(&overturn_ref).expect("overturn type"),
            Some(ENTITY_TYPE_TURN)
        );
    }

    /// Magistrate work rides the EXISTING Dreamer runner queue as a
    /// payload-level attempt type under the unchanged outer kind.
    #[test]
    fn magistrate_work_enqueues_as_a_payload_level_attempt_type() {
        let (_dir, vault) = open_vault();
        let store = DreamerRunnerStore::new(&vault);
        let case = magistrate_case(ladder_id(0xB2), ladder_id(0xB3), CaseCriticality::Normal);

        let outcome = enqueue_magistrate(&store, &case, None, Some("run-magistrate".to_owned()))
            .expect("magistrate enqueues");
        let replay = enqueue_magistrate(&store, &case, None, Some("run-magistrate".to_owned()))
            .expect("magistrate re-enqueue");

        let EnqueueDreamerAttemptOutcome::Enqueued(status) = outcome else {
            panic!("the first enqueue is not a dedupe hit");
        };
        assert_eq!(status.payload.attempt_type, DREAMER_MAGISTRATE_ATTEMPT_TYPE);
        assert_eq!(status.attempt.kind, DREAMER_RUNNER_ATTEMPT_KIND);
        assert!(matches!(replay, EnqueueDreamerAttemptOutcome::Existing(_)));
    }

    // ── board + A2A over persisted rows ─────────────────────────────────

    /// The board reads the ladder outcome off the persisted row: a countered
    /// original renders as an immutable rejected row naming its successor,
    /// while the counter renders independently.
    #[test]
    fn a_countered_original_renders_as_rejected_with_its_counter() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
        let delta = ladder_delta(
            fixture.target,
            fixture.delta_ref,
            fixture.proposer,
            fixture.owner,
        );
        let CrossActorRoute::ConsultOwner { receipt } = facade
            .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
            .expect("cross-actor delta routes")
        else {
            panic!("expected an owner consult");
        };
        let original = receipt.task_ref.expect("consult minted");
        let counter = facade
            .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
            .expect("counter mints")
            .task_ref
            .expect("counter task minted");

        let section = facade.tasks_check().expect("board renders");
        let original_row = section
            .rows
            .iter()
            .find(|row| row.id == original.to_hex())
            .expect("the countered original stays on the board");
        let counter_row = section
            .rows
            .iter()
            .find(|row| row.id == counter.to_hex())
            .expect("the counter renders independently");

        assert_eq!(original_row.status, TaskBoardStatus::Failed);
        assert_eq!(
            original_row.ladder_disposition,
            Some(LadderTerminalDisposition::Countered)
        );
        assert_eq!(
            original_row.counter_task_ref.as_deref(),
            Some(counter.to_hex().as_str())
        );
        let tokens: Vec<&str> = original_row.line.split_whitespace().collect();
        assert!(tokens.contains(&"rejected"), "{}", original_row.line);
        assert!(tokens.contains(&"countered"), "{}", original_row.line);
        // The counter is its own row: no ladder outcome of its own yet, and
        // no counter link pointing anywhere.
        assert_eq!(counter_row.ladder_disposition, None);
        assert_eq!(counter_row.counter_task_ref, None);
        assert_ne!(counter_row.id, original_row.id);
    }

    /// A counter answers to the same attribution laws as the original ask:
    /// a forged owner or an unattributed proposer never mints one.
    #[test]
    fn a_counter_cannot_forge_its_owner_or_proposer() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
        let delta = ladder_delta(
            fixture.target,
            fixture.delta_ref,
            fixture.proposer,
            fixture.owner,
        );
        let CrossActorRoute::ConsultOwner { receipt } = facade
            .route_entity_delta(delta, None, LADDER_DEADLINE, LADDER_NOW)
            .expect("cross-actor delta routes")
        else {
            panic!("expected an owner consult");
        };
        let original = receipt.task_ref.expect("consult minted");

        let forged_owner = facade
            .mint_counter_task(
                original,
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.proposer,
                    fixture.proposer,
                ),
                LADDER_DEADLINE,
                LADDER_NOW + 5,
            )
            .expect_err("a forged owner is refused");
        let forged_proposer = facade
            .mint_counter_task(
                original,
                ladder_delta(
                    fixture.target,
                    fixture.delta_ref,
                    fixture.owner,
                    fixture.owner,
                ),
                LADDER_DEADLINE,
                LADDER_NOW + 5,
            )
            .expect_err("an unattributed proposer is refused");
        let original_body = task_verb_body(&vault, original)
            .expect("decode original")
            .expect("original is typed");

        assert_eq!(forged_owner.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(forged_proposer.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(
            original_body.terminal(),
            None,
            "a refused counter never terminalizes the original"
        );
    }

    /// An UNSTAMPED ONE-1699 terminal projects its OWN disposition: `expired`
    /// is not rounded to the nearest ladder word, and no interruption kind is
    /// invented for a body that never recorded one.
    #[test]
    fn an_unstamped_legacy_terminal_projects_its_own_disposition() {
        let (_dir, vault) = open_vault();
        let (task_ref, _peer, _question) = open_consult(&vault);
        let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
        grant_outbound(&vault, own_agent(&vault), 0xC8);
        facade
            .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
            .expect("the expiry sweep runs");

        let projection = project_consult_task_to_a2a(&vault, task_ref)
            .expect("projection reads")
            .expect("the expired consult projects");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode consult")
            .expect("consult is typed");

        assert_eq!(body.terminal().and_then(|record| record.ladder), None);
        assert_eq!(projection.state, A2aBaseTaskState::Cancelled);
        assert_eq!(
            projection.extensions.terminal_disposition.as_deref(),
            Some("expired")
        );
        assert_eq!(projection.extensions.interruption_kind, None);
        assert!(projection.extensions.result_ref.is_some());
    }

    /// The A2A projection reads a real persisted consult, including its
    /// counter lineage. A counter is a decision that COMPLETED, never a
    /// failure.
    #[test]
    fn a_persisted_counter_projects_with_its_counter_of_extension() {
        let (_dir, vault) = open_vault();
        let fixture = cross_actor_fixture(&vault);
        let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
        let delta = ladder_delta(
            fixture.target,
            fixture.delta_ref,
            fixture.proposer,
            fixture.owner,
        );
        let CrossActorRoute::ConsultOwner { receipt } = facade
            .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
            .expect("cross-actor delta routes")
        else {
            panic!("expected an owner consult");
        };
        let original = receipt.task_ref.expect("consult minted");
        let counter = facade
            .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
            .expect("counter mints")
            .task_ref
            .expect("counter task minted");

        let original_projection = project_consult_task_to_a2a(&vault, original)
            .expect("projection reads")
            .expect("the original projects");
        let counter_projection = project_consult_task_to_a2a(&vault, counter)
            .expect("projection reads")
            .expect("the counter projects");

        assert_eq!(original_projection.state, A2aBaseTaskState::Completed);
        assert_eq!(
            original_projection
                .extensions
                .terminal_disposition
                .as_deref(),
            Some("rejected")
        );
        assert_eq!(
            counter_projection.extensions.counter_of.as_deref(),
            Some(original.to_hex().as_str())
        );
    }
    // ── assignee routing (ONE-1700) ─────────────────────────────────────

    const ROUTE_NOW: u64 = 1_772_500_000;

    /// Every generic ONE-1700 fixture identity routes through the canonical
    /// band assertion, so a fixture can never alias a production-pinned system
    /// identity (`0xD7` is the default policy manifest — a seed collision there
    /// surfaces as a bewildering entity-type error deep inside an unrelated
    /// write). `crate::test_util::entity` owns the pinned list; this is the
    /// seed-shaped adapter onto the ONE-1699 fixture helpers, not a second copy
    /// of the rule.
    fn route_seed(seed: u8) -> u8 {
        crate::test_util::entity(seed);
        seed
    }

    fn route_peer(vault: &Vault, seed: u8) -> EntityId {
        consult_peer(vault, route_seed(seed))
    }

    fn route_turn(vault: &Vault, seed: u8) -> ConsultPayloadRef {
        consult_turn(vault, route_seed(seed))
    }

    fn route_dangling(seed: u8) -> EntityId {
        crate::test_util::entity(seed)
    }

    /// A dispatchable AGENT_DEF row: an ordinary fork of a seeded row, which is
    /// the only way to get an Active+approved+enabled definition without
    /// hand-rolling a body the validator would reject.
    fn routable_agent_def(vault: &Vault, seed: u8) -> EntityId {
        let def_ref = crate::test_util::entity(seed);
        let (base_id, base) = vault
            .get_seeded_agent_definition_by_logical_id("sys.keeper")
            .expect("resolve seeded keeper")
            .expect("seeded keeper exists");
        let mut fork = base.clone();
        fork.agent_id = format!("route-worker-{seed:02x}");
        fork.version = "1".to_owned();
        fork.forked_from = Some(base_id);
        fork.ceiling = base.ceiling;
        fork.logical_id = None;
        fork.display_name = None;
        fork.source = ClaimSource::UserStated;
        fork.provenance = Value::Map(vec![(Value::from("forkOf"), Value::from(base_id.to_hex()))]);
        vault
            .put_agent_definition(&def_ref, &fork, TimeRange { start: 1, end: 1 }, 1)
            .expect("store routable agent definition");
        def_ref
    }

    fn attempts_for(vault: &Vault, task_ref: EntityId) -> Vec<AttemptRecord> {
        let task_hex = task_ref.to_hex();
        AttemptQueue::new(vault)
            .list()
            .expect("list attempts")
            .into_iter()
            .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
            .collect()
    }

    fn route_spec(assignee: Option<TaskAssignee>) -> TaskCreateSpec {
        let base = TaskCreateSpec::new(Value::from("routed-task"), None, None, Some(ROUTE_NOW));
        match assignee {
            Some(assignee) => base.with_assignee(assignee),
            None => base,
        }
    }

    /// Compatibility: a schema-v1 create — assignee absent entirely — still
    /// mints exactly one `tasks.realize` attempt on the Dreamer lane.
    #[test]
    fn absent_assignee_routes_to_one_dreamer_realization() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let receipt = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(None))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        let attempts = attempts_for(&vault, task_ref);

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].kind, TASK_REALIZE_ATTEMPT_KIND);
        assert_eq!(
            receipt.route.map(TaskRouteOutcome::lane),
            Some(TaskRouteLane::Dreamer)
        );
        assert_eq!(
            receipt.route.and_then(TaskRouteOutcome::local_attempt),
            Some(attempts[0].id)
        );
    }

    /// `Some(Dreamer)` and absent are the SAME lane: one realize attempt, and
    /// the explicit spelling is what lands on the row.
    #[test]
    fn explicit_dreamer_assignee_routes_exactly_like_absent() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let receipt = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Dreamer)))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        let attempts = attempts_for(&vault, task_ref);
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].kind, TASK_REALIZE_ATTEMPT_KIND);
        assert_eq!(body.assignee, Some(TaskAssignee::Dreamer));
        assert_eq!(
            receipt.route.map(TaskRouteOutcome::lane),
            Some(TaskRouteLane::Dreamer)
        );
    }

    /// The agent-definition lane creates ONE in-process `agent.dispatch`
    /// attempt, backlinked to the TASK, and never a `tasks.realize` row.
    #[test]
    fn agent_def_assignee_routes_to_one_in_process_dispatch() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let agent_def_ref = routable_agent_def(&vault, 0xC1);
        let receipt = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        let attempts = attempts_for(&vault, task_ref);
        let payload =
            decode_dreamer_attempt_payload(&attempts[0].payload).expect("dispatch payload");

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].kind, DREAMER_RUNNER_ATTEMPT_KIND);
        assert_eq!(payload.attempt_type, AGENT_DISPATCH_ATTEMPT_TYPE);
        assert_eq!(
            receipt.route,
            Some(TaskRouteOutcome::AgentDispatch {
                attempt_ref: attempts[0].id,
                agent_def_ref,
            })
        );
    }

    /// The dispatched child freezes the CURRENT definition snapshot and
    /// addresses the ROW: no preset variant is persisted anywhere (ONE-1890
    /// compatibility, proven from the stored bytes).
    #[test]
    fn agent_def_route_persists_a_row_ref_and_no_preset() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let agent_def_ref = routable_agent_def(&vault, 0xC2);
        let receipt = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        let attempts = attempts_for(&vault, task_ref);
        let payload =
            decode_dreamer_attempt_payload(&attempts[0].payload).expect("dispatch payload");
        let dispatch_input =
            decode_agent_dispatch_input(&payload.input).expect("decode dispatch input");
        let stored_body = vault.get(&task_ref).expect("read task").expect("task row");
        let stored_text = String::from_utf8_lossy(&stored_body).to_ascii_lowercase();

        assert_eq!(
            dispatch_input.target,
            AgentDispatchTarget::Custom(agent_def_ref)
        );
        assert_eq!(
            dispatch_input.definition.agent_id.as_str(),
            format!("route-worker-{:02x}", 0xC2).as_str()
        );
        assert_eq!(usize::from(stored_text.contains("preset")), 0);
        assert_eq!(usize::from(stored_text.contains("system")), 0);
    }

    /// Re-routing the SAME task ref returns the existing dispatch instead of
    /// minting a second one, and the dedupe row keeps its parent/run metadata.
    #[test]
    fn agent_def_route_is_idempotent_by_task_ref() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let agent_def_ref = routable_agent_def(&vault, 0xC3);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let receipt = facade
            .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        let first = attempts_for(&vault, task_ref);
        // A retried route on the SAME task: the dispatcher's namespaced dedupe
        // key resolves to the row already realizing it.
        let replayed = AgentDispatcher::new(&vault)
            .dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(agent_def_ref),
                parent_attempt: None,
                dedupe_key: Some(task_route_dedupe_key(task_ref)),
                run_id: None,
                now: ROUTE_NOW,
            })
            .expect("replayed dispatch");
        let after = attempts_for(&vault, task_ref);

        assert_eq!(first.len(), 1);
        assert_eq!(after.len(), 1);
        assert_eq!(
            match replayed {
                AgentDispatchOutcome::Existing(status) => status.attempt.id,
                AgentDispatchOutcome::Dispatched(_) => panic!("a replayed route must dedupe"),
            },
            first[0].id
        );
    }

    /// The peer lane mints the synced TASK and NOTHING local: no realize row,
    /// no dispatch row, no synthetic transport attempt.
    #[test]
    fn peer_assignee_routes_with_zero_local_attempts() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xC4);
        let receipt = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(attempts_for(&vault, task_ref).len(), 0);
        assert_eq!(
            AttemptQueue::new(&vault).list().expect("list").len(),
            0,
            "the peer lane mints no local attempt of any kind"
        );
        assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref }));
        assert_eq!(
            receipt.route,
            Some(TaskRouteOutcome::PeerSyncedOnly { actor_ref })
        );
    }

    /// A person the vault knows but cannot reach natively is refused in its own
    /// name, and the refusal rolls the WHOLE create back (ONE-1708). The
    /// reachability check lives inside the create transaction precisely so this
    /// cannot leave a human task with nothing tracking it.
    #[test]
    fn unreachable_human_assignee_rolls_the_whole_create_back() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        // A bare PERSON row: a real entity the assignee validator admits, with
        // no connected channel behind it.
        let actor_ref = route_peer(&vault, 0xC5);
        let error = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Human { actor_ref })))
            .expect_err("an unreachable person is refused");

        assert_eq!(error.code, FACADE_CODE_INVALID_STATE);
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .len(),
            0,
            "the TASK write rolls back with its follow-up cursor"
        );
        assert!(
            crate::human_task::human_followup_records(&vault)
                .expect("cursors")
                .is_empty()
        );
        assert_eq!(AttemptQueue::new(&vault).list().expect("list").len(), 0);
    }

    /// An assignee that names no live row — or names the WRONG kind — is
    /// refused before the TASK write, not compensated afterwards.
    #[test]
    fn agent_def_assignee_rejects_dangling_and_mistyped_rows_before_mutation() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let dangling = route_dangling(0xC6);
        let person = route_peer(&vault, 0xC7);

        let missing = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::AgentDef {
                agent_def_ref: dangling,
            })))
            .expect_err("a dangling agent definition is refused");
        let mistyped = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::AgentDef {
                agent_def_ref: person,
            })))
            .expect_err("a PERSON row is not an agent definition");

        assert_eq!(missing.code, mistyped.code);
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .len(),
            0
        );
        assert_eq!(AttemptQueue::new(&vault).list().expect("list").len(), 0);
    }

    /// The synced TASK body carries the execution FACTS and none of the local
    /// ACT mechanics: no lease owner, lock, trap id, or wait binding.
    #[test]
    fn task_body_carries_facts_and_never_local_lease_or_trap_state() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xC8);
        let peer_facade = vault.memory_facade(actor_ref, EdgeActorClass::Agent);
        let receipt = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create");
        let task_ref = receipt.task_ref.expect("task ref");
        peer_facade
            .mark_task_started(task_ref, ROUTE_NOW + 5)
            .expect("start");
        let result_ref = route_turn(&vault, 0xC9).entity_ref();
        peer_facade
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition: TaskTerminalDisposition::Abandoned,
                    finished_at: ROUTE_NOW + 9,
                },
            )
            .expect("land result");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");
        let terminal = body.terminal().expect("terminal record").clone();
        let stored = vault.get(&task_ref).expect("read task").expect("task row");
        let stored_text = String::from_utf8_lossy(&stored).to_ascii_lowercase();

        assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref }));
        assert_eq!(terminal.disposition, TaskTerminalDisposition::Abandoned);
        assert_eq!(terminal.result_ref, Some(result_ref));
        for act_marker in [
            "lease_owner",
            "lease",
            "lock",
            "trap",
            "park_owner",
            "peer_wait",
        ] {
            assert_eq!(
                usize::from(stored_text.contains(act_marker)),
                0,
                "synced TASK body must not carry local ACT mechanics: {act_marker}"
            );
        }
    }

    /// `started_at` stamps once. A re-delivered start reports the FIRST
    /// instant and mutates nothing — a redelivery is not a restart.
    #[test]
    fn mark_task_started_stamps_once_and_replays_idempotently() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xCA);
        let peer_facade = vault.memory_facade(actor_ref, EdgeActorClass::Agent);
        let task_ref = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create")
            .task_ref
            .expect("task ref");

        let first = peer_facade
            .mark_task_started(task_ref, ROUTE_NOW + 5)
            .expect("first start");
        let replay = peer_facade
            .mark_task_started(task_ref, ROUTE_NOW + 40)
            .expect("replayed start");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(first.started_at, ROUTE_NOW + 5);
        assert_eq!(usize::from(first.idempotent_replay), 0);
        assert_eq!(replay.started_at, ROUTE_NOW + 5);
        assert_eq!(usize::from(replay.idempotent_replay), 1);
        assert_eq!(
            body.state,
            Some(TaskExecutionState::Working {
                started_at: ROUTE_NOW + 5
            })
        );
    }

    /// Execution facts are ADDRESSED writes: an actor who is not the assignee
    /// cannot start or settle someone else's task.
    #[test]
    fn execution_facts_refuse_an_unaddressed_writer() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xCB);
        let stranger = route_peer(&vault, 0xCC);
        let task_ref = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create")
            .task_ref
            .expect("task ref");
        let result_ref = route_turn(&vault, 0xCD).entity_ref();
        let stranger_facade = vault.memory_facade(stranger, EdgeActorClass::Agent);

        let start_error = stranger_facade
            .mark_task_started(task_ref, ROUTE_NOW + 5)
            .expect_err("a stranger cannot start an addressed task");
        let land_error = stranger_facade
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: ROUTE_NOW + 9,
                },
            )
            .expect_err("a stranger cannot settle an addressed task");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(start_error.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(land_error.code, FACADE_CODE_FORBIDDEN);
        assert_eq!(body.state, Some(TaskExecutionState::Queued));
    }

    /// The local Dreamer has no actor row, so its lane answers to the task
    /// OWNER — the principal the engine drives realization under.
    #[test]
    fn dreamer_lane_execution_facts_answer_to_the_owner() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let task_ref = facade
            .tasks_create(&route_spec(Some(TaskAssignee::Dreamer)))
            .expect("create")
            .task_ref
            .expect("task ref");
        let result_ref = route_turn(&vault, 0xCE).entity_ref();

        let started = facade
            .mark_task_started(task_ref, ROUTE_NOW + 5)
            .expect("owner starts its own dreamer task");
        let landed = facade
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: ROUTE_NOW + 9,
                },
            )
            .expect("owner settles its own dreamer task");

        assert_eq!(started.started_at, ROUTE_NOW + 5);
        assert_eq!(landed.terminal.result_ref, Some(result_ref));
        assert_eq!(usize::from(landed.idempotent_replay), 0);
    }

    /// Terminal records are immutable and always carry `result_ref`. A
    /// byte-identical replay reports the winner; a CONFLICTING one is refused.
    #[test]
    fn terminal_results_are_immutable_and_always_carry_a_result_ref() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xCF);
        let peer_facade = vault.memory_facade(actor_ref, EdgeActorClass::Agent);
        let task_ref = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create")
            .task_ref
            .expect("task ref");
        let result_ref = route_turn(&vault, 0xD0).entity_ref();
        let other_ref = route_turn(&vault, 0xD1).entity_ref();
        let input = TaskResultInput {
            result_ref,
            disposition: TaskTerminalDisposition::Completed,
            finished_at: ROUTE_NOW + 9,
        };

        let landed = peer_facade
            .land_task_result(task_ref, &input)
            .expect("land result");
        let replay = peer_facade
            .land_task_result(task_ref, &input)
            .expect("identical replay reports the winner");
        let conflict = peer_facade
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref: other_ref,
                    disposition: TaskTerminalDisposition::Failed,
                    finished_at: ROUTE_NOW + 30,
                },
            )
            .expect_err("a converged terminal task is immutable");

        assert_eq!(landed.terminal.result_ref, Some(result_ref));
        assert_eq!(usize::from(landed.idempotent_replay), 0);
        assert_eq!(usize::from(replay.idempotent_replay), 1);
        assert_eq!(replay.terminal.result_ref, Some(result_ref));
        assert_eq!(conflict.code, FACADE_CODE_INVALID_STATE);
    }

    /// A result whose `result_ref` names nothing is refused: a terminal record
    /// without durable outputs is exactly what the floor forbids.
    #[test]
    fn land_task_result_requires_a_resolved_result_ref() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xD2);
        let task_ref = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create")
            .task_ref
            .expect("task ref");

        let error = vault
            .memory_facade(actor_ref, EdgeActorClass::Agent)
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref: route_dangling(0xD3),
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: ROUTE_NOW + 9,
                },
            )
            .expect_err("a dangling result ref is refused");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(usize::from(error.code.is_empty()), 0);
        assert_eq!(body.state, Some(TaskExecutionState::Queued));
    }

    /// Delegation returns the C9 durable wait keyed on the delegated TASK, and
    /// refuses any assignee that is not a peer actor.
    #[test]
    fn delegate_task_and_wait_returns_a_peer_result_wait_on_the_task_ref() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xD4);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let (receipt, wait) = facade
            .delegate_task_and_wait(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("delegate");
        let not_a_peer = facade
            .delegate_task_and_wait(&route_spec(Some(TaskAssignee::Dreamer)))
            .expect_err("only a peer actor can be delegated to");

        assert_eq!(wait.wait_id, receipt.task_ref.expect("task ref"));
        assert_eq!(wait.effect, crate::code_run::SelfEffect::TaskDelegate);
        assert_eq!(
            wait.reason,
            crate::code_run::SelfDurableWaitReason::PeerResult
        );
        assert_eq!(wait.prompt, None);
        assert_eq!(usize::from(not_a_peer.code.is_empty()), 0);
    }

    /// A consult still routes as a peer task and still enforces ONE-1699's
    /// evidence/abstention contract after general result routing landed.
    #[test]
    fn consult_regression_survives_general_result_routing() {
        let (_dir, vault) = open_vault();
        let (task_ref, peer, question) = open_consult(&vault);
        let peer_facade = vault.memory_facade(peer, EdgeActorClass::Agent);

        let answer_ref = route_turn(&vault, 0xDA).entity_ref();
        let receipt = peer_facade
            .land_consult_result(task_ref, &answer_input(answer_ref, question))
            .expect("evidence answer still lands");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");
        let terminal = body.terminal().expect("terminal record");

        assert_eq!(attempts_for(&vault, task_ref).len(), 0);
        assert_eq!(usize::from(receipt.idempotent_replay), 0);
        assert_eq!(terminal.disposition, TaskTerminalDisposition::Completed);
        assert_eq!(
            usize::from(matches!(
                terminal.summary,
                Some(ConsultResultSummary::Answer { .. })
            )),
            1
        );
    }

    /// The general result door must NOT be a second way to settle a consult:
    /// a consult's terminal record carries the ONE-1699 evidence-or-abstention
    /// summary, and the general input cannot express one. Without this the
    /// addressed peer could settle its consult with a bare result ref and no
    /// evidence at all — weakening exactly the contract ONE-1700 must preserve.
    #[test]
    fn the_general_result_door_cannot_settle_a_consult() {
        let (_dir, vault) = open_vault();
        let (task_ref, peer, question) = open_consult(&vault);
        let peer_facade = vault.memory_facade(peer, EdgeActorClass::Agent);
        let result_ref = route_turn(&vault, 0xDC).entity_ref();

        // The ADDRESSED peer — the one actor the terminal writer admits — is
        // still refused, so this is a contract door, not an actor check.
        let bypass = peer_facade
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: CONSULT_NOW + 10,
                },
            )
            .expect_err("a consult cannot settle through the general door");
        let body = task_verb_body(&vault, task_ref)
            .expect("decode body")
            .expect("typed body");

        assert_eq!(bypass.code, FACADE_CODE_INVALID_STATE);
        assert_eq!(usize::from(body.terminal().is_none()), 1);

        // The consult's own door still works and still carries the summary.
        let answer_ref = route_turn(&vault, 0xDD).entity_ref();
        let landed = peer_facade
            .land_consult_result(task_ref, &answer_input(answer_ref, question))
            .expect("the evidence door still lands");

        assert_eq!(
            usize::from(matches!(
                landed.terminal.summary,
                Some(ConsultResultSummary::Answer { .. })
            )),
            1
        );
    }

    /// The general terminal door refuses a non-consult body reader mismatch:
    /// `land_consult_result` still rejects a standard task outright.
    #[test]
    fn land_consult_result_still_refuses_a_standard_task() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let actor_ref = route_peer(&vault, 0xD5);
        let task_ref = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
            .expect("create")
            .task_ref
            .expect("task ref");
        let question = route_turn(&vault, 0xD6);
        let answer_ref = route_turn(&vault, 0xDB).entity_ref();

        let error = vault
            .memory_facade(actor_ref, EdgeActorClass::Agent)
            .land_consult_result(task_ref, &answer_input(answer_ref, question))
            .expect_err("a standard task is not a consult");

        assert_eq!(usize::from(error.message.contains("consult")), 1);
    }
}
