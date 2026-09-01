//! Dreamer runner request/outcome vocabulary and its pure impls.

use rmpv::Value;

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;

use super::claim_authoring::{
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier, DreamerClaimAuthoringBudgetTrap,
};
use super::codec::invalid_dreamer_runner;
use super::constants::{
    DEFAULT_DREAMER_CHILD_RESERVE_UNITS, DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
};

/// Coarse Dreamer attempt progress state for live ephemeral rows and durable
/// milestone fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerAttemptProgressState {
    Created,
    Started,
    Running,
    CheckpointReached,
    Parked,
    Done,
    Failed,
}

impl DreamerAttemptProgressState {
    /// Stable string stored in `job:{job_id}` ephemeral values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::Running => "running",
            Self::CheckpointReached => "checkpoint-reached",
            Self::Parked => "parked",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }

    /// Parses the pinned live-progress state string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "started" => Some(Self::Started),
            "running" => Some(Self::Running),
            "checkpoint-reached" => Some(Self::CheckpointReached),
            "parked" => Some(Self::Parked),
            "done" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Returns true once the runner must stop producing live ticks.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }
}

impl From<DreamerMilestoneKind> for DreamerAttemptProgressState {
    fn from(kind: DreamerMilestoneKind) -> Self {
        match kind {
            DreamerMilestoneKind::Created => Self::Created,
            DreamerMilestoneKind::Started => Self::Started,
            DreamerMilestoneKind::CheckpointReached => Self::CheckpointReached,
            DreamerMilestoneKind::Done => Self::Done,
            DreamerMilestoneKind::Failed => Self::Failed,
        }
    }
}

/// Durable Dreamer milestone decoded from `dreamer.job_milestone` claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerDurableMilestone {
    pub claim_id: EntityId,
    pub attempt_id: AttemptId,
    pub kind: DreamerMilestoneKind,
    pub at: u64,
    pub learned_at: u64,
}

/// Consolidation attempt-table lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerConsolidationScope {
    Micro,
    Meso,
    Macro,
}

impl DreamerConsolidationScope {
    /// Stable scope string used in Dreamer payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Meso => "meso",
            Self::Macro => "macro",
        }
    }

    /// Private attempt-table kind for this consolidation lane.
    #[must_use]
    pub const fn attempt_kind(self) -> &'static str {
        match self {
            Self::Micro => DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
            Self::Meso => DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
            Self::Macro => DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND,
        }
    }
}

/// Speaker role of a TURN entity as seen by the Dreamer extraction lane.
///
/// GATE-10: only [`DreamerTurnRole::User`] and [`DreamerTurnRole::Assistant`]
/// turns may seed first-party claims; every other role — including
/// [`DreamerTurnRole::Unknown`] — is excluded fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerTurnRole {
    User,
    Assistant,
    System,
    Tool,
    Injected,
    Unknown,
}

impl DreamerTurnRole {
    /// Stable role string for diagnostics and extraction provenance.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
            Self::Tool => "tool",
            Self::Injected => "injected",
            Self::Unknown => "unknown",
        }
    }
}

/// Classify a TURN's stored speaker string into a [`DreamerTurnRole`].
///
/// Ingest already lowercase-normalizes `speaker|role|author`; this trims and
/// lowercases again defensively. Absent, empty, or novel speaker strings map
/// to [`DreamerTurnRole::Unknown`], which is never admissible.
#[must_use]
pub fn dreamer_turn_role(speaker: Option<&str>) -> DreamerTurnRole {
    let Some(speaker) = speaker else {
        return DreamerTurnRole::Unknown;
    };
    match speaker.trim().to_ascii_lowercase().as_str() {
        "user" | "human" | "owner" => DreamerTurnRole::User,
        "assistant" | "agent" | "eiri" | "ai" | "model" => DreamerTurnRole::Assistant,
        "system" | "system_prompt" | "developer" => DreamerTurnRole::System,
        "tool" | "function" | "tool_result" | "tool_call" => DreamerTurnRole::Tool,
        "cron" | "metadata" | "injected" => DreamerTurnRole::Injected,
        _ => DreamerTurnRole::Unknown,
    }
}

/// GATE-10 admissibility: only User and Assistant turns feed extraction.
#[must_use]
pub const fn dreamer_extraction_role_admissible(role: DreamerTurnRole) -> bool {
    matches!(role, DreamerTurnRole::User | DreamerTurnRole::Assistant)
}

/// Candidate node signals for home-node MACRO election.
///
/// `attached` is the sync attachment signal. It is authority-bearing only for
/// cloud candidates; local always-on and primary candidates are elected from
/// the current caller-supplied candidate set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DreamerHomeNodeCandidate {
    pub node_id: u64,
    pub cloud: bool,
    pub attached: bool,
    pub always_on_local: bool,
    pub primary_device: bool,
}

impl DreamerHomeNodeCandidate {
    /// Cloud candidate; eligible only while attached.
    #[must_use]
    pub const fn cloud(node_id: u64, attached: bool) -> Self {
        Self {
            node_id,
            cloud: true,
            attached,
            always_on_local: false,
            primary_device: false,
        }
    }

    /// Always-on local candidate.
    #[must_use]
    pub const fn always_on_local(node_id: u64) -> Self {
        Self {
            node_id,
            cloud: false,
            attached: true,
            always_on_local: true,
            primary_device: false,
        }
    }

    /// Primary-device candidate.
    #[must_use]
    pub const fn primary_device(node_id: u64) -> Self {
        Self {
            node_id,
            cloud: false,
            attached: true,
            always_on_local: false,
            primary_device: true,
        }
    }

    pub(super) fn designation_class(self) -> Option<DreamerHomeNodeClass> {
        if self.cloud && self.attached {
            Some(DreamerHomeNodeClass::CloudAttached)
        } else if self.always_on_local {
            Some(DreamerHomeNodeClass::AlwaysOnLocal)
        } else if self.primary_device {
            Some(DreamerHomeNodeClass::PrimaryDevice)
        } else {
            None
        }
    }
}

/// Election class that made a node the MACRO home node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerHomeNodeClass {
    CloudAttached,
    AlwaysOnLocal,
    PrimaryDevice,
}

impl DreamerHomeNodeClass {
    /// Stable string stored in the private designation row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudAttached => "cloud_attached",
            Self::AlwaysOnLocal => "always_on_local",
            Self::PrimaryDevice => "primary_device",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "cloud_attached" => Some(Self::CloudAttached),
            "always_on_local" => Some(Self::AlwaysOnLocal),
            "primary_device" => Some(Self::PrimaryDevice),
            _ => None,
        }
    }

    pub(super) const fn rank(self) -> u8 {
        match self {
            Self::CloudAttached => 0,
            Self::AlwaysOnLocal => 1,
            Self::PrimaryDevice => 2,
        }
    }
}

/// The single persisted MACRO home-node designation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DreamerHomeNodeDesignation {
    pub node_id: u64,
    pub class: DreamerHomeNodeClass,
    pub elected_at: u64,
}

/// Input for enqueueing MICRO/MESO/MACRO consolidation on the advisory floor.
#[derive(Debug, Clone, PartialEq)]
pub struct EnqueueDreamerConsolidationAttempt {
    pub scope: DreamerConsolidationScope,
    pub input: Value,
    pub parent_attempt: Option<AttemptId>,
    /// Optional advisory dedupe key. This is a local cost/policy coalescer,
    /// not a correctness lock.
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Input for enqueueing a SKILL-OPT maintenance attempt (ONE-1448).
///
/// Carries no scope: the job picks its one skill from the reliability signal
/// at run time, so an enqueued attempt names the WORK, never its target.
#[derive(Debug, Clone, PartialEq)]
pub struct EnqueueDreamerSkillOptimizeAttempt {
    pub input: Value,
    pub parent_attempt: Option<AttemptId>,
    /// Optional advisory dedupe key — a local cost coalescer (one optimization
    /// pass per wake), not a correctness lock.
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Input for home-aware consolidation admission.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmitDreamerConsolidationAttempt {
    pub scope: DreamerConsolidationScope,
    pub local_node_id: u64,
    pub claim_authoring_tier: DreamerClaimAuthoringBatchTier,
    pub claim_authoring: DreamerClaimAuthoringAdmission,
    pub admission: AdmitDreamerAttempt,
}

/// Home-aware consolidation admission result.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DreamerConsolidationAdmissionOutcome {
    NoHomeNode,
    NotHomeNode(DreamerHomeNodeDesignation),
    ClaimAuthoringBudgetTrap(DreamerClaimAuthoringBudgetTrap),
    Admission(DreamerAdmissionOutcome),
}

/// Typed Dreamer attempt payload stored in the generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerAttemptPayload {
    pub attempt_type: String,
    pub input: Value,
    pub parent_attempt: Option<AttemptId>,
}

/// Input for enqueueing a Dreamer attempt into the private runner queue.
#[derive(Debug, Clone, PartialEq)]
pub struct EnqueueDreamerAttempt {
    pub attempt_type: String,
    pub input: Value,
    pub parent_attempt: Option<AttemptId>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Decoded Dreamer attempt plus its backing generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerAttemptStatus {
    pub attempt: AttemptRecord,
    pub payload: DreamerAttemptPayload,
}

/// Typed enqueue outcome for Dreamer attempts.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum EnqueueDreamerAttemptOutcome {
    Enqueued(DreamerAttemptStatus),
    Existing(DreamerAttemptStatus),
}

/// Input for completing a leased Dreamer attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDreamerAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed complete outcome for a Dreamer attempt.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CompleteDreamerAttemptOutcome {
    Completed(DreamerAttemptStatus),
    AlreadyCompleted(DreamerAttemptStatus),
}

/// Input for failing a leased Dreamer attempt terminally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailDreamerAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed fail outcome for a Dreamer attempt.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FailDreamerAttemptOutcome {
    Failed(DreamerAttemptStatus),
    AlreadyFailed(DreamerAttemptStatus),
}

/// Pinned milestone vocabulary for durable Dreamer progress claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerMilestoneKind {
    Created,
    Started,
    CheckpointReached,
    Done,
    Failed,
}

impl DreamerMilestoneKind {
    /// Stable string stored in `dreamer.job_milestone` claim values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::CheckpointReached => "checkpoint-reached",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }

    /// Parses the pinned milestone string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "started" => Some(Self::Started),
            "checkpoint-reached" => Some(Self::CheckpointReached),
            "done" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Durable milestone claim material to write with an admission transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerMilestoneClaim {
    pub claim_id: EntityId,
    pub subject: EntityId,
    pub kind: DreamerMilestoneKind,
    pub envelope: WriteEnvelope,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// Private wake-budget counter row used only by the local Dreamer runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerBudgetRecord {
    pub budget_id: String,
    pub total_units: u64,
    pub remaining_units: u64,
    pub reserved_units: u64,
    pub updated_at: u64,
}

/// Wake-budget fan-out policy knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerWakeBudgetConfig {
    pub child_reserve_units: u64,
}

impl Default for DreamerWakeBudgetConfig {
    fn default() -> Self {
        Self {
            child_reserve_units: DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
        }
    }
}

impl DreamerWakeBudgetConfig {
    /// Validates budget policy knobs before they are used for admission.
    pub fn validate(self) -> Result<()> {
        if self.child_reserve_units == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer child reserve units must be > 0",
            ));
        }
        Ok(())
    }
}

/// Private per-child reservation row used to reconcile completion or abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerBudgetReservation {
    pub budget_id: String,
    pub attempt_id: AttemptId,
    pub reserved_units: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Explicit reserve input for callers that already have a child attempt id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveDreamerBudget {
    pub budget_id: String,
    pub child_attempt: AttemptId,
    /// Initial local budget total when no private row exists yet. Existing
    /// rows keep their stored total.
    pub budget_total_units: u64,
    pub reserve_units: u64,
    pub now: u64,
}

/// Reserve result for a private wake-budget counter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerBudgetReserveOutcome {
    BudgetExhausted(DreamerBudgetRecord),
    AlreadyReserved(DreamerBudgetReservation),
    Reserved(Box<DreamerReservedBudget>),
}

/// A newly reserved child budget and the counter row after reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerReservedBudget {
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
}

/// Completion-time budget settlement for a previously reserved child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleDreamerBudget {
    pub budget_id: String,
    pub child_attempt: AttemptId,
    pub actual_units: u64,
    pub now: u64,
}

/// Abort-time refund for a previously reserved child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortDreamerBudgetReservation {
    pub budget_id: String,
    pub child_attempt: AttemptId,
    pub now: u64,
}

/// Settlement result for a child budget reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerBudgetSettlementOutcome {
    NoReservation,
    Settled(DreamerBudgetSettlement),
}

/// Counter reconciliation after completion or abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerBudgetSettlement {
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
    pub actual_units: u64,
    pub refunded_units: u64,
    pub over_reserved_units: u64,
}

/// Input for the atomic Dreamer admission step.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmitDreamerAttempt {
    pub lease_owner: String,
    pub now: u64,
    pub budget_id: String,
    /// Initial local budget total when no private row exists yet. Existing
    /// rows keep their stored total.
    pub budget_total_units: u64,
    /// Units to move from remaining to reserved if admission succeeds.
    pub reserve_units: u64,
    /// Optional durable started milestone claim to co-commit with admission.
    pub started_milestone: Option<DreamerMilestoneClaim>,
}

/// Atomic admission result.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DreamerAdmissionOutcome {
    Empty,
    BudgetExhausted(DreamerBudgetRecord),
    Admitted(Box<DreamerAdmittedAttempt>),
}

/// A leased Dreamer attempt plus the private budget row after admission.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerAdmittedAttempt {
    pub status: DreamerAttemptStatus,
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
}

/// Private run-tree row keyed by attempt id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerRunTreeRecord {
    pub attempt_id: AttemptId,
    pub parent_attempt: Option<AttemptId>,
    pub created_at: u64,
}

/// Input for parking a Dreamer attempt in local runner state.
///
/// `park_owner` is the parker's ownership token: only the owner recorded on
/// the row may overwrite it or resume the attempt (fail-closed on mismatch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkDreamerAttempt {
    pub attempt_id: AttemptId,
    pub reason: String,
    pub park_owner: String,
    pub now: u64,
}

/// Private parked-attempt row keyed by attempt id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerParkedAttemptRecord {
    pub attempt_id: AttemptId,
    pub reason: String,
    pub park_owner: String,
    pub parked_at: u64,
}
