//! Private Dreamer runner store plus atomic admission.
//!
//! Durable Dreamer milestones are ordinary vault claims. Live runner state
//! (queue leases, local run-tree rows, parked rows, and budget counters) stays
//! in private LMDB rows and is not sync materialized as vault entities.

#[cfg(feature = "sync")]
use std::collections::HashMap;
use std::collections::HashSet;
#[cfg(feature = "sync")]
use std::fmt::Write as _;
use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
#[cfg(feature = "sync")]
use crate::attempt_queue::AttemptState;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome,
    FailAttempt, FailOutcome, InterveneAttempt,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
#[cfg(feature = "sync")]
use crate::error::SyncEngineContext;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};
use crate::store::Store;
#[cfg(feature = "sync")]
use crate::sync::{EphemeralStore, LoroValue, TransportError, encode_ephemeral};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};

/// Generic [`AttemptQueue`] kind used by Dreamer runner attempts.
pub const DREAMER_RUNNER_ATTEMPT_KIND: &str = "dreamer";
/// Current pinned Dreamer attempt payload schema version.
pub const DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer attempt payloads.
pub const DREAMER_ATTEMPT_PAYLOAD_KEYS: [&str; 4] =
    ["schema_version", "job_type", "input", "parent_job"];
/// Claim predicate used for durable Dreamer attempt milestones.
pub const DREAMER_MILESTONE_PREDICATE: &str = "dreamer.job_milestone";
/// Current pinned Dreamer milestone claim value schema version.
pub const DREAMER_MILESTONE_VALUE_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer milestone claim values.
pub const DREAMER_MILESTONE_VALUE_KEYS: [&str; 4] = ["schema_version", "job_id", "milestone", "at"];
const DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX: &[u8] = b"dreamer.milestone_index.v1.c:";
const DREAMER_MILESTONE_INDEX_CLAIM_PREFIX: &[u8] = b"dreamer.milestone_index.v1.i:";
const DREAMER_MILESTONE_INDEX_BACKFILLED_KEY: &[u8] = b"dreamer.milestone_index.v1.backfilled";
const DREAMER_MILESTONE_INDEX_CANDIDATE_KEY_LEN: usize =
    DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX.len() + 16 + 8 + 8 + 16;
/// Flat ephemeral key prefix for live Dreamer attempt progress.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX: &str = "job:";
/// Current schema version for live Dreamer attempt progress ephemeral values.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION: i64 = 1;
/// Default per-attempt live progress throttle: at most one update per second.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS: u64 = 1_000;
/// Default in-process terminal-stop retention, matching the sync lane TTL.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS: u64 = 30_000;
/// Default fan-out reservation for one Dreamer child, in token-like units.
pub const DEFAULT_DREAMER_CHILD_RESERVE_UNITS: u64 = 8_000;
/// Default OF-366 tournament candidate fan-out.
pub const DEFAULT_DREAMER_TOURNAMENT_FANOUT_M: u16 = 2;
/// Default OF-366 tournament refinement depth.
pub const DEFAULT_DREAMER_TOURNAMENT_DEPTH_K: u16 = 2;
/// MICRO consolidation queue kind. Private per-device attempt rows only.
pub const DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND: &str = "dreamer.consolidation.micro";
/// MESO consolidation queue kind. Private per-device attempt rows only.
pub const DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND: &str = "dreamer.consolidation.meso";
/// MACRO consolidation queue kind. Admission is restricted to the elected home node.
pub const DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND: &str = "dreamer.consolidation.macro";
/// Current pinned home-node designation schema version.
pub const DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for the private home-node designation.
pub const DREAMER_HOME_NODE_DESIGNATION_KEYS: [&str; 4] =
    ["schema_version", "node_id", "class", "elected_at"];

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_ATTEMPT_TYPE: &str = "job_type";
const KEY_INPUT: &str = "input";
const KEY_PARENT_ATTEMPT: &str = "parent_job";
const KEY_ATTEMPT_ID: &str = "job_id";
const KEY_MILESTONE: &str = "milestone";
const KEY_AT: &str = "at";
const KEY_BUDGET_ID: &str = "budget_id";
const KEY_TOTAL_UNITS: &str = "total_units";
const KEY_REMAINING_UNITS: &str = "remaining_units";
const KEY_RESERVED_UNITS: &str = "reserved_units";
const KEY_UPDATED_AT: &str = "updated_at";
const KEY_CREATED_AT: &str = "created_at";
const KEY_NODE_ID: &str = "node_id";
const KEY_CLASS: &str = "class";
const KEY_ELECTED_AT: &str = "elected_at";
const KEY_REASON: &str = "reason";
const KEY_PARK_OWNER: &str = "park_owner";
const KEY_PARKED_AT: &str = "parked_at";
#[cfg(feature = "sync")]
const KEY_STATE: &str = "state";
#[cfg(feature = "sync")]
const KEY_MESSAGE: &str = "message";
#[cfg(feature = "sync")]
const KEY_COMPLETED_UNITS: &str = "completed_units";
#[cfg(feature = "sync")]
const KEY_UPDATED_AT_MS: &str = "updated_at_ms";
#[cfg(feature = "sync")]
const DREAMER_ATTEMPT_PROGRESS_VALUE_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_STATE,
    KEY_MESSAGE,
    KEY_COMPLETED_UNITS,
    KEY_TOTAL_UNITS,
    KEY_UPDATED_AT_MS,
];
const DREAMER_BUDGET_SCHEMA_VERSION: u64 = 1;
const DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION: u64 = 1;
const DREAMER_RUN_TREE_SCHEMA_VERSION: u64 = 1;
// v2 adds the mandatory `park_owner` token; v1 rows (no owner) fail closed.
const DREAMER_PARKED_SCHEMA_VERSION: u64 = 2;
const DREAMER_BUDGET_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_TOTAL_UNITS,
    KEY_REMAINING_UNITS,
    KEY_RESERVED_UNITS,
    KEY_UPDATED_AT,
];
const DREAMER_BUDGET_RESERVATION_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_ATTEMPT_ID,
    KEY_RESERVED_UNITS,
    KEY_CREATED_AT,
    KEY_UPDATED_AT,
];
const DREAMER_RUN_TREE_KEYS: [&str; 4] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_PARENT_ATTEMPT,
    KEY_CREATED_AT,
];
const DREAMER_PARKED_KEYS: [&str; 5] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_REASON,
    KEY_PARK_OWNER,
    KEY_PARKED_AT,
];
const DREAMER_PRIVATE_BUDGET_PREFIX: &[u8] = b"dreamer:budget:";
const DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX: &[u8] = b"dreamer:budget_reservation:";
const DREAMER_PRIVATE_RUN_TREE_PREFIX: &[u8] = b"dreamer:run_tree:";
const DREAMER_PRIVATE_PARKED_PREFIX: &[u8] = b"dreamer:parked:";
const DREAMER_PRIVATE_HOME_NODE_KEY: &[u8] = b"dreamer:home_node_macro:v1";
const MAX_DREAMER_ATTEMPT_TYPE_LEN: usize = 128;
const MAX_DREAMER_BUDGET_ID_LEN: usize = 128;
const MAX_DREAMER_PARK_REASON_LEN: usize = 512;
const MAX_DREAMER_PARK_OWNER_LEN: usize = 128;
#[cfg(feature = "sync")]
const MAX_DREAMER_PROGRESS_MESSAGE_LEN: usize = 512;
const MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT: u32 = 3;
const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR: &str = "dreamer-budget-trap";
const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE: &str =
    "BudgetTrap: tournament claim authoring suspended for budget approval";

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

/// Live Dreamer progress update to publish into the ephemeral keyspace.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerAttemptProgressUpdate {
    pub attempt_id: AttemptId,
    pub state: DreamerAttemptProgressState,
    pub message: Option<String>,
    pub completed_units: u64,
    pub total_units: Option<u64>,
    pub updated_at_ms: u64,
}

/// Source used for a progress snapshot returned to a consumer.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerAttemptProgressSource {
    Ephemeral,
    DurableMilestone,
}

/// Consumer-facing progress snapshot: live row if present, durable milestone
/// fallback otherwise.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerAttemptProgressSnapshot {
    pub attempt_id: AttemptId,
    pub state: DreamerAttemptProgressState,
    pub source: DreamerAttemptProgressSource,
    pub message: Option<String>,
    pub completed_units: u64,
    pub total_units: Option<u64>,
    pub updated_at_ms: u64,
}

/// In-process producer for Dreamer live progress on the Loro ephemeral lane.
///
/// The producer keeps only bounded throttle/terminal-stop bookkeeping. The
/// sync-visible state remains exactly one mutable `job:{job_id}` row in the
/// provided [`EphemeralStore`].
#[cfg(feature = "sync")]
#[derive(Debug, Clone)]
pub struct DreamerAttemptProgressProducer {
    throttle_ms: u64,
    terminal_retention_ms: u64,
    last_emitted_at_ms: HashMap<AttemptId, u64>,
    terminal_at_ms: HashMap<AttemptId, u64>,
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

/// Claim-authoring strategy on the OF-267/Dreamer path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DreamerClaimAuthoringStrategy {
    #[default]
    SinglePass,
    Tournament,
}

impl DreamerClaimAuthoringStrategy {
    /// Stable strategy string for configs and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SinglePass => "single_pass",
            Self::Tournament => "tournament",
        }
    }
}

/// Batch-tier schedule admitted for tournament claim authoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerClaimAuthoringSchedule {
    Batch,
    Nightly,
}

impl DreamerClaimAuthoringSchedule {
    /// Stable schedule string for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Nightly => "nightly",
        }
    }
}

/// Claim-time token proving tournament authoring is running on a batch tier.
///
/// The token has no interactive/hot-path constructor. Tournament admission
/// requires this type at the consolidation claim site, so callers cannot run
/// the tournament gate without selecting a batch/nightly tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DreamerClaimAuthoringBatchTier {
    schedule: DreamerClaimAuthoringSchedule,
}

impl DreamerClaimAuthoringBatchTier {
    /// Batch consolidation tier.
    #[must_use]
    pub const fn batch() -> Self {
        Self {
            schedule: DreamerClaimAuthoringSchedule::Batch,
        }
    }

    /// Nightly consolidation tier.
    #[must_use]
    pub const fn nightly() -> Self {
        Self {
            schedule: DreamerClaimAuthoringSchedule::Nightly,
        }
    }

    /// Stable schedule carried by this batch-tier token.
    #[must_use]
    pub const fn schedule(self) -> DreamerClaimAuthoringSchedule {
        self.schedule
    }

    /// Stable tier string for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.schedule.as_str()
    }
}

/// OF-197 evidence state as seen by the OF-366 admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerClaimEvidenceState {
    Uncontested,
    Contested,
}

/// Incumbent single-pass claim metadata used to decide tournament admission.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentClaim {
    pub predicate: String,
    pub sample_count: u32,
    pub incumbent_confidence: f32,
    pub evidence_state: DreamerClaimEvidenceState,
}

/// OF-290 budget axes for one tournament admission lease line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerTournamentBudgetAxes {
    pub fanout_m: u16,
    pub depth_k: u16,
    pub reserve_units_per_step: u64,
}

impl Default for DreamerTournamentBudgetAxes {
    fn default() -> Self {
        Self {
            fanout_m: DEFAULT_DREAMER_TOURNAMENT_FANOUT_M,
            depth_k: DEFAULT_DREAMER_TOURNAMENT_DEPTH_K,
            reserve_units_per_step: DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
        }
    }
}

impl DreamerTournamentBudgetAxes {
    /// Units to reserve on the single OF-290 lease line for M×k work.
    pub fn reserve_units(self) -> Result<u64> {
        if self.fanout_m == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer tournament fanout_m must be > 0",
            ));
        }
        if self.depth_k == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer tournament depth_k must be > 0",
            ));
        }
        if self.reserve_units_per_step == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer tournament reserve_units_per_step must be > 0",
            ));
        }

        u64::from(self.fanout_m)
            .checked_mul(u64::from(self.depth_k))
            .and_then(|units| units.checked_mul(self.reserve_units_per_step))
            .ok_or(Error::ArithmeticOverflow(
                "dreamer tournament reserve units",
            ))
    }
}

/// Tournament admission policy for a candidate claim.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentAdmission {
    pub claim: DreamerTournamentClaim,
    pub uncertainty_tau: f32,
    pub budget_axes: DreamerTournamentBudgetAxes,
}

/// Strategy knob carried by the Dreamer claim-authoring admission path.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub enum DreamerClaimAuthoringAdmission {
    #[default]
    SinglePass,
    Tournament(DreamerTournamentAdmission),
}

impl DreamerClaimAuthoringAdmission {
    /// Current OF-267 behavior: no tournament escalation.
    #[must_use]
    pub const fn single_pass() -> Self {
        Self::SinglePass
    }

    /// Strategy selected by this admission value.
    #[must_use]
    pub const fn strategy(&self) -> DreamerClaimAuthoringStrategy {
        match self {
            Self::SinglePass => DreamerClaimAuthoringStrategy::SinglePass,
            Self::Tournament(_) => DreamerClaimAuthoringStrategy::Tournament,
        }
    }

    /// Evaluates the OF-366 gate without mutating queue or budget state.
    ///
    /// The `batch_tier` argument is the claim-time OF-193 guard: there is no
    /// zero-argument tournament gate and no hot-path tier value.
    pub fn gate_decision(
        &self,
        batch_tier: DreamerClaimAuthoringBatchTier,
    ) -> Result<DreamerClaimAuthoringGateDecision> {
        match self {
            Self::SinglePass => Ok(DreamerClaimAuthoringGateDecision::SinglePass(
                DreamerClaimAuthoringSinglePassReason::Strategy,
            )),
            Self::Tournament(admission) => admission.gate_decision(batch_tier),
        }
    }
}

impl DreamerTournamentAdmission {
    /// Evaluates the OF-366 tournament gate without mutating queue or budget state.
    pub fn gate_decision(
        &self,
        batch_tier: DreamerClaimAuthoringBatchTier,
    ) -> Result<DreamerClaimAuthoringGateDecision> {
        validate_unit_interval(
            self.uncertainty_tau,
            "dreamer tournament uncertainty_tau must be finite in [0, 1]",
        )?;
        validate_unit_interval(
            self.claim.incumbent_confidence,
            "dreamer tournament incumbent_confidence must be finite in [0, 1]",
        )?;

        if !is_pattern_claim_predicate(&self.claim.predicate)
            || self.claim.sample_count < MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT
        {
            return Ok(DreamerClaimAuthoringGateDecision::SinglePass(
                DreamerClaimAuthoringSinglePassReason::Class,
            ));
        }

        if self.claim.incumbent_confidence >= self.uncertainty_tau
            && self.claim.evidence_state != DreamerClaimEvidenceState::Contested
        {
            return Ok(DreamerClaimAuthoringGateDecision::SinglePass(
                DreamerClaimAuthoringSinglePassReason::Uncertainty,
            ));
        }

        Ok(DreamerClaimAuthoringGateDecision::Tournament(
            DreamerTournamentAdmissionGrant {
                schedule: batch_tier.schedule(),
                fanout_m: self.budget_axes.fanout_m,
                depth_k: self.budget_axes.depth_k,
                reserve_units: self.budget_axes.reserve_units()?,
            },
        ))
    }
}

/// Reason a requested authoring path stays on the single-pass incumbent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerClaimAuthoringSinglePassReason {
    Strategy,
    Class,
    Uncertainty,
}

/// Successful tournament admission axes after class/uncertainty/schedule gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerTournamentAdmissionGrant {
    pub schedule: DreamerClaimAuthoringSchedule,
    pub fanout_m: u16,
    pub depth_k: u16,
    pub reserve_units: u64,
}

/// Isolated OF-366 admission-gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerClaimAuthoringGateDecision {
    SinglePass(DreamerClaimAuthoringSinglePassReason),
    Tournament(DreamerTournamentAdmissionGrant),
}

/// BudgetTrap result for tournament admission depletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerClaimAuthoringBudgetTrap {
    pub attempt_id: AttemptId,
    pub budget_id: String,
    pub budget: DreamerBudgetRecord,
    pub required_units: u64,
    pub fanout_m: u16,
    pub depth_k: u16,
    pub intervention_effect: AttemptInterventionEffect,
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

    fn designation_class(self) -> Option<DreamerHomeNodeClass> {
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

    fn parse(value: &str) -> Option<Self> {
        match value {
            "cloud_attached" => Some(Self::CloudAttached),
            "always_on_local" => Some(Self::AlwaysOnLocal),
            "primary_device" => Some(Self::PrimaryDevice),
            _ => None,
        }
    }

    const fn rank(self) -> u8 {
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

struct DreamerKindAdmissionResult {
    outcome: DreamerAdmissionOutcome,
    budget_exhausted_candidate: Option<AttemptId>,
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

/// Runner transition outcome plus an optional encoded ephemeral frame.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerProgressed<T> {
    pub outcome: T,
    pub frame: Option<Vec<u8>>,
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

#[cfg(feature = "sync")]
impl DreamerAttemptProgressUpdate {
    fn validate(&self) -> std::result::Result<(), TransportError> {
        if let Some(total) = self.total_units
            && self.completed_units > total
        {
            return Err(TransportError::InvalidPayload(
                "dreamer progress completed_units exceeds total_units",
            ));
        }
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_DREAMER_PROGRESS_MESSAGE_LEN)
        {
            return Err(TransportError::InvalidPayload(
                "dreamer progress message exceeds 512 bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "sync")]
impl DreamerAttemptProgressSnapshot {
    fn from_live_update(update: &DreamerAttemptProgressUpdate) -> Self {
        Self {
            attempt_id: update.attempt_id,
            state: update.state,
            source: DreamerAttemptProgressSource::Ephemeral,
            message: update.message.clone(),
            completed_units: update.completed_units,
            total_units: update.total_units,
            updated_at_ms: update.updated_at_ms,
        }
    }

    fn from_milestone(milestone: DreamerDurableMilestone) -> Self {
        Self {
            attempt_id: milestone.attempt_id,
            state: milestone.kind.into(),
            source: DreamerAttemptProgressSource::DurableMilestone,
            message: None,
            completed_units: 0,
            total_units: None,
            updated_at_ms: milestone.at.saturating_mul(1_000),
        }
    }
}

#[cfg(feature = "sync")]
impl Default for DreamerAttemptProgressProducer {
    fn default() -> Self {
        Self::with_limits(
            DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS,
            DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS,
        )
        .expect("default dreamer progress limits are valid")
    }
}

#[cfg(feature = "sync")]
impl DreamerAttemptProgressProducer {
    /// Creates a producer with the contract-pinned 1Hz throttle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a producer with explicit limits. `terminal_retention_ms` should
    /// match the [`EphemeralStore`] timeout so stopped attempts cannot resume
    /// ticking before their last live row ages out.
    pub fn with_limits(throttle_ms: u64, terminal_retention_ms: u64) -> Result<Self> {
        if throttle_ms == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer progress throttle_ms must be > 0",
            ));
        }
        if terminal_retention_ms == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer progress terminal_retention_ms must be > 0",
            ));
        }
        Ok(Self {
            throttle_ms,
            terminal_retention_ms,
            last_emitted_at_ms: HashMap::new(),
            terminal_at_ms: HashMap::new(),
        })
    }

    /// Publishes one live progress update if it passes the per-attempt throttle.
    ///
    /// Terminal `Done`/`Failed` updates overwrite the mutable live row with a
    /// terminal state, then stop any further live production until TTL ageout.
    pub fn publish(
        &mut self,
        store: &EphemeralStore,
        update: DreamerAttemptProgressUpdate,
    ) -> std::result::Result<Option<Vec<u8>>, TransportError> {
        update.validate()?;
        self.retain_terminal_stops(update.updated_at_ms);

        if update.state.is_terminal() {
            let key = dreamer_attempt_progress_key(update.attempt_id);
            let value = encode_attempt_progress_value(&update)?;
            store.set(&key, value);
            self.mark_terminal(update.attempt_id, update.updated_at_ms);
            return encode_ephemeral(&store.encode(&key))
                .into_result()
                .map(Some);
        }
        if self.terminal_at_ms.contains_key(&update.attempt_id) {
            return Ok(None);
        }
        if let Some(last) = self.last_emitted_at_ms.get(&update.attempt_id)
            && update.updated_at_ms.saturating_sub(*last) < self.throttle_ms
        {
            return Ok(None);
        }

        let key = dreamer_attempt_progress_key(update.attempt_id);
        let value = encode_attempt_progress_value(&update)?;
        store.set(&key, value);
        self.last_emitted_at_ms
            .insert(update.attempt_id, update.updated_at_ms);
        encode_ephemeral(&store.encode(&key))
            .into_result()
            .map(Some)
    }

    /// Marks an attempt terminal without producing a live progress frame.
    pub fn mark_terminal(&mut self, attempt_id: AttemptId, now_ms: u64) {
        self.last_emitted_at_ms.remove(&attempt_id);
        self.terminal_at_ms.insert(attempt_id, now_ms);
    }

    /// Runs the Rust-side `EphemeralStore` TTL pass and prunes old terminal
    /// stop markers from this producer.
    pub fn remove_outdated(&mut self, store: &EphemeralStore, now_ms: u64) {
        store.remove_outdated();
        self.retain_terminal_stops(now_ms);
    }

    fn retain_terminal_stops(&mut self, now_ms: u64) {
        let retention = self.terminal_retention_ms;
        self.terminal_at_ms
            .retain(|_, terminal_at| now_ms.saturating_sub(*terminal_at) < retention);
    }
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

/// Private Dreamer runner store over an already-open vault.
pub struct DreamerRunnerStore<'a> {
    vault: &'a Vault,
    attempts: AttemptQueue<'a>,
}

impl<'a> DreamerRunnerStore<'a> {
    /// Opens a Dreamer runner store over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            attempts: AttemptQueue::new(vault),
        }
    }

    /// Builds a local candidate from the vault's stable sync device identity.
    pub fn local_home_node_candidate(
        &self,
        attached: bool,
        always_on_local: bool,
        primary_device: bool,
    ) -> Result<DreamerHomeNodeCandidate> {
        let node_id = crate::identity::load_or_mint_client_id(self.vault)?;
        Ok(DreamerHomeNodeCandidate {
            node_id,
            cloud: false,
            attached,
            always_on_local,
            primary_device,
        })
    }

    /// Elects and persists the single MACRO home-node designation.
    ///
    /// Election is deterministic over the supplied current candidate set:
    /// attached cloud > always-on local > primary device, with node id as a
    /// stable tie-breaker inside a tier.
    pub fn elect_home_node(
        &self,
        candidates: &[DreamerHomeNodeCandidate],
        now: u64,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        let designation = elect_home_node_designation(candidates, now)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        if let Some(designation) = designation {
            let encoded = encode_home_node_designation(&designation)?;
            self.vault
                .store
                .vault_meta
                .put(&mut wtxn, DREAMER_PRIVATE_HOME_NODE_KEY, &encoded)?;
        } else {
            self.vault
                .store
                .vault_meta
                .delete(&mut wtxn, DREAMER_PRIVATE_HOME_NODE_KEY)?;
        }
        wtxn.commit()?;
        Ok(designation)
    }

    /// Reads the persisted MACRO home-node designation, if one exists.
    pub fn home_node_designation(&self) -> Result<Option<DreamerHomeNodeDesignation>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let Some(raw) = self
            .vault
            .store
            .vault_meta
            .get(&rtxn, DREAMER_PRIVATE_HOME_NODE_KEY)?
        else {
            return Ok(None);
        };
        decode_home_node_designation(&raw).map(Some)
    }

    /// Enqueues a Dreamer attempt and records its private run-tree parent row in
    /// the same LMDB write transaction.
    pub fn enqueue(&self, input: EnqueueDreamerAttempt) -> Result<EnqueueDreamerAttemptOutcome> {
        validate_attempt_type(&input.attempt_type)?;
        let payload = DreamerAttemptPayload {
            attempt_type: input.attempt_type,
            input: input.input,
            parent_attempt: input.parent_attempt,
        };
        let encoded_payload = encode_dreamer_attempt_payload(&payload)?;

        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.attempts.enqueue_in_txn(
            &mut wtxn,
            EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: encoded_payload,
                dedupe_key: input.dedupe_key,
                run_id: input.run_id,
                now: input.now,
            },
        )?;

        let (was_enqueued, status) = match outcome {
            EnqueueOutcome::Enqueued(record) => {
                put_run_tree_record_in_txn(
                    self.vault,
                    &mut wtxn,
                    &DreamerRunTreeRecord {
                        attempt_id: record.id,
                        parent_attempt: payload.parent_attempt,
                        created_at: record.created_at,
                    },
                )?;
                (true, decode_dreamer_attempt_status(record)?)
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, &mut wtxn, &record)?;
                (false, decode_dreamer_attempt_status(record)?)
            }
        };
        wtxn.commit()?;

        if was_enqueued {
            Ok(EnqueueDreamerAttemptOutcome::Enqueued(status))
        } else {
            Ok(EnqueueDreamerAttemptOutcome::Existing(status))
        }
    }

    /// Enqueues a local consolidation attempt on the advisory attempt-table floor.
    ///
    /// MICRO and MESO remain per-device because these queue rows are private
    /// runner state. MACRO uses the same advisory dedupe mechanics, but
    /// admission is restricted by [`Self::admit_next_consolidation`].
    pub fn enqueue_consolidation(
        &self,
        input: EnqueueDreamerConsolidationAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_consolidation_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Enqueues a consolidation attempt in a caller-owned write transaction.
    pub(crate) fn enqueue_consolidation_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueDreamerConsolidationAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let payload = DreamerAttemptPayload {
            attempt_type: input.scope.as_str().to_owned(),
            input: input.input,
            parent_attempt: input.parent_attempt,
        };
        let encoded_payload = encode_dreamer_attempt_payload(&payload)?;

        let outcome = self.attempts.enqueue_in_txn(
            wtxn,
            EnqueueAttempt {
                kind: input.scope.attempt_kind().to_owned(),
                payload: encoded_payload,
                dedupe_key: input.dedupe_key,
                run_id: input.run_id,
                now: input.now,
            },
        )?;

        let (was_enqueued, status) = match outcome {
            EnqueueOutcome::Enqueued(record) => {
                put_run_tree_record_in_txn(
                    self.vault,
                    wtxn,
                    &DreamerRunTreeRecord {
                        attempt_id: record.id,
                        parent_attempt: payload.parent_attempt,
                        created_at: record.created_at,
                    },
                )?;
                (true, decode_dreamer_attempt_status(record)?)
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, wtxn, &record)?;
                (false, decode_dreamer_attempt_status(record)?)
            }
        };

        if was_enqueued {
            Ok(EnqueueDreamerAttemptOutcome::Enqueued(status))
        } else {
            Ok(EnqueueDreamerAttemptOutcome::Existing(status))
        }
    }

    /// Publishes a live progress update for an existing Dreamer attempt.
    ///
    /// This is the runner seam used by execution loops for in-flight ticks;
    /// the producer enforces per-attempt throttling and terminal-stop behavior.
    #[cfg(feature = "sync")]
    pub fn publish_progress(
        &self,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
        update: DreamerAttemptProgressUpdate,
    ) -> Result<Option<Vec<u8>>> {
        let status = self
            .status(update.attempt_id)?
            .ok_or(invalid_dreamer_runner(
                "dreamer progress attempt must exist before publish",
            ))?;
        match (status.attempt.state, update.state) {
            (AttemptState::Completed, DreamerAttemptProgressState::Done)
            | (AttemptState::Failed, DreamerAttemptProgressState::Failed)
            | (AttemptState::Queued | AttemptState::Leased, _) => {}
            (
                AttemptState::Paused
                | AttemptState::Completed
                | AttemptState::Failed
                | AttemptState::Cancelled,
                _,
            ) => {
                return Ok(None);
            }
        }
        producer
            .publish(ephemeral, update)
            .map_err(dreamer_progress_error)
    }

    /// Atomically admits the next queued Dreamer attempt.
    ///
    /// A successful admission leases one queue row, mutates the private budget
    /// counter, and optionally writes a durable started milestone claim before
    /// committing. Budget denial commits only queue scan repairs, leaving the
    /// attempt queued and the budget row unchanged.
    pub fn admit_next(&self, input: AdmitDreamerAttempt) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(DREAMER_RUNNER_ATTEMPT_KIND, input)
    }

    /// Home-aware consolidation admission.
    ///
    /// MICRO/MESO admission remains per-device. MACRO admission requires the
    /// caller's local node id to match the persisted home-node designation.
    pub fn admit_next_consolidation(
        &self,
        mut input: AdmitDreamerConsolidationAttempt,
    ) -> Result<DreamerConsolidationAdmissionOutcome> {
        let claim_authoring_decision = input
            .claim_authoring
            .gate_decision(input.claim_authoring_tier)?;
        let tournament_grant = match claim_authoring_decision {
            DreamerClaimAuthoringGateDecision::SinglePass(_) => None,
            DreamerClaimAuthoringGateDecision::Tournament(grant) => {
                input.admission.reserve_units = grant.reserve_units;
                Some(grant)
            }
        };
        validate_admission_input(&input.admission)?;
        if input.local_node_id == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer local node_id must be nonzero",
            ));
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        if input.scope == DreamerConsolidationScope::Macro {
            let local_node_id =
                crate::identity::load_or_mint_client_id_in_txn(self.vault, &mut wtxn)?;
            if input.local_node_id != local_node_id {
                return Err(invalid_dreamer_runner(
                    "dreamer local node_id does not match vault identity",
                ));
            }

            let Some(designation) = home_node_designation_in_txn(self.vault, &wtxn)? else {
                wtxn.commit()?;
                return Ok(DreamerConsolidationAdmissionOutcome::NoHomeNode);
            };
            if designation.node_id != local_node_id {
                wtxn.commit()?;
                return Ok(DreamerConsolidationAdmissionOutcome::NotHomeNode(
                    designation,
                ));
            }
        }

        let budget_trap_budget_id = input.admission.budget_id.clone();
        let budget_trap_now = input.admission.now;
        let result =
            self.admit_next_kind_in_txn(&mut wtxn, input.scope.attempt_kind(), input.admission)?;
        match (tournament_grant, result.outcome) {
            (Some(grant), DreamerAdmissionOutcome::BudgetExhausted(budget)) => {
                let Some(attempt_id) = result.budget_exhausted_candidate else {
                    wtxn.commit()?;
                    return Ok(DreamerConsolidationAdmissionOutcome::Admission(
                        DreamerAdmissionOutcome::BudgetExhausted(budget),
                    ));
                };
                let intervention = self.attempts.intervene_in_txn(
                    &mut wtxn,
                    InterveneAttempt {
                        id: attempt_id,
                        kind: AttemptInterventionKind::Pause,
                        actor: DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR.to_owned(),
                        note: Some(DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE.to_owned()),
                        now: budget_trap_now,
                    },
                )?;
                wtxn.commit()?;
                Ok(
                    DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(
                        DreamerClaimAuthoringBudgetTrap {
                            attempt_id,
                            budget_id: budget_trap_budget_id,
                            budget,
                            required_units: grant.reserve_units,
                            fanout_m: grant.fanout_m,
                            depth_k: grant.depth_k,
                            intervention_effect: intervention.effect,
                        },
                    ),
                )
            }
            (_, outcome) => {
                wtxn.commit()?;
                Ok(DreamerConsolidationAdmissionOutcome::Admission(outcome))
            }
        }
    }

    fn admit_next_kind(
        &self,
        queue_kind: &str,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        validate_admission_input(&input)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let result = self.admit_next_kind_in_txn(&mut wtxn, queue_kind, input)?;
        wtxn.commit()?;
        Ok(result.outcome)
    }

    fn admit_next_kind_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        queue_kind: &str,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerKindAdmissionResult> {
        let Some(candidate_attempt_id) = self
            .attempts
            .ready_kind_candidate_in_txn(wtxn, queue_kind, input.now)?
        else {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::Empty,
                budget_exhausted_candidate: None,
            });
        };

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        let existing_reservation = read_budget_reservation_in_txn(
            self.vault,
            wtxn,
            &input.budget_id,
            candidate_attempt_id,
        )?;
        if let Some(reservation) = existing_reservation.as_ref() {
            if reservation.reserved_units > budget.reserved_units {
                return Err(invalid_dreamer_runner(
                    "dreamer budget reservation exceeds reserved units",
                ));
            }
            if input.reserve_units > reservation.reserved_units {
                let additional_units = input
                    .reserve_units
                    .checked_sub(reservation.reserved_units)
                    .ok_or(Error::ArithmeticOverflow(
                        "dreamer budget reservation top-up",
                    ))?;
                if additional_units > budget.remaining_units {
                    return Ok(DreamerKindAdmissionResult {
                        outcome: DreamerAdmissionOutcome::BudgetExhausted(budget),
                        budget_exhausted_candidate: Some(candidate_attempt_id),
                    });
                }
            }
        } else if input.reserve_units > budget.remaining_units {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::BudgetExhausted(budget),
                budget_exhausted_candidate: Some(candidate_attempt_id),
            });
        }

        let claim = self.attempts.claim_kind_in_txn(
            wtxn,
            queue_kind,
            ClaimAttempt {
                lease_owner: input.lease_owner,
                now: input.now,
            },
        )?;
        let ClaimOutcome::Claimed(attempt) = claim else {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::Empty,
                budget_exhausted_candidate: None,
            });
        };
        if attempt.id != candidate_attempt_id {
            return Err(invalid_dreamer_runner(
                "dreamer admission claimed unexpected ready attempt",
            ));
        }

        let reservation = if let Some(reservation) = existing_reservation {
            if input.reserve_units > reservation.reserved_units {
                top_up_budget_reservation_in_txn(
                    self.vault,
                    wtxn,
                    &mut budget,
                    reservation,
                    input.reserve_units,
                    input.now,
                )?
            } else {
                reservation
            }
        } else {
            let reservation = DreamerBudgetReservation {
                budget_id: input.budget_id,
                attempt_id: attempt.id,
                reserved_units: input.reserve_units,
                created_at: input.now,
                updated_at: input.now,
            };
            reserve_budget_for_child_in_txn(self.vault, wtxn, &mut budget, &reservation)?;
            reservation
        };

        if let Some(milestone) = input.started_milestone {
            apply_milestone_claim_in_txn(self.vault, wtxn, &attempt, milestone)?;
        }

        let status = decode_dreamer_attempt_status(attempt)?;

        Ok(DreamerKindAdmissionResult {
            outcome: DreamerAdmissionOutcome::Admitted(Box::new(DreamerAdmittedAttempt {
                status,
                budget,
                reservation,
            })),
            budget_exhausted_candidate: None,
        })
    }

    /// Admits the next Dreamer attempt and emits its initial live progress row.
    #[cfg(feature = "sync")]
    pub fn admit_next_with_progress(
        &self,
        input: AdmitDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<DreamerAdmissionOutcome>> {
        let now_ms = input.now.saturating_mul(1_000);
        let outcome = self.admit_next(input)?;
        let frame = if let DreamerAdmissionOutcome::Admitted(admitted) = &outcome {
            let reservation = &admitted.reservation;
            self.publish_progress(
                producer,
                ephemeral,
                DreamerAttemptProgressUpdate {
                    attempt_id: admitted.status.attempt.id,
                    state: DreamerAttemptProgressState::Started,
                    message: None,
                    completed_units: 0,
                    total_units: Some(reservation.reserved_units),
                    updated_at_ms: now_ms,
                },
            )?
        } else {
            None
        };
        Ok(DreamerProgressed { outcome, frame })
    }

    /// Reserves wake-budget units for a known child attempt.
    ///
    /// `admit_next` is the normal spawn path because it co-commits queue
    /// leasing and reservation. This method exists for runner call sites that
    /// already have a child id and still need the same private counter rules.
    pub fn reserve_budget(
        &self,
        input: ReserveDreamerBudget,
    ) -> Result<DreamerBudgetReserveOutcome> {
        validate_budget_id(&input.budget_id)?;
        if input.reserve_units == 0 {
            return Err(invalid_dreamer_runner("dreamer reserve_units must be > 0"));
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        if let Some(reservation) = read_budget_reservation_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.child_attempt,
        )? {
            return Ok(DreamerBudgetReserveOutcome::AlreadyReserved(reservation));
        }

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        if input.reserve_units > budget.remaining_units {
            wtxn.commit()?;
            return Ok(DreamerBudgetReserveOutcome::BudgetExhausted(budget));
        }

        let reservation = DreamerBudgetReservation {
            budget_id: input.budget_id,
            attempt_id: input.child_attempt,
            reserved_units: input.reserve_units,
            created_at: input.now,
            updated_at: input.now,
        };
        reserve_budget_for_child_in_txn(self.vault, &mut wtxn, &mut budget, &reservation)?;
        wtxn.commit()?;

        Ok(DreamerBudgetReserveOutcome::Reserved(Box::new(
            DreamerReservedBudget {
                budget,
                reservation,
            },
        )))
    }

    /// Settles a child reservation with actual usage and refunds any unspent
    /// reservation.
    pub fn settle_budget(
        &self,
        input: SettleDreamerBudget,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        validate_budget_id(&input.budget_id)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let reservation_key = budget_reservation_key(&input.budget_id, input.child_attempt)?;
        let Some(reservation) = read_budget_reservation_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.child_attempt,
        )?
        else {
            return Ok(DreamerBudgetSettlementOutcome::NoReservation);
        };

        let budget_key = budget_key(&input.budget_id)?;
        let Some(raw_budget) = self.vault.store.vault_meta.get(&wtxn, &budget_key)? else {
            return Err(invalid_dreamer_runner(
                "dreamer budget reservation missing counter",
            ));
        };
        let mut budget = decode_budget_record(&raw_budget)?;
        if budget.budget_id != input.budget_id {
            return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
        }

        let settlement =
            settle_budget_for_child(&mut budget, reservation, input.actual_units, input.now)?;
        put_budget_record_in_txn(self.vault, &mut wtxn, &settlement.budget)?;
        self.vault
            .store
            .vault_meta
            .delete(&mut wtxn, &reservation_key)?;
        wtxn.commit()?;

        Ok(DreamerBudgetSettlementOutcome::Settled(settlement))
    }

    /// Refunds a child reservation when the child aborts before spending any
    /// budget units.
    pub fn abort_budget_reservation(
        &self,
        input: AbortDreamerBudgetReservation,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.settle_budget(SettleDreamerBudget {
            budget_id: input.budget_id,
            child_attempt: input.child_attempt,
            actual_units: 0,
            now: input.now,
        })
    }

    /// Marks a leased Dreamer attempt complete through the generic queue.
    pub fn complete(&self, input: CompleteDreamerAttempt) -> Result<CompleteDreamerAttemptOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        match self.attempts.complete(CompleteAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            now: input.now,
        })? {
            CompleteOutcome::Completed(record) => Ok(CompleteDreamerAttemptOutcome::Completed(
                decode_dreamer_attempt_status(record)?,
            )),
            CompleteOutcome::AlreadyCompleted(record) => {
                Ok(CompleteDreamerAttemptOutcome::AlreadyCompleted(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
        }
    }

    /// Marks a leased Dreamer attempt complete and stops live progress production.
    #[cfg(feature = "sync")]
    pub fn complete_with_progress(
        &self,
        input: CompleteDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<CompleteDreamerAttemptOutcome>> {
        let outcome = self.complete(input)?;
        let status = complete_outcome_status(&outcome);
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerAttemptProgressUpdate {
                attempt_id: status.attempt.id,
                state: DreamerAttemptProgressState::Done,
                message: None,
                completed_units: 0,
                total_units: None,
                updated_at_ms: status.attempt.updated_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed { outcome, frame })
    }

    /// Marks a leased Dreamer attempt terminally failed through the generic queue.
    pub fn fail(&self, input: FailDreamerAttempt) -> Result<FailDreamerAttemptOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        match self.attempts.fail(FailAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            reason: input.reason,
            now: input.now,
        })? {
            FailOutcome::Failed(record) => Ok(FailDreamerAttemptOutcome::Failed(
                decode_dreamer_attempt_status(record)?,
            )),
            FailOutcome::AlreadyFailed(record) => Ok(FailDreamerAttemptOutcome::AlreadyFailed(
                decode_dreamer_attempt_status(record)?,
            )),
        }
    }

    /// Marks a leased Dreamer attempt failed and stops live progress production.
    #[cfg(feature = "sync")]
    pub fn fail_with_progress(
        &self,
        input: FailDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<FailDreamerAttemptOutcome>> {
        let outcome = self.fail(input)?;
        let status = fail_outcome_status(&outcome);
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerAttemptProgressUpdate {
                attempt_id: status.attempt.id,
                state: DreamerAttemptProgressState::Failed,
                message: bounded_progress_message(status.attempt.last_error.as_deref()),
                completed_units: 0,
                total_units: None,
                updated_at_ms: status.attempt.updated_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed { outcome, frame })
    }

    fn ensure_terminal_transition_target(&self, id: AttemptId) -> Result<()> {
        let record = self.attempts.get(id)?.ok_or(invalid_dreamer_runner(
            "dreamer terminal transition attempt must exist",
        ))?;
        decode_dreamer_attempt_status(record).map(|_| ())
    }

    /// Reads one Dreamer attempt by queue id.
    pub fn status(&self, id: AttemptId) -> Result<Option<DreamerAttemptStatus>> {
        self.attempts
            .get(id)?
            .map(decode_dreamer_attempt_status)
            .transpose()
    }

    /// Reads a private Dreamer budget row.
    pub fn budget(&self, budget_id: &str) -> Result<Option<DreamerBudgetRecord>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_key(budget_id)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_record(&raw).map(Some)
    }

    /// Reads the remaining units in a private Dreamer budget row.
    pub fn remaining_budget(&self, budget_id: &str) -> Result<Option<u64>> {
        self.budget(budget_id)
            .map(|budget| budget.map(|record| record.remaining_units))
    }

    /// Reads a private child reservation row.
    pub fn budget_reservation(
        &self,
        budget_id: &str,
        child_attempt: AttemptId,
    ) -> Result<Option<DreamerBudgetReservation>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_reservation_key(budget_id, child_attempt)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_reservation(&raw).map(Some)
    }

    /// Reads a private Dreamer run-tree row.
    pub fn run_tree(&self, attempt_id: AttemptId) -> Result<Option<DreamerRunTreeRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = run_tree_key(attempt_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_run_tree_record(&raw).map(Some)
    }

    /// Parks a Dreamer attempt in private runner state without changing the
    /// generic queue row.
    ///
    /// A row already parked by a DIFFERENT owner is never overwritten
    /// (fail-closed error); the same owner may re-park to refresh the row.
    pub fn park_attempt(&self, input: ParkDreamerAttempt) -> Result<DreamerParkedAttemptRecord> {
        validate_park_reason(&input.reason)?;
        validate_park_owner(&input.park_owner)?;
        if self.status(input.attempt_id)?.is_none() {
            return Err(invalid_dreamer_runner("dreamer parked attempt must exist"));
        }

        let record = DreamerParkedAttemptRecord {
            attempt_id: input.attempt_id,
            reason: input.reason,
            park_owner: input.park_owner,
            parked_at: input.now,
        };
        let encoded = encode_parked_record(&record)?;
        let key = parked_key(record.attempt_id);
        let mut wtxn = self.vault.store.env.write_txn()?;
        let existing = self
            .vault
            .store
            .vault_meta
            .get(&wtxn, &key)?
            .map(|raw| decode_parked_record(&raw))
            .transpose()?;
        if let Some(existing) = existing
            && existing.park_owner != record.park_owner
        {
            return Err(invalid_dreamer_runner(
                "dreamer parked row is owned by a different parker",
            ));
        }
        self.vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Parks a Dreamer attempt and emits a live parked progress row.
    #[cfg(feature = "sync")]
    pub fn park_attempt_with_progress(
        &self,
        input: ParkDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<DreamerParkedAttemptRecord>> {
        let record = self.park_attempt(input)?;
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerAttemptProgressUpdate {
                attempt_id: record.attempt_id,
                state: DreamerAttemptProgressState::Parked,
                message: Some(record.reason.clone()),
                completed_units: 0,
                total_units: None,
                updated_at_ms: record.parked_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed {
            outcome: record,
            frame,
        })
    }

    /// Clears a parked-attempt row so the attempt becomes admissible again through
    /// the normal admission path (ONE-1288).
    ///
    /// Returns the attempt status when a parked row was cleared. An attempt with NO
    /// parked row is an idempotent no-op: `Ok(None)`, nothing mutated
    /// (pinned). A row parked by a DIFFERENT owner than `park_owner` is a
    /// fail-closed error, nothing deleted. `now` is accepted for symmetry
    /// with the other transition inputs; the queue row is not touched —
    /// re-admission re-leases it.
    pub fn resume_parked(
        &self,
        attempt_id: AttemptId,
        park_owner: &str,
        now: u64,
    ) -> Result<Option<DreamerAttemptStatus>> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let resumed = self.resume_parked_in_txn(&mut wtxn, attempt_id, park_owner, now)?;
        wtxn.commit()?;
        Ok(resumed)
    }

    /// Transaction-composable body of [`Self::resume_parked`], so the trap
    /// consume path (ONE-1343) can commit the `consumed` transition and this
    /// un-park in ONE wtxn.
    pub(crate) fn resume_parked_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
        park_owner: &str,
        _now: u64,
    ) -> Result<Option<DreamerAttemptStatus>> {
        let key = parked_key(attempt_id);
        let Some(raw) = self.vault.store.vault_meta.get(wtxn, &key)? else {
            return Ok(None);
        };
        let record = decode_parked_record(&raw)?;
        if record.park_owner != park_owner {
            return Err(invalid_dreamer_runner(
                "dreamer parked row is owned by a different parker",
            ));
        }
        let status = self
            .status(attempt_id)?
            .ok_or(invalid_dreamer_runner("dreamer resumed attempt must exist"))?;
        self.vault.store.vault_meta.delete(wtxn, &key)?;
        Ok(Some(status))
    }

    /// Reads a private parked-attempt row.
    pub fn parked_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = parked_key(attempt_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_parked_record(&raw).map(Some)
    }

    /// Returns the latest active/approved durable milestone for `attempt_id`.
    ///
    /// This is the coarse fallback surface for consumers that cannot reach the
    /// executing device's live ephemeral row.
    pub fn latest_durable_milestone(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerDurableMilestone>> {
        let rtxn = self.vault.store.env.read_txn()?;
        if self
            .vault
            .store
            .vault_meta
            .get(&rtxn, DREAMER_MILESTONE_INDEX_BACKFILLED_KEY)?
            .is_some()
        {
            return latest_indexed_dreamer_milestone(&self.vault.store, &rtxn, attempt_id);
        }
        drop(rtxn);

        let mut wtxn = self.vault.store.env.write_txn()?;
        if self
            .vault
            .store
            .vault_meta
            .get(&wtxn, DREAMER_MILESTONE_INDEX_BACKFILLED_KEY)?
            .is_some()
        {
            drop(wtxn);
            let rtxn = self.vault.store.env.read_txn()?;
            return latest_indexed_dreamer_milestone(&self.vault.store, &rtxn, attempt_id);
        }
        let latest = backfill_dreamer_milestone_index(&self.vault.store, &mut wtxn, attempt_id)?;
        wtxn.commit()?;
        Ok(latest)
    }

    /// Returns the live ephemeral progress row when present, otherwise falls
    /// back to the latest durable milestone claim.
    #[cfg(feature = "sync")]
    pub fn progress_snapshot(
        &self,
        ephemeral: &EphemeralStore,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerAttemptProgressSnapshot>> {
        if let Some(value) = ephemeral.get(&dreamer_attempt_progress_key(attempt_id))
            && let Ok(update) = decode_attempt_progress_value(&value, attempt_id)
        {
            return Ok(Some(DreamerAttemptProgressSnapshot::from_live_update(
                &update,
            )));
        }

        self.latest_durable_milestone(attempt_id)
            .map(|milestone| milestone.map(DreamerAttemptProgressSnapshot::from_milestone))
    }
}

/// Encodes a Dreamer attempt payload in canonical MessagePack field order.
pub fn encode_dreamer_attempt_payload(payload: &DreamerAttemptPayload) -> Result<Vec<u8>> {
    validate_attempt_type(&payload.attempt_type)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_TYPE),
            Value::from(payload.attempt_type.as_str()),
        ),
        (Value::from(KEY_INPUT), payload.input.clone()),
        (
            Value::from(KEY_PARENT_ATTEMPT),
            encode_optional_attempt_id(payload.parent_attempt),
        ),
    ]);
    encode_value(&value, "dreamer attempt payload MessagePack encode failed")
}

/// Decodes and validates a Dreamer attempt payload.
pub fn decode_dreamer_attempt_payload(bytes: &[u8]) -> Result<DreamerAttemptPayload> {
    let value = decode_value(bytes)?;
    decode_dreamer_attempt_payload_value(&value)
}

fn decode_dreamer_attempt_status(record: AttemptRecord) -> Result<DreamerAttemptStatus> {
    if !is_dreamer_queue_kind(&record.kind) {
        return Err(invalid_dreamer_runner(
            "attempt is not a Dreamer runner attempt",
        ));
    }
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    Ok(DreamerAttemptStatus {
        attempt: record,
        payload,
    })
}

#[cfg(feature = "sync")]
fn dreamer_progress_error(error: TransportError) -> Error {
    Error::sync_engine(SyncEngineContext::DreamerProgressTransport, error)
}

#[cfg(feature = "sync")]
fn complete_outcome_status(outcome: &CompleteDreamerAttemptOutcome) -> &DreamerAttemptStatus {
    match outcome {
        CompleteDreamerAttemptOutcome::Completed(status)
        | CompleteDreamerAttemptOutcome::AlreadyCompleted(status) => status,
    }
}

#[cfg(feature = "sync")]
fn fail_outcome_status(outcome: &FailDreamerAttemptOutcome) -> &DreamerAttemptStatus {
    match outcome {
        FailDreamerAttemptOutcome::Failed(status)
        | FailDreamerAttemptOutcome::AlreadyFailed(status) => status,
    }
}

#[cfg(feature = "sync")]
fn bounded_progress_message(message: Option<&str>) -> Option<String> {
    let message = message?;
    if message.len() <= MAX_DREAMER_PROGRESS_MESSAGE_LEN {
        return Some(message.to_owned());
    }

    let mut end = 0;
    for (index, ch) in message.char_indices() {
        let next = index + ch.len_utf8();
        if next > MAX_DREAMER_PROGRESS_MESSAGE_LEN {
            break;
        }
        end = next;
    }
    Some(message[..end].to_owned())
}

fn is_dreamer_queue_kind(kind: &str) -> bool {
    kind == DREAMER_RUNNER_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND
}

fn home_node_designation_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
) -> Result<Option<DreamerHomeNodeDesignation>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(txn, DREAMER_PRIVATE_HOME_NODE_KEY)?
    else {
        return Ok(None);
    };
    decode_home_node_designation(&raw).map(Some)
}

fn elect_home_node_designation(
    candidates: &[DreamerHomeNodeCandidate],
    now: u64,
) -> Result<Option<DreamerHomeNodeDesignation>> {
    let mut seen = HashSet::with_capacity(candidates.len());
    let mut best: Option<(u8, u64, DreamerHomeNodeDesignation)> = None;

    for candidate in candidates {
        if candidate.node_id == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer home node_id must be nonzero",
            ));
        }
        if !seen.insert(candidate.node_id) {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer home node candidate",
            ));
        }

        let Some(class) = candidate.designation_class() else {
            continue;
        };
        let rank = class.rank();
        let designation = DreamerHomeNodeDesignation {
            node_id: candidate.node_id,
            class,
            elected_at: now,
        };
        match best.as_ref() {
            Some((best_rank, best_node_id, _))
                if rank > *best_rank
                    || (rank == *best_rank && candidate.node_id > *best_node_id) => {}
            _ => best = Some((rank, candidate.node_id, designation)),
        }
    }

    Ok(best.map(|(_, _, designation)| designation))
}

fn encode_home_node_designation(record: &DreamerHomeNodeDesignation) -> Result<Vec<u8>> {
    validate_home_node_designation(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_NODE_ID), Value::from(record.node_id)),
        (Value::from(KEY_CLASS), Value::from(record.class.as_str())),
        (Value::from(KEY_ELECTED_AT), Value::from(record.elected_at)),
    ]);
    encode_value(&value, "dreamer home-node MessagePack encode failed")
}

fn decode_home_node_designation(bytes: &[u8]) -> Result<DreamerHomeNodeDesignation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer home-node row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut node_id = None;
    let mut class = None;
    let mut elected_at = None;
    let mut seen = [false; DREAMER_HOME_NODE_DESIGNATION_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer home-node keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_HOME_NODE_DESIGNATION_KEYS).ok_or(
            invalid_dreamer_runner("dreamer home-node key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer home-node key"));
        }
        seen[index] = true;

        match DREAMER_HOME_NODE_DESIGNATION_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer home-node schema_version must be an integer",
                )?);
            }
            KEY_NODE_ID => {
                node_id = Some(expect_u64(
                    value,
                    "dreamer home-node node_id must be an integer",
                )?);
            }
            KEY_CLASS => {
                let parsed = expect_string(value, "dreamer home-node class must be a string")?;
                class = Some(
                    DreamerHomeNodeClass::parse(&parsed)
                        .ok_or(invalid_dreamer_runner("invalid dreamer home-node class"))?,
                );
            }
            KEY_ELECTED_AT => {
                elected_at = Some(expect_u64(
                    value,
                    "dreamer home-node elected_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_HOME_NODE_DESIGNATION_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer home-node schema_version",
    ))?;
    if schema_version != DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer home-node schema_version",
        ));
    }
    let record = DreamerHomeNodeDesignation {
        node_id: node_id.ok_or(invalid_dreamer_runner("missing dreamer home-node node_id"))?,
        class: class.ok_or(invalid_dreamer_runner("missing dreamer home-node class"))?,
        elected_at: elected_at.ok_or(invalid_dreamer_runner(
            "missing dreamer home-node elected_at",
        ))?,
    };
    validate_home_node_designation(&record)?;
    Ok(record)
}

fn decode_dreamer_attempt_payload_value(value: &Value) -> Result<DreamerAttemptPayload> {
    let entries = expect_map(value, "dreamer attempt payload must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_type = None;
    let mut input = None;
    let mut parent_attempt = None;
    let mut seen = [false; DREAMER_ATTEMPT_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer attempt payload keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_ATTEMPT_PAYLOAD_KEYS).ok_or(
            invalid_dreamer_runner("dreamer attempt payload key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer attempt payload key",
            ));
        }
        seen[index] = true;

        match DREAMER_ATTEMPT_PAYLOAD_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer attempt payload schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_TYPE => {
                let parsed = expect_string(value, "dreamer job_type must be a string")?;
                validate_attempt_type(&parsed)?;
                attempt_type = Some(parsed);
            }
            KEY_INPUT => input = Some(value.clone()),
            KEY_PARENT_ATTEMPT => parent_attempt = Some(decode_optional_attempt_id(value)?),
            _ => unreachable!("index resolved from DREAMER_ATTEMPT_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer attempt payload schema_version",
    ))?;
    if schema_version != DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer attempt payload schema_version",
        ));
    }

    Ok(DreamerAttemptPayload {
        attempt_type: attempt_type.ok_or(invalid_dreamer_runner("missing dreamer job_type"))?,
        input: input.ok_or(invalid_dreamer_runner("missing dreamer attempt input"))?,
        parent_attempt: parent_attempt
            .ok_or(invalid_dreamer_runner("missing dreamer parent_job"))?,
    })
}

fn ensure_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    let key = run_tree_key(record.id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
        return Ok(());
    }
    let status = decode_dreamer_attempt_status(record.clone())?;
    put_run_tree_record_in_txn(
        vault,
        wtxn,
        &DreamerRunTreeRecord {
            attempt_id: status.attempt.id,
            parent_attempt: status.payload.parent_attempt,
            created_at: status.attempt.created_at,
        },
    )
}

fn put_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerRunTreeRecord,
) -> Result<()> {
    let encoded = encode_run_tree_record(record)?;
    let key = run_tree_key(record.attempt_id);
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn read_or_initialize_budget_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    budget_id: &str,
    budget_total_units: u64,
    now: u64,
) -> Result<DreamerBudgetRecord> {
    let key = budget_key(budget_id)?;
    let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? else {
        return Ok(DreamerBudgetRecord {
            budget_id: budget_id.to_owned(),
            total_units: budget_total_units,
            remaining_units: budget_total_units,
            reserved_units: 0,
            updated_at: now,
        });
    };
    let record = decode_budget_record(&raw)?;
    if record.budget_id != budget_id {
        return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
    }
    Ok(record)
}

fn put_budget_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerBudgetRecord,
) -> Result<()> {
    let encoded = encode_budget_record(record)?;
    let key = budget_key(&record.budget_id)?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn read_budget_reservation_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    budget_id: &str,
    child_attempt: AttemptId,
) -> Result<Option<DreamerBudgetReservation>> {
    let reservation_key = budget_reservation_key(budget_id, child_attempt)?;
    let Some(raw) = vault.store.vault_meta.get(txn, &reservation_key)? else {
        return Ok(None);
    };
    let reservation = decode_budget_reservation(&raw)?;
    if reservation.budget_id != budget_id || reservation.attempt_id != child_attempt {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation key/body mismatch",
        ));
    }
    Ok(Some(reservation))
}

fn reserve_budget_for_child_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    budget: &mut DreamerBudgetRecord,
    reservation: &DreamerBudgetReservation,
) -> Result<()> {
    validate_budget_reservation(reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.attempt_id)?;
    if vault
        .store
        .vault_meta
        .get(&*wtxn, &reservation_key)?
        .is_some()
    {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation already exists",
        ));
    }
    if reservation.reserved_units > budget.remaining_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds remaining units",
        ));
    }

    budget.remaining_units -= reservation.reserved_units;
    budget.reserved_units = budget
        .reserved_units
        .checked_add(reservation.reserved_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget reserved units"))?;
    budget.updated_at = reservation.updated_at;
    put_budget_record_in_txn(vault, wtxn, budget)?;

    let encoded = encode_budget_reservation(reservation)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &reservation_key, &encoded)?;
    Ok(())
}

fn top_up_budget_reservation_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    budget: &mut DreamerBudgetRecord,
    mut reservation: DreamerBudgetReservation,
    required_units: u64,
    now: u64,
) -> Result<DreamerBudgetReservation> {
    validate_budget_reservation(&reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    if required_units <= reservation.reserved_units {
        return Ok(reservation);
    }
    let additional_units = required_units
        .checked_sub(reservation.reserved_units)
        .ok_or(Error::ArithmeticOverflow(
            "dreamer budget reservation top-up",
        ))?;
    if additional_units > budget.remaining_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation top-up exceeds remaining units",
        ));
    }

    budget.remaining_units -= additional_units;
    budget.reserved_units = budget
        .reserved_units
        .checked_add(additional_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget reserved units"))?;
    budget.updated_at = now;

    reservation.reserved_units = required_units;
    reservation.updated_at = now;
    validate_budget_reservation(&reservation)?;
    validate_budget_record(budget)?;

    put_budget_record_in_txn(vault, wtxn, budget)?;
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.attempt_id)?;
    let encoded = encode_budget_reservation(&reservation)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &reservation_key, &encoded)?;
    Ok(reservation)
}

fn settle_budget_for_child(
    budget: &mut DreamerBudgetRecord,
    reservation: DreamerBudgetReservation,
    actual_units: u64,
    now: u64,
) -> Result<DreamerBudgetSettlement> {
    validate_budget_reservation(&reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    if reservation.reserved_units > budget.reserved_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds reserved units",
        ));
    }

    let refunded_units = reservation.reserved_units.saturating_sub(actual_units);
    let over_reserved_units = actual_units.saturating_sub(reservation.reserved_units);
    let remaining_after_refund = budget
        .remaining_units
        .checked_add(refunded_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget refund units"))?;
    if over_reserved_units > remaining_after_refund {
        return Err(invalid_dreamer_runner(
            "dreamer budget settlement exceeds remaining units",
        ));
    }

    budget.reserved_units -= reservation.reserved_units;
    budget.remaining_units = remaining_after_refund - over_reserved_units;
    budget.updated_at = now;
    validate_budget_record(budget)?;

    Ok(DreamerBudgetSettlement {
        budget: budget.clone(),
        reservation,
        actual_units,
        refunded_units,
        over_reserved_units,
    })
}

fn apply_milestone_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: &AttemptRecord,
    milestone: DreamerMilestoneClaim,
) -> Result<()> {
    let milestone = stamp_agent_dispatch_milestone(attempt, milestone)?;
    let value = dreamer_milestone_value(attempt.id, milestone.kind, milestone.occurred.start);
    let candidate = ClaimCandidate::new(
        DREAMER_MILESTONE_PREDICATE,
        ClaimSubject::Entity(milestone.subject),
        value,
        1.0,
    );
    vault
        .batch_in()
        .claim_candidate(
            &milestone.claim_id,
            candidate,
            &milestone.envelope,
            milestone.occurred,
            milestone.learned_at,
        )
        .apply(wtxn)
}

/// Milestones co-committed for an agent-dispatch attempt carry AUTHORITATIVE
/// attribution: the subject is stamped to the attempt id and the envelope
/// provenance's agent key is stamped from the dispatched payload's own
/// `agent_id`, never trusted from the caller — an admission milestone can
/// therefore not attribute another agent. Non-agent attempts pass through
/// unchanged.
fn stamp_agent_dispatch_milestone(
    attempt: &AttemptRecord,
    milestone: DreamerMilestoneClaim,
) -> Result<DreamerMilestoneClaim> {
    if attempt.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(milestone);
    }
    let Ok(payload) = decode_dreamer_attempt_payload(&attempt.payload) else {
        // A payload that fails the dreamer envelope decode errors moments
        // later in status decoding; the milestone stamp is not the door.
        return Ok(milestone);
    };
    if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(milestone);
    }
    let Some(agent_id) = crate::agent_dispatch::agent_dispatch_payload_agent_id(&payload) else {
        return Err(invalid_dreamer_runner(
            "agent dispatch payload is unattributable; refusing milestone claim",
        ));
    };
    let subject = EntityId::from_bytes(*attempt.id.as_bytes()).map_err(|_| {
        invalid_dreamer_runner("agent dispatch attempt id is not usable as a milestone subject")
    })?;
    let mut entries = match milestone.envelope.provenance().value() {
        Value::Map(entries) => entries
            .iter()
            .filter(|(key, _)| {
                key.as_str() != Some(crate::agent_dispatch::AGENT_DISPATCH_MILESTONE_AGENT_KEY)
            })
            .cloned()
            .collect::<Vec<_>>(),
        other => vec![(Value::from("caller"), other.clone())],
    };
    entries.push((
        Value::from(crate::agent_dispatch::AGENT_DISPATCH_MILESTONE_AGENT_KEY),
        Value::from(agent_id),
    ));
    let envelope = WriteEnvelope::new(
        milestone.envelope.actor(),
        milestone.envelope.source(),
        WriteProvenance::new(Value::Map(entries))?,
        milestone.envelope.approval(),
    );
    Ok(DreamerMilestoneClaim {
        subject,
        envelope,
        ..milestone
    })
}

pub(crate) fn index_dreamer_milestone_claim_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<()> {
    deindex_dreamer_milestone_claim(store, wtxn, claim_id)?;

    let Some(milestone) = dreamer_milestone_from_claim_body(claim_id, body, learned_at) else {
        return Ok(());
    };

    // A milestone becomes durable-index visible only when it is BOUND to the
    // attempt it names — for EVERY milestone kind. A forged claim stays an
    // ordinary claim but never enters `latest_durable_milestone` (tolerant
    // skip, never a write error: replicated replay must not fail a peer's
    // write on local queue state).
    if !dreamer_milestone_attribution_is_bound(store, wtxn, milestone.attempt_id, body) {
        return Ok(());
    }

    let candidate_key = dreamer_milestone_candidate_key(&milestone);
    store.vault_meta.put(wtxn, &candidate_key, b"")?;
    store
        .vault_meta
        .put(wtxn, &dreamer_milestone_claim_key(claim_id), &candidate_key)?;
    Ok(())
}

/// F4 binding check for the durable milestone index, applied to EVERY
/// milestone kind on every door that indexes (the `apply_put` hook and the
/// one-time backfill). Resolution ladder:
///
/// * no local queue row → NOT bound (fail closed). Queue rows are private
///   per-device runner state and are never sync-materialized, so a milestone
///   claim replicated from a peer has nothing local to bind against —
///   indexing it would let a peer's (or a forger's) claim decide this
///   device's resume point. `latest_durable_milestone` is only meaningful on
///   the device holding the row, so nothing legitimate is lost;
/// * unreadable/undecodable local row or payload → NOT bound (fail closed);
/// * non-dreamer or non-agent-dispatch attempt → bound (today's semantics for
///   milestones that carry no agent attribution);
/// * agent-dispatch attempt → bound only when ALL THREE bindings hold:
///   the claim's subject is the attempt id, its write envelope is a SYSTEM
///   (Dreamer bookkeeping) envelope, and its stamped attribution equals the
///   dispatched payload's `agent_id`.
fn dreamer_milestone_attribution_is_bound(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    body: &ClaimBody,
) -> bool {
    let attempt_hex = bytes_to_hex_lower(attempt_id.as_bytes());
    let raw = match store.attempt_records.get(txn, attempt_id.as_bytes()) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            tracing::warn!(
                attempt_id = %attempt_hex,
                "milestone names an attempt with no local queue row; \
                 refusing durable index entry",
            );
            return false;
        }
        Err(error) => {
            tracing::warn!(
                attempt_id = %attempt_hex,
                %error,
                "milestone attempt row read failed; refusing durable index entry",
            );
            return false;
        }
    };
    // Attempt rows are one version byte + an rmp_serde body (attempt_queue.rs); a
    // record this module cannot decode cannot be bound — fail closed.
    let Some((_version, record_body)) = raw.split_first() else {
        return false;
    };
    let Ok(record) = rmp_serde::from_slice::<AttemptRecord>(record_body) else {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "milestone attempt row failed to decode; refusing durable index entry",
        );
        return false;
    };
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return true;
    }
    let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "milestone attempt payload failed to decode; refusing durable index entry",
        );
        return false;
    };
    if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return true;
    }
    let Some(expected) = crate::agent_dispatch::agent_dispatch_payload_agent_id(&payload) else {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "agent dispatch payload is unattributable; refusing durable index entry",
        );
        return false;
    };

    // (1) Subject binding: the milestone must be about THIS attempt.
    let Ok(expected_subject) = EntityId::from_bytes(*attempt_id.as_bytes()) else {
        return false;
    };
    if body.subject != ClaimSubject::Entity(expected_subject) {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "milestone subject is not the dispatched attempt id; \
             refusing durable index entry",
        );
        return false;
    }

    // (2) Envelope-actor binding: agent-dispatch milestones are runner
    // bookkeeping and ride the SYSTEM/Dreamer envelope (B1 (a)). This is
    // RESOLVED from the writer's stored entity, not trusted from the class
    // byte on the record: the milestone's stamped `actor_entity_ref` must
    // name a currently-stored MACHINE (the only System-capable kind), so an
    // agent-envelope milestone, a class-byte lie, or a writer whose entity
    // was deleted after the write all fail closed. (The residual — a genuine
    // MACHINE actor the manifest grants Auto — is the manifest boundary; see
    // the report. oneiron has no per-actor write authentication, so WHICH
    // system actor is Auto-granted is deployment policy.)
    match milestone_claim_envelope_writer_kind(store, txn, body) {
        Ok(Some(kind)) if kind == ENTITY_TYPE_MACHINE => {}
        other => {
            tracing::warn!(
                attempt_id = %attempt_hex,
                ?other,
                "milestone writer does not resolve to a stored MACHINE (system) \
                 actor; refusing durable index entry",
            );
            return false;
        }
    }

    // (3) Attribution binding: the stamped agent is the dispatched agent.
    match milestone_claim_agent_attribution(body) {
        Some(claimed) if claimed == expected => true,
        claimed => {
            tracing::warn!(
                attempt_id = %attempt_hex,
                expected,
                ?claimed,
                "milestone attribution does not match the dispatched agent; \
                 refusing durable index entry",
            );
            false
        }
    }
}

/// Reads the write-envelope evidence map a claim carries (`evid`).
fn milestone_claim_envelope_evidence(body: &ClaimBody) -> Option<&Vec<(Value, Value)>> {
    match body.evidence.as_ref() {
        Some(Value::Map(evidence)) => Some(evidence),
        _ => None,
    }
}

/// Resolves the STORED entity type of a milestone claim's write actor from
/// its stamped `actor_entity_ref` evidence — the resolved writer, not the
/// self-asserted class byte. `Ok(None)` when the evidence carries no actor
/// ref, the ref is malformed, or no entity is stored there (a deleted or
/// never-existent writer); the stored type byte otherwise. Read errors
/// propagate so the caller fails closed.
fn milestone_claim_envelope_writer_kind(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<Option<u8>> {
    let Some(actor_ref) = milestone_claim_envelope_actor_ref(body) else {
        return Ok(None);
    };
    let Some(raw) = store.entities.get(txn, actor_ref.as_bytes())? else {
        return Ok(None);
    };
    Ok(EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
}

/// Reads the actor entity id stamped into a claim's write-envelope evidence.
fn milestone_claim_envelope_actor_ref(body: &ClaimBody) -> Option<EntityId> {
    milestone_claim_envelope_evidence(body)?
        .iter()
        .find_map(|(key, value)| {
            if key.as_str() != Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
                return None;
            }
            let Value::Binary(bytes) = value else {
                return None;
            };
            let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
            EntityId::from_bytes(arr).ok()
        })
}

/// Reads the agent attribution a milestone claim carries in its stamped
/// write-envelope evidence (`evid.provenance.agent`).
fn milestone_claim_agent_attribution(body: &ClaimBody) -> Option<String> {
    let provenance = milestone_claim_envelope_evidence(body)?
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY))
                .then_some(value)
        })?;
    let Value::Map(entries) = provenance else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(crate::agent_dispatch::AGENT_DISPATCH_MILESTONE_AGENT_KEY))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

pub(crate) fn deindex_dreamer_milestone_claim(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let claim_key = dreamer_milestone_claim_key(claim_id);
    let Some(candidate_key) = store
        .vault_meta
        .get(wtxn, &claim_key)?
        .map(|value| value.to_vec())
    else {
        return Ok(());
    };
    store.vault_meta.delete(wtxn, &candidate_key)?;
    store.vault_meta.delete(wtxn, &claim_key)?;
    Ok(())
}

fn latest_indexed_dreamer_milestone(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    let prefix = dreamer_milestone_candidate_prefix(attempt_id);
    let mut latest: Option<DreamerDurableMilestone> = None;
    for row in store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, _value) = row?;
        let Some(milestone) = indexed_dreamer_milestone_if_current(store, rtxn, &key, attempt_id)?
        else {
            continue;
        };
        latest = Some(milestone);
    }
    Ok(latest)
}

fn indexed_dreamer_milestone_if_current(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
    expected_attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    let Ok((attempt_id, at, learned_at, claim_id)) = decode_dreamer_milestone_candidate_key(key)
    else {
        return Ok(None);
    };
    if attempt_id != expected_attempt_id {
        return Ok(None);
    }
    let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(None);
    };
    let Some(milestone) = dreamer_milestone_from_claim_body(&claim_id, &body, header.learned_at)
    else {
        return Ok(None);
    };
    if milestone.attempt_id == attempt_id
        && milestone.at == at
        && milestone.learned_at == learned_at
        && milestone.claim_id == claim_id
    {
        Ok(Some(milestone))
    } else {
        Ok(None)
    }
}

fn backfill_dreamer_milestone_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    let mut milestones = Vec::new();
    for row in store.entities.iter(&*wtxn)? {
        let (key, raw) = row?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() == ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let Ok(key_bytes) = <[u8; 16]>::try_from(key.as_ref()) else {
            continue;
        };
        let Ok(claim_id) = EntityId::from_bytes(key_bytes) else {
            continue;
        };
        let Some(milestone) =
            dreamer_milestone_from_claim_body(&claim_id, &body, header.learned_at)
        else {
            continue;
        };
        // The one-time backfill is an indexing door like the `apply_put`
        // hook, so it runs the SAME binding check — otherwise a forged
        // milestone written before the index existed would be admitted by
        // the rebuild.
        if !dreamer_milestone_attribution_is_bound(store, &*wtxn, milestone.attempt_id, &body) {
            continue;
        }
        milestones.push(milestone);
    }

    let mut latest: Option<DreamerDurableMilestone> = None;
    for milestone in milestones {
        let candidate_key = dreamer_milestone_candidate_key(&milestone);
        store.vault_meta.put(wtxn, &candidate_key, b"")?;
        store.vault_meta.put(
            wtxn,
            &dreamer_milestone_claim_key(&milestone.claim_id),
            &candidate_key,
        )?;
        if milestone.attempt_id == attempt_id
            && latest.as_ref().is_none_or(|current| {
                (milestone.at, milestone.learned_at, milestone.claim_id)
                    > (current.at, current.learned_at, current.claim_id)
            })
        {
            latest = Some(milestone);
        }
    }
    store
        .vault_meta
        .put(wtxn, DREAMER_MILESTONE_INDEX_BACKFILLED_KEY, b"1")?;
    Ok(latest)
}

fn dreamer_milestone_from_claim_body(
    claim_id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Option<DreamerDurableMilestone> {
    if body.predicate != DREAMER_MILESTONE_PREDICATE
        || body.approval != ClaimApprovalStatus::Approved
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
    {
        return None;
    }
    let Ok((attempt_id, kind, at)) = decode_milestone_value(&body.value) else {
        return None;
    };
    Some(DreamerDurableMilestone {
        claim_id: *claim_id,
        attempt_id,
        kind,
        at,
        learned_at,
    })
}

fn dreamer_milestone_candidate_prefix(attempt_id: AttemptId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX);
    key.extend_from_slice(attempt_id.as_bytes());
    key
}

fn dreamer_milestone_candidate_key(milestone: &DreamerDurableMilestone) -> Vec<u8> {
    let mut key = dreamer_milestone_candidate_prefix(milestone.attempt_id);
    key.extend_from_slice(&milestone.at.to_be_bytes());
    key.extend_from_slice(&milestone.learned_at.to_be_bytes());
    key.extend_from_slice(milestone.claim_id.as_bytes());
    key
}

fn dreamer_milestone_claim_key(claim_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_MILESTONE_INDEX_CLAIM_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_MILESTONE_INDEX_CLAIM_PREFIX);
    key.extend_from_slice(claim_id.as_bytes());
    key
}

fn decode_dreamer_milestone_candidate_key(key: &[u8]) -> Result<(AttemptId, u64, u64, EntityId)> {
    if key.len() != DREAMER_MILESTONE_INDEX_CANDIDATE_KEY_LEN
        || !key.starts_with(DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX)
    {
        return Err(Error::CorruptedIndex("dreamer milestone index key"));
    }
    let mut cursor = DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX.len();
    let attempt_id = AttemptId::from_bytes(&key[cursor..cursor + 16])?;
    cursor += 16;
    let at = u64::from_be_bytes(
        key[cursor..cursor + 8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("dreamer milestone index key"))?,
    );
    cursor += 8;
    let learned_at = u64::from_be_bytes(
        key[cursor..cursor + 8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("dreamer milestone index key"))?,
    );
    cursor += 8;
    let claim_id = EntityId::from_bytes(
        key[cursor..cursor + 16]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("dreamer milestone index key"))?,
    )?;
    Ok((attempt_id, at, learned_at, claim_id))
}

/// The ONE home of the pinned `dreamer.job_milestone` claim-value shape
/// (`["schema_version","job_id","milestone","at"]`). Public so the agent
/// dispatch layer (and the DREAM execution loop) build milestone values here
/// instead of re-encoding the shape.
pub fn dreamer_milestone_value(
    attempt_id: AttemptId,
    kind: DreamerMilestoneKind,
    at: u64,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_MILESTONE_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_ATTEMPT_ID), encode_attempt_id(attempt_id)),
        (Value::from(KEY_MILESTONE), Value::from(kind.as_str())),
        (Value::from(KEY_AT), Value::from(at)),
    ])
}

fn decode_milestone_value(value: &Value) -> Result<(AttemptId, DreamerMilestoneKind, u64)> {
    let entries = expect_map(value, "dreamer milestone value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut milestone = None;
    let mut at = None;
    let mut seen = [false; DREAMER_MILESTONE_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer milestone value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_MILESTONE_VALUE_KEYS).ok_or(
            invalid_dreamer_runner("dreamer milestone value key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer milestone value key",
            ));
        }
        seen[index] = true;

        match DREAMER_MILESTONE_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer milestone value schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_MILESTONE => {
                let parsed =
                    expect_string(value, "dreamer milestone value milestone must be a string")?;
                milestone = Some(DreamerMilestoneKind::parse(&parsed).ok_or(
                    invalid_dreamer_runner("unknown dreamer milestone value milestone"),
                )?);
            }
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer milestone value at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_MILESTONE_VALUE_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer milestone value schema_version",
    ))?;
    if schema_version != DREAMER_MILESTONE_VALUE_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer milestone value schema_version",
        ));
    }

    Ok((
        attempt_id.ok_or(invalid_dreamer_runner(
            "missing dreamer milestone value job_id",
        ))?,
        milestone.ok_or(invalid_dreamer_runner(
            "missing dreamer milestone value milestone",
        ))?,
        at.ok_or(invalid_dreamer_runner("missing dreamer milestone value at"))?,
    ))
}

#[cfg(feature = "sync")]
#[must_use]
pub fn dreamer_attempt_progress_key(attempt_id: AttemptId) -> String {
    let mut key = String::with_capacity(DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX.len() + 32);
    key.push_str(DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX);
    for byte in attempt_id.as_bytes() {
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

#[cfg(feature = "sync")]
fn encode_attempt_progress_value(
    update: &DreamerAttemptProgressUpdate,
) -> std::result::Result<LoroValue, TransportError> {
    update.validate()?;
    Ok(LoroValue::Map(
        vec![
            (
                KEY_SCHEMA_VERSION.to_owned(),
                LoroValue::I64(DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION),
            ),
            (
                KEY_ATTEMPT_ID.to_owned(),
                LoroValue::String(dreamer_attempt_id_hex(update.attempt_id).into()),
            ),
            (
                KEY_STATE.to_owned(),
                LoroValue::String(update.state.as_str().into()),
            ),
            (
                KEY_MESSAGE.to_owned(),
                update
                    .message
                    .as_deref()
                    .map_or(LoroValue::Null, |message| LoroValue::String(message.into())),
            ),
            (
                KEY_COMPLETED_UNITS.to_owned(),
                LoroValue::I64(u64_to_i64_progress(update.completed_units)?),
            ),
            (
                KEY_TOTAL_UNITS.to_owned(),
                update
                    .total_units
                    .map(u64_to_i64_progress)
                    .transpose()?
                    .map_or(LoroValue::Null, LoroValue::I64),
            ),
            (
                KEY_UPDATED_AT_MS.to_owned(),
                LoroValue::I64(u64_to_i64_progress(update.updated_at_ms)?),
            ),
        ]
        .into(),
    ))
}

#[cfg(feature = "sync")]
fn decode_attempt_progress_value(
    value: &LoroValue,
    expected_attempt_id: AttemptId,
) -> std::result::Result<DreamerAttemptProgressUpdate, TransportError> {
    let LoroValue::Map(entries) = value else {
        return Err(TransportError::InvalidPayload(
            "dreamer progress value must be a map",
        ));
    };
    if entries
        .keys()
        .any(|key| !DREAMER_ATTEMPT_PROGRESS_VALUE_KEYS.contains(&key.as_str()))
    {
        return Err(TransportError::InvalidPayload(
            "dreamer progress value key is not pinned",
        ));
    }

    let schema_version = expect_loro_i64(entries.get(KEY_SCHEMA_VERSION), KEY_SCHEMA_VERSION)?;
    if schema_version != DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION {
        return Err(TransportError::InvalidPayload(
            "unsupported dreamer progress schema_version",
        ));
    }

    let attempt_id = expect_loro_string(entries.get(KEY_ATTEMPT_ID), KEY_ATTEMPT_ID)?;
    if attempt_id != dreamer_attempt_id_hex(expected_attempt_id) {
        return Err(TransportError::InvalidPayload(
            "dreamer progress job_id mismatch",
        ));
    }

    let state =
        DreamerAttemptProgressState::parse(expect_loro_string(entries.get(KEY_STATE), KEY_STATE)?)
            .ok_or(TransportError::InvalidPayload(
                "unknown dreamer progress state",
            ))?;
    let message = match entries.get(KEY_MESSAGE) {
        Some(LoroValue::Null) | None => None,
        Some(value) => Some(expect_loro_string(Some(value), KEY_MESSAGE)?.to_owned()),
    };
    let completed_units = i64_to_u64_progress(expect_loro_i64(
        entries.get(KEY_COMPLETED_UNITS),
        KEY_COMPLETED_UNITS,
    )?)?;
    let total_units = match entries.get(KEY_TOTAL_UNITS) {
        Some(LoroValue::Null) | None => None,
        Some(value) => Some(i64_to_u64_progress(expect_loro_i64(
            Some(value),
            KEY_TOTAL_UNITS,
        )?)?),
    };
    let updated_at_ms = i64_to_u64_progress(expect_loro_i64(
        entries.get(KEY_UPDATED_AT_MS),
        KEY_UPDATED_AT_MS,
    )?)?;

    let update = DreamerAttemptProgressUpdate {
        attempt_id: expected_attempt_id,
        state,
        message,
        completed_units,
        total_units,
        updated_at_ms,
    };
    update.validate()?;
    Ok(update)
}

#[cfg(feature = "sync")]
fn dreamer_attempt_id_hex(attempt_id: AttemptId) -> String {
    let mut out = String::with_capacity(32);
    for byte in attempt_id.as_bytes() {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[cfg(feature = "sync")]
fn u64_to_i64_progress(value: u64) -> std::result::Result<i64, TransportError> {
    i64::try_from(value)
        .map_err(|_| TransportError::InvalidPayload("dreamer progress integer exceeds i64"))
}

#[cfg(feature = "sync")]
fn i64_to_u64_progress(value: i64) -> std::result::Result<u64, TransportError> {
    u64::try_from(value)
        .map_err(|_| TransportError::InvalidPayload("dreamer progress integer is negative"))
}

#[cfg(feature = "sync")]
fn expect_loro_i64(
    value: Option<&LoroValue>,
    field: &'static str,
) -> std::result::Result<i64, TransportError> {
    let Some(LoroValue::I64(value)) = value else {
        return Err(TransportError::InvalidPayload(field));
    };
    Ok(*value)
}

#[cfg(feature = "sync")]
fn expect_loro_string<'a>(
    value: Option<&'a LoroValue>,
    field: &'static str,
) -> std::result::Result<&'a str, TransportError> {
    let Some(LoroValue::String(value)) = value else {
        return Err(TransportError::InvalidPayload(field));
    };
    Ok(value.as_str())
}

fn encode_budget_record(record: &DreamerBudgetRecord) -> Result<Vec<u8>> {
    validate_budget_id(&record.budget_id)?;
    validate_budget_record(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_BUDGET_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_BUDGET_ID),
            Value::from(record.budget_id.as_str()),
        ),
        (
            Value::from(KEY_TOTAL_UNITS),
            Value::from(record.total_units),
        ),
        (
            Value::from(KEY_REMAINING_UNITS),
            Value::from(record.remaining_units),
        ),
        (
            Value::from(KEY_RESERVED_UNITS),
            Value::from(record.reserved_units),
        ),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(&value, "dreamer budget MessagePack encode failed")
}

fn decode_budget_record(bytes: &[u8]) -> Result<DreamerBudgetRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer budget must be a MessagePack map")?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut total_units = None;
    let mut remaining_units = None;
    let mut reserved_units = None;
    let mut updated_at = None;
    let mut seen = [false; DREAMER_BUDGET_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer budget keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_BUDGET_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer budget key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer budget key"));
        }
        seen[index] = true;

        match DREAMER_BUDGET_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer budget schema_version must be an integer",
                )?);
            }
            KEY_BUDGET_ID => {
                let parsed = expect_string(value, "dreamer budget_id must be a string")?;
                validate_budget_id(&parsed)?;
                budget_id = Some(parsed);
            }
            KEY_TOTAL_UNITS => {
                total_units = Some(expect_u64(value, "dreamer total_units must be an integer")?);
            }
            KEY_REMAINING_UNITS => {
                remaining_units = Some(expect_u64(
                    value,
                    "dreamer remaining_units must be an integer",
                )?);
            }
            KEY_RESERVED_UNITS => {
                reserved_units = Some(expect_u64(
                    value,
                    "dreamer reserved_units must be an integer",
                )?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value, "dreamer updated_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_BUDGET_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer budget schema_version",
    ))?;
    if schema_version != DREAMER_BUDGET_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer budget schema_version",
        ));
    }

    let record = DreamerBudgetRecord {
        budget_id: budget_id.ok_or(invalid_dreamer_runner("missing dreamer budget_id"))?,
        total_units: total_units.ok_or(invalid_dreamer_runner("missing dreamer total_units"))?,
        remaining_units: remaining_units
            .ok_or(invalid_dreamer_runner("missing dreamer remaining_units"))?,
        reserved_units: reserved_units
            .ok_or(invalid_dreamer_runner("missing dreamer reserved_units"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_record(&record)?;
    Ok(record)
}

fn encode_budget_reservation(record: &DreamerBudgetReservation) -> Result<Vec<u8>> {
    validate_budget_reservation(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_BUDGET_ID),
            Value::from(record.budget_id.as_str()),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (
            Value::from(KEY_RESERVED_UNITS),
            Value::from(record.reserved_units),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(
        &value,
        "dreamer budget reservation MessagePack encode failed",
    )
}

fn decode_budget_reservation(bytes: &[u8]) -> Result<DreamerBudgetReservation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(
        &value,
        "dreamer budget reservation must be a MessagePack map",
    )?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut attempt_id = None;
    let mut reserved_units = None;
    let mut created_at = None;
    let mut updated_at = None;
    let mut seen = [false; DREAMER_BUDGET_RESERVATION_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer budget reservation keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_BUDGET_RESERVATION_KEYS).ok_or(
            invalid_dreamer_runner("dreamer budget reservation key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer budget reservation key",
            ));
        }
        seen[index] = true;

        match DREAMER_BUDGET_RESERVATION_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer budget reservation schema_version must be an integer",
                )?);
            }
            KEY_BUDGET_ID => {
                let parsed = expect_string(value, "dreamer budget_id must be a string")?;
                validate_budget_id(&parsed)?;
                budget_id = Some(parsed);
            }
            KEY_ATTEMPT_ID => {
                attempt_id = Some(decode_attempt_id(value)?);
            }
            KEY_RESERVED_UNITS => {
                reserved_units = Some(expect_u64(
                    value,
                    "dreamer reserved_units must be an integer",
                )?);
            }
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(value, "dreamer created_at must be an integer")?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value, "dreamer updated_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_BUDGET_RESERVATION_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer budget reservation schema_version",
    ))?;
    if schema_version != DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer budget reservation schema_version",
        ));
    }

    let record = DreamerBudgetReservation {
        budget_id: budget_id.ok_or(invalid_dreamer_runner("missing dreamer budget_id"))?,
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer job_id"))?,
        reserved_units: reserved_units
            .ok_or(invalid_dreamer_runner("missing dreamer reserved_units"))?,
        created_at: created_at.ok_or(invalid_dreamer_runner("missing dreamer created_at"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_reservation(&record)?;
    Ok(record)
}

fn encode_run_tree_record(record: &DreamerRunTreeRecord) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_RUN_TREE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (
            Value::from(KEY_PARENT_ATTEMPT),
            encode_optional_attempt_id(record.parent_attempt),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
    ]);
    encode_value(&value, "dreamer run-tree MessagePack encode failed")
}

fn decode_run_tree_record(bytes: &[u8]) -> Result<DreamerRunTreeRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer run-tree row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut parent_attempt = None;
    let mut created_at = None;
    let mut seen = [false; DREAMER_RUN_TREE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer run-tree keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_RUN_TREE_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer run-tree key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer run-tree key"));
        }
        seen[index] = true;

        match DREAMER_RUN_TREE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer run-tree schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_PARENT_ATTEMPT => parent_attempt = Some(decode_optional_attempt_id(value)?),
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(
                    value,
                    "dreamer run-tree created_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_RUN_TREE_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer run-tree schema_version",
    ))?;
    if schema_version != DREAMER_RUN_TREE_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer run-tree schema_version",
        ));
    }

    Ok(DreamerRunTreeRecord {
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer run-tree job_id"))?,
        parent_attempt: parent_attempt.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree parent_job",
        ))?,
        created_at: created_at.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree created_at",
        ))?,
    })
}

fn encode_parked_record(record: &DreamerParkedAttemptRecord) -> Result<Vec<u8>> {
    validate_park_reason(&record.reason)?;
    validate_park_owner(&record.park_owner)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_PARKED_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (Value::from(KEY_REASON), Value::from(record.reason.as_str())),
        (
            Value::from(KEY_PARK_OWNER),
            Value::from(record.park_owner.as_str()),
        ),
        (Value::from(KEY_PARKED_AT), Value::from(record.parked_at)),
    ]);
    encode_value(&value, "dreamer parked row MessagePack encode failed")
}

fn decode_parked_record(bytes: &[u8]) -> Result<DreamerParkedAttemptRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer parked row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut reason = None;
    let mut park_owner = None;
    let mut parked_at = None;
    let mut seen = [false; DREAMER_PARKED_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer parked row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_PARKED_KEYS).ok_or(invalid_dreamer_runner(
            "dreamer parked row key is not pinned",
        ))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer parked row key"));
        }
        seen[index] = true;

        match DREAMER_PARKED_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer parked row schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_REASON => {
                let parsed = expect_string(value, "dreamer parked reason must be a string")?;
                validate_park_reason(&parsed)?;
                reason = Some(parsed);
            }
            KEY_PARK_OWNER => {
                let parsed = expect_string(value, "dreamer parked park_owner must be a string")?;
                validate_park_owner(&parsed)?;
                park_owner = Some(parsed);
            }
            KEY_PARKED_AT => {
                parked_at = Some(expect_u64(value, "dreamer parked_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_PARKED_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer parked row schema_version",
    ))?;
    if schema_version != DREAMER_PARKED_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer parked row schema_version",
        ));
    }

    Ok(DreamerParkedAttemptRecord {
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer parked job_id"))?,
        reason: reason.ok_or(invalid_dreamer_runner("missing dreamer parked reason"))?,
        park_owner: park_owner
            .ok_or(invalid_dreamer_runner("missing dreamer parked park_owner"))?,
        parked_at: parked_at.ok_or(invalid_dreamer_runner("missing dreamer parked_at"))?,
    })
}

fn encode_value(value: &Value, reason: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(reason))?;
    Ok(out)
}

fn decode_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_dreamer_runner("dreamer runner row is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_dreamer_runner(
            "trailing bytes after dreamer runner row",
        ));
    }
    Ok(value)
}

fn encode_attempt_id(attempt_id: AttemptId) -> Value {
    Value::Binary(attempt_id.as_bytes().to_vec())
}

fn decode_attempt_id(value: &Value) -> Result<AttemptId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_dreamer_runner("dreamer attempt id must be binary"));
    };
    AttemptId::from_bytes(bytes)
}

fn encode_optional_attempt_id(attempt_id: Option<AttemptId>) -> Value {
    attempt_id.map_or(Value::Nil, encode_attempt_id)
}

fn decode_optional_attempt_id(value: &Value) -> Result<Option<AttemptId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_attempt_id(value).map(Some)
}

fn expect_map<'a>(value: &'a Value, reason: &'static str) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_dreamer_runner(reason));
    };
    Ok(entries)
}

fn expect_key<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or(invalid_dreamer_runner(reason))
}

fn expect_string(value: &Value, reason: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(invalid_dreamer_runner(reason))
}

fn expect_u64(value: &Value, reason: &'static str) -> Result<u64> {
    value.as_u64().ok_or(invalid_dreamer_runner(reason))
}

fn pinned_key_index(key: &str, keys: &[&str]) -> Option<usize> {
    keys.iter().position(|known| *known == key)
}

fn budget_key(budget_id: &str) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_BUDGET_PREFIX.len() + budget_id.len());
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_PREFIX);
    out.extend_from_slice(budget_id.as_bytes());
    Ok(out)
}

fn budget_reservation_key(budget_id: &str, attempt_id: AttemptId) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let budget_id_len = u16::try_from(budget_id.len())
        .map_err(|_| invalid_dreamer_runner("dreamer budget_id exceeds 128 bytes"))?;
    let mut out = Vec::with_capacity(
        DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX.len() + 2 + budget_id.len() + 16,
    );
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX);
    out.extend_from_slice(&budget_id_len.to_be_bytes());
    out.extend_from_slice(budget_id.as_bytes());
    out.extend_from_slice(attempt_id.as_bytes());
    Ok(out)
}

fn run_tree_key(attempt_id: AttemptId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_RUN_TREE_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_RUN_TREE_PREFIX);
    out.extend_from_slice(attempt_id.as_bytes());
    out
}

fn parked_key(attempt_id: AttemptId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_PARKED_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_PARKED_PREFIX);
    out.extend_from_slice(attempt_id.as_bytes());
    out
}

fn validate_attempt_type(attempt_type: &str) -> Result<()> {
    if attempt_type.is_empty() {
        return Err(invalid_dreamer_runner("dreamer job_type must not be empty"));
    }
    if attempt_type.len() > MAX_DREAMER_ATTEMPT_TYPE_LEN {
        return Err(invalid_dreamer_runner("dreamer job_type exceeds 128 bytes"));
    }
    Ok(())
}

fn validate_budget_id(budget_id: &str) -> Result<()> {
    if budget_id.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id must not be empty",
        ));
    }
    if budget_id.len() > MAX_DREAMER_BUDGET_ID_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id exceeds 128 bytes",
        ));
    }
    Ok(())
}

fn validate_park_reason(reason: &str) -> Result<()> {
    if reason.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason must not be empty",
        ));
    }
    if reason.len() > MAX_DREAMER_PARK_REASON_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason exceeds 512 bytes",
        ));
    }
    Ok(())
}

fn validate_park_owner(park_owner: &str) -> Result<()> {
    if park_owner.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked park_owner must not be empty",
        ));
    }
    if park_owner.len() > MAX_DREAMER_PARK_OWNER_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer parked park_owner exceeds 128 bytes",
        ));
    }
    Ok(())
}

fn validate_admission_input(input: &AdmitDreamerAttempt) -> Result<()> {
    validate_budget_id(&input.budget_id)?;
    if input.reserve_units == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer admission reserve_units must be > 0",
        ));
    }
    if input
        .started_milestone
        .as_ref()
        .is_some_and(|milestone| milestone.kind != DreamerMilestoneKind::Started)
    {
        return Err(invalid_dreamer_runner(
            "dreamer admission milestone must be started",
        ));
    }
    Ok(())
}

fn validate_unit_interval(value: f32, reason: &'static str) -> Result<()> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(invalid_dreamer_runner(reason));
    }
    Ok(())
}

fn is_pattern_claim_predicate(predicate: &str) -> bool {
    predicate
        .strip_prefix("pattern.")
        .is_some_and(|suffix| !suffix.is_empty())
}

fn validate_budget_record(record: &DreamerBudgetRecord) -> Result<()> {
    validate_budget_id(&record.budget_id)?;
    if record.remaining_units > record.total_units || record.reserved_units > record.total_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget counters exceed total",
        ));
    }
    let used = record
        .remaining_units
        .checked_add(record.reserved_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget counters"))?;
    if used > record.total_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget counters exceed total",
        ));
    }
    Ok(())
}

fn validate_budget_reservation(record: &DreamerBudgetReservation) -> Result<()> {
    validate_budget_id(&record.budget_id)?;
    if record.reserved_units == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation must reserve > 0 units",
        ));
    }
    if record.updated_at < record.created_at {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation updated_at precedes created_at",
        ));
    }
    Ok(())
}

fn validate_home_node_designation(record: &DreamerHomeNodeDesignation) -> Result<()> {
    if record.node_id == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer home node_id must be nonzero",
        ));
    }
    Ok(())
}

const fn invalid_dreamer_runner(reason: &'static str) -> Error {
    Error::InvalidAttemptQueueRecord(reason)
}

#[cfg(test)]
mod tests;
