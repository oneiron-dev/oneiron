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
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::job_queue::JobState;
use crate::job_queue::{
    ClaimJob, ClaimOutcome, CompleteJob, CompleteOutcome, EnqueueJob, EnqueueOutcome, FailJob,
    FailOutcome, InterveneJob, JobId, JobInterventionEffect, JobInterventionKind, JobQueue,
    JobRecord,
};
use crate::store::Store;
#[cfg(feature = "sync")]
use crate::sync::{EphemeralStore, LoroValue, TransportError, encode_ephemeral};
use crate::types::{ClaimCandidate, ENTITY_TYPE_CLAIM, EntityId, TimeRange, WriteEnvelope};

/// Generic [`JobQueue`] kind used by Dreamer runner jobs.
pub const DREAMER_RUNNER_JOB_KIND: &str = "dreamer";
/// Current pinned Dreamer job payload schema version.
pub const DREAMER_JOB_PAYLOAD_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer job payloads.
pub const DREAMER_JOB_PAYLOAD_KEYS: [&str; 4] =
    ["schema_version", "job_type", "input", "parent_job"];
/// Claim predicate used for durable Dreamer job milestones.
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
/// Flat ephemeral key prefix for live Dreamer job progress.
#[cfg(feature = "sync")]
pub const DREAMER_JOB_PROGRESS_KEY_PREFIX: &str = "job:";
/// Current schema version for live Dreamer job progress ephemeral values.
#[cfg(feature = "sync")]
pub const DREAMER_JOB_PROGRESS_VALUE_SCHEMA_VERSION: i64 = 1;
/// Default per-job live progress throttle: at most one update per second.
#[cfg(feature = "sync")]
pub const DREAMER_JOB_PROGRESS_THROTTLE_MS: u64 = 1_000;
/// Default in-process terminal-stop retention, matching the sync lane TTL.
#[cfg(feature = "sync")]
pub const DREAMER_JOB_PROGRESS_TERMINAL_RETENTION_MS: u64 = 30_000;
/// Default fan-out reservation for one Dreamer child, in token-like units.
pub const DEFAULT_DREAMER_CHILD_RESERVE_UNITS: u64 = 8_000;
/// Default OF-366 tournament candidate fan-out.
pub const DEFAULT_DREAMER_TOURNAMENT_FANOUT_M: u16 = 2;
/// Default OF-366 tournament refinement depth.
pub const DEFAULT_DREAMER_TOURNAMENT_DEPTH_K: u16 = 2;
/// MICRO consolidation queue kind. Private per-device job rows only.
pub const DREAMER_CONSOLIDATION_MICRO_JOB_KIND: &str = "dreamer.consolidation.micro";
/// MESO consolidation queue kind. Private per-device job rows only.
pub const DREAMER_CONSOLIDATION_MESO_JOB_KIND: &str = "dreamer.consolidation.meso";
/// MACRO consolidation queue kind. Admission is restricted to the elected home node.
pub const DREAMER_CONSOLIDATION_MACRO_JOB_KIND: &str = "dreamer.consolidation.macro";
/// Current pinned home-node designation schema version.
pub const DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for the private home-node designation.
pub const DREAMER_HOME_NODE_DESIGNATION_KEYS: [&str; 4] =
    ["schema_version", "node_id", "class", "elected_at"];

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_JOB_TYPE: &str = "job_type";
const KEY_INPUT: &str = "input";
const KEY_PARENT_JOB: &str = "parent_job";
const KEY_JOB_ID: &str = "job_id";
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
const DREAMER_JOB_PROGRESS_VALUE_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    KEY_JOB_ID,
    KEY_STATE,
    KEY_MESSAGE,
    KEY_COMPLETED_UNITS,
    KEY_TOTAL_UNITS,
    KEY_UPDATED_AT_MS,
];
const DREAMER_BUDGET_SCHEMA_VERSION: u64 = 1;
const DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION: u64 = 1;
const DREAMER_RUN_TREE_SCHEMA_VERSION: u64 = 1;
const DREAMER_PARKED_SCHEMA_VERSION: u64 = 1;
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
    KEY_JOB_ID,
    KEY_RESERVED_UNITS,
    KEY_CREATED_AT,
    KEY_UPDATED_AT,
];
const DREAMER_RUN_TREE_KEYS: [&str; 4] = [
    KEY_SCHEMA_VERSION,
    KEY_JOB_ID,
    KEY_PARENT_JOB,
    KEY_CREATED_AT,
];
const DREAMER_PARKED_KEYS: [&str; 4] = [KEY_SCHEMA_VERSION, KEY_JOB_ID, KEY_REASON, KEY_PARKED_AT];
const DREAMER_PRIVATE_BUDGET_PREFIX: &[u8] = b"dreamer:budget:";
const DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX: &[u8] = b"dreamer:budget_reservation:";
const DREAMER_PRIVATE_RUN_TREE_PREFIX: &[u8] = b"dreamer:run_tree:";
const DREAMER_PRIVATE_PARKED_PREFIX: &[u8] = b"dreamer:parked:";
const DREAMER_PRIVATE_HOME_NODE_KEY: &[u8] = b"dreamer:home_node_macro:v1";
const MAX_DREAMER_JOB_TYPE_LEN: usize = 128;
const MAX_DREAMER_BUDGET_ID_LEN: usize = 128;
const MAX_DREAMER_PARK_REASON_LEN: usize = 512;
#[cfg(feature = "sync")]
const MAX_DREAMER_PROGRESS_MESSAGE_LEN: usize = 512;
const MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT: u32 = 3;
const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR: &str = "dreamer-budget-trap";
const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE: &str =
    "BudgetTrap: tournament claim authoring suspended for budget approval";

/// Coarse Dreamer job progress state for live ephemeral rows and durable
/// milestone fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerJobProgressState {
    Created,
    Started,
    Running,
    CheckpointReached,
    Parked,
    Done,
    Failed,
}

impl DreamerJobProgressState {
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

impl From<DreamerMilestoneKind> for DreamerJobProgressState {
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
    pub job_id: JobId,
    pub kind: DreamerMilestoneKind,
    pub at: u64,
    pub learned_at: u64,
}

/// Live Dreamer progress update to publish into the ephemeral keyspace.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerJobProgressUpdate {
    pub job_id: JobId,
    pub state: DreamerJobProgressState,
    pub message: Option<String>,
    pub completed_units: u64,
    pub total_units: Option<u64>,
    pub updated_at_ms: u64,
}

/// Source used for a progress snapshot returned to a consumer.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerJobProgressSource {
    Ephemeral,
    DurableMilestone,
}

/// Consumer-facing progress snapshot: live row if present, durable milestone
/// fallback otherwise.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerJobProgressSnapshot {
    pub job_id: JobId,
    pub state: DreamerJobProgressState,
    pub source: DreamerJobProgressSource,
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
pub struct DreamerJobProgressProducer {
    throttle_ms: u64,
    terminal_retention_ms: u64,
    last_emitted_at_ms: HashMap<JobId, u64>,
    terminal_at_ms: HashMap<JobId, u64>,
}

/// Consolidation job-table lane.
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

    /// Private job-table kind for this consolidation lane.
    #[must_use]
    pub const fn job_kind(self) -> &'static str {
        match self {
            Self::Micro => DREAMER_CONSOLIDATION_MICRO_JOB_KIND,
            Self::Meso => DREAMER_CONSOLIDATION_MESO_JOB_KIND,
            Self::Macro => DREAMER_CONSOLIDATION_MACRO_JOB_KIND,
        }
    }
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
    pub job_id: JobId,
    pub budget_id: String,
    pub budget: DreamerBudgetRecord,
    pub required_units: u64,
    pub fanout_m: u16,
    pub depth_k: u16,
    pub intervention_effect: JobInterventionEffect,
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
pub struct EnqueueDreamerConsolidationJob {
    pub scope: DreamerConsolidationScope,
    pub input: Value,
    pub parent_job: Option<JobId>,
    /// Optional advisory dedupe key. This is a local cost/policy coalescer,
    /// not a correctness lock.
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Input for home-aware consolidation admission.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmitDreamerConsolidationJob {
    pub scope: DreamerConsolidationScope,
    pub local_node_id: u64,
    pub claim_authoring_tier: DreamerClaimAuthoringBatchTier,
    pub claim_authoring: DreamerClaimAuthoringAdmission,
    pub admission: AdmitDreamerJob,
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
    budget_exhausted_candidate: Option<JobId>,
}

/// Typed Dreamer job payload stored in the generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerJobPayload {
    pub job_type: String,
    pub input: Value,
    pub parent_job: Option<JobId>,
}

/// Input for enqueueing a Dreamer job into the private runner queue.
#[derive(Debug, Clone, PartialEq)]
pub struct EnqueueDreamerJob {
    pub job_type: String,
    pub input: Value,
    pub parent_job: Option<JobId>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Decoded Dreamer job plus its backing generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerJobStatus {
    pub job: JobRecord,
    pub payload: DreamerJobPayload,
}

/// Typed enqueue outcome for Dreamer jobs.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum EnqueueDreamerJobOutcome {
    Enqueued(DreamerJobStatus),
    Existing(DreamerJobStatus),
}

/// Input for completing a leased Dreamer job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDreamerJob {
    pub id: JobId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed complete outcome for a Dreamer job.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CompleteDreamerJobOutcome {
    Completed(DreamerJobStatus),
    AlreadyCompleted(DreamerJobStatus),
}

/// Input for failing a leased Dreamer job terminally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailDreamerJob {
    pub id: JobId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed fail outcome for a Dreamer job.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FailDreamerJobOutcome {
    Failed(DreamerJobStatus),
    AlreadyFailed(DreamerJobStatus),
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
impl DreamerJobProgressUpdate {
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
impl DreamerJobProgressSnapshot {
    fn from_live_update(update: &DreamerJobProgressUpdate) -> Self {
        Self {
            job_id: update.job_id,
            state: update.state,
            source: DreamerJobProgressSource::Ephemeral,
            message: update.message.clone(),
            completed_units: update.completed_units,
            total_units: update.total_units,
            updated_at_ms: update.updated_at_ms,
        }
    }

    fn from_milestone(milestone: DreamerDurableMilestone) -> Self {
        Self {
            job_id: milestone.job_id,
            state: milestone.kind.into(),
            source: DreamerJobProgressSource::DurableMilestone,
            message: None,
            completed_units: 0,
            total_units: None,
            updated_at_ms: milestone.at.saturating_mul(1_000),
        }
    }
}

#[cfg(feature = "sync")]
impl Default for DreamerJobProgressProducer {
    fn default() -> Self {
        Self::with_limits(
            DREAMER_JOB_PROGRESS_THROTTLE_MS,
            DREAMER_JOB_PROGRESS_TERMINAL_RETENTION_MS,
        )
        .expect("default dreamer progress limits are valid")
    }
}

#[cfg(feature = "sync")]
impl DreamerJobProgressProducer {
    /// Creates a producer with the contract-pinned 1Hz throttle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a producer with explicit limits. `terminal_retention_ms` should
    /// match the [`EphemeralStore`] timeout so stopped jobs cannot resume
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

    /// Publishes one live progress update if it passes the per-job throttle.
    ///
    /// Terminal `Done`/`Failed` updates overwrite the mutable live row with a
    /// terminal state, then stop any further live production until TTL ageout.
    pub fn publish(
        &mut self,
        store: &EphemeralStore,
        update: DreamerJobProgressUpdate,
    ) -> std::result::Result<Option<Vec<u8>>, TransportError> {
        update.validate()?;
        self.retain_terminal_stops(update.updated_at_ms);

        if update.state.is_terminal() {
            let key = dreamer_job_progress_key(update.job_id);
            let value = encode_job_progress_value(&update)?;
            store.set(&key, value);
            self.mark_terminal(update.job_id, update.updated_at_ms);
            return encode_ephemeral(&store.encode(&key))
                .into_result()
                .map(Some);
        }
        if self.terminal_at_ms.contains_key(&update.job_id) {
            return Ok(None);
        }
        if let Some(last) = self.last_emitted_at_ms.get(&update.job_id)
            && update.updated_at_ms.saturating_sub(*last) < self.throttle_ms
        {
            return Ok(None);
        }

        let key = dreamer_job_progress_key(update.job_id);
        let value = encode_job_progress_value(&update)?;
        store.set(&key, value);
        self.last_emitted_at_ms
            .insert(update.job_id, update.updated_at_ms);
        encode_ephemeral(&store.encode(&key))
            .into_result()
            .map(Some)
    }

    /// Marks a job terminal without producing a live progress frame.
    pub fn mark_terminal(&mut self, job_id: JobId, now_ms: u64) {
        self.last_emitted_at_ms.remove(&job_id);
        self.terminal_at_ms.insert(job_id, now_ms);
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
    pub job_id: JobId,
    pub reserved_units: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Explicit reserve input for callers that already have a child job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveDreamerBudget {
    pub budget_id: String,
    pub child_job: JobId,
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
    pub child_job: JobId,
    pub actual_units: u64,
    pub now: u64,
}

/// Abort-time refund for a previously reserved child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortDreamerBudgetReservation {
    pub budget_id: String,
    pub child_job: JobId,
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
pub struct AdmitDreamerJob {
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
    Admitted(Box<DreamerAdmittedJob>),
}

/// A leased Dreamer job plus the private budget row after admission.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerAdmittedJob {
    pub status: DreamerJobStatus,
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
}

/// Private run-tree row keyed by job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerRunTreeRecord {
    pub job_id: JobId,
    pub parent_job: Option<JobId>,
    pub created_at: u64,
}

/// Input for parking a Dreamer job in local runner state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkDreamerJob {
    pub job_id: JobId,
    pub reason: String,
    pub now: u64,
}

/// Private parked-job row keyed by job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerParkedJobRecord {
    pub job_id: JobId,
    pub reason: String,
    pub parked_at: u64,
}

/// Private Dreamer runner store over an already-open vault.
pub struct DreamerRunnerStore<'a> {
    vault: &'a Vault,
    jobs: JobQueue<'a>,
}

impl<'a> DreamerRunnerStore<'a> {
    /// Opens a Dreamer runner store over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            jobs: JobQueue::new(vault),
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
        decode_home_node_designation(raw).map(Some)
    }

    /// Enqueues a Dreamer job and records its private run-tree parent row in
    /// the same LMDB write transaction.
    pub fn enqueue(&self, input: EnqueueDreamerJob) -> Result<EnqueueDreamerJobOutcome> {
        validate_job_type(&input.job_type)?;
        let payload = DreamerJobPayload {
            job_type: input.job_type,
            input: input.input,
            parent_job: input.parent_job,
        };
        let encoded_payload = encode_dreamer_job_payload(&payload)?;

        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.jobs.enqueue_in_txn(
            &mut wtxn,
            EnqueueJob {
                kind: DREAMER_RUNNER_JOB_KIND.to_owned(),
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
                        job_id: record.id,
                        parent_job: payload.parent_job,
                        created_at: record.created_at,
                    },
                )?;
                (true, decode_dreamer_job_status(record)?)
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, &mut wtxn, &record)?;
                (false, decode_dreamer_job_status(record)?)
            }
        };
        wtxn.commit()?;

        if was_enqueued {
            Ok(EnqueueDreamerJobOutcome::Enqueued(status))
        } else {
            Ok(EnqueueDreamerJobOutcome::Existing(status))
        }
    }

    /// Enqueues a local consolidation job on the advisory job-table floor.
    ///
    /// MICRO and MESO remain per-device because these queue rows are private
    /// runner state. MACRO uses the same advisory dedupe mechanics, but
    /// admission is restricted by [`Self::admit_next_consolidation`].
    pub fn enqueue_consolidation(
        &self,
        input: EnqueueDreamerConsolidationJob,
    ) -> Result<EnqueueDreamerJobOutcome> {
        let payload = DreamerJobPayload {
            job_type: input.scope.as_str().to_owned(),
            input: input.input,
            parent_job: input.parent_job,
        };
        let encoded_payload = encode_dreamer_job_payload(&payload)?;

        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.jobs.enqueue_in_txn(
            &mut wtxn,
            EnqueueJob {
                kind: input.scope.job_kind().to_owned(),
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
                        job_id: record.id,
                        parent_job: payload.parent_job,
                        created_at: record.created_at,
                    },
                )?;
                (true, decode_dreamer_job_status(record)?)
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, &mut wtxn, &record)?;
                (false, decode_dreamer_job_status(record)?)
            }
        };
        wtxn.commit()?;

        if was_enqueued {
            Ok(EnqueueDreamerJobOutcome::Enqueued(status))
        } else {
            Ok(EnqueueDreamerJobOutcome::Existing(status))
        }
    }

    /// Publishes a live progress update for an existing Dreamer job.
    ///
    /// This is the runner seam used by execution loops for in-flight ticks;
    /// the producer enforces per-job throttling and terminal-stop behavior.
    #[cfg(feature = "sync")]
    pub fn publish_progress(
        &self,
        producer: &mut DreamerJobProgressProducer,
        ephemeral: &EphemeralStore,
        update: DreamerJobProgressUpdate,
    ) -> Result<Option<Vec<u8>>> {
        let status = self.status(update.job_id)?.ok_or(invalid_dreamer_runner(
            "dreamer progress job must exist before publish",
        ))?;
        match (status.job.state, update.state) {
            (JobState::Completed, DreamerJobProgressState::Done)
            | (JobState::Failed, DreamerJobProgressState::Failed)
            | (JobState::Queued | JobState::Leased, _) => {}
            (
                JobState::Paused | JobState::Completed | JobState::Failed | JobState::Cancelled,
                _,
            ) => {
                return Ok(None);
            }
        }
        producer
            .publish(ephemeral, update)
            .map_err(dreamer_progress_error)
    }

    /// Atomically admits the next queued Dreamer job.
    ///
    /// A successful admission leases one queue row, mutates the private budget
    /// counter, and optionally writes a durable started milestone claim before
    /// committing. Budget denial commits only queue scan repairs, leaving the
    /// job queued and the budget row unchanged.
    pub fn admit_next(&self, input: AdmitDreamerJob) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(DREAMER_RUNNER_JOB_KIND, input)
    }

    /// Home-aware consolidation admission.
    ///
    /// MICRO/MESO admission remains per-device. MACRO admission requires the
    /// caller's local node id to match the persisted home-node designation.
    pub fn admit_next_consolidation(
        &self,
        mut input: AdmitDreamerConsolidationJob,
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
            self.admit_next_kind_in_txn(&mut wtxn, input.scope.job_kind(), input.admission)?;
        match (tournament_grant, result.outcome) {
            (Some(grant), DreamerAdmissionOutcome::BudgetExhausted(budget)) => {
                let Some(job_id) = result.budget_exhausted_candidate else {
                    wtxn.commit()?;
                    return Ok(DreamerConsolidationAdmissionOutcome::Admission(
                        DreamerAdmissionOutcome::BudgetExhausted(budget),
                    ));
                };
                let intervention = self.jobs.intervene_in_txn(
                    &mut wtxn,
                    InterveneJob {
                        id: job_id,
                        kind: JobInterventionKind::Pause,
                        actor: DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR.to_owned(),
                        note: Some(DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE.to_owned()),
                        now: budget_trap_now,
                    },
                )?;
                wtxn.commit()?;
                Ok(
                    DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(
                        DreamerClaimAuthoringBudgetTrap {
                            job_id,
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
        input: AdmitDreamerJob,
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
        input: AdmitDreamerJob,
    ) -> Result<DreamerKindAdmissionResult> {
        let Some(candidate_job_id) = self
            .jobs
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
        let existing_reservation =
            read_budget_reservation_in_txn(self.vault, wtxn, &input.budget_id, candidate_job_id)?;
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
                        budget_exhausted_candidate: Some(candidate_job_id),
                    });
                }
            }
        } else if input.reserve_units > budget.remaining_units {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::BudgetExhausted(budget),
                budget_exhausted_candidate: Some(candidate_job_id),
            });
        }

        let claim = self.jobs.claim_kind_in_txn(
            wtxn,
            queue_kind,
            ClaimJob {
                lease_owner: input.lease_owner,
                now: input.now,
            },
        )?;
        let ClaimOutcome::Claimed(job) = claim else {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::Empty,
                budget_exhausted_candidate: None,
            });
        };
        if job.id != candidate_job_id {
            return Err(invalid_dreamer_runner(
                "dreamer admission claimed unexpected ready job",
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
                job_id: job.id,
                reserved_units: input.reserve_units,
                created_at: input.now,
                updated_at: input.now,
            };
            reserve_budget_for_child_in_txn(self.vault, wtxn, &mut budget, &reservation)?;
            reservation
        };

        if let Some(milestone) = input.started_milestone {
            apply_milestone_claim_in_txn(self.vault, wtxn, job.id, milestone)?;
        }

        let status = decode_dreamer_job_status(job)?;

        Ok(DreamerKindAdmissionResult {
            outcome: DreamerAdmissionOutcome::Admitted(Box::new(DreamerAdmittedJob {
                status,
                budget,
                reservation,
            })),
            budget_exhausted_candidate: None,
        })
    }

    /// Admits the next Dreamer job and emits its initial live progress row.
    #[cfg(feature = "sync")]
    pub fn admit_next_with_progress(
        &self,
        input: AdmitDreamerJob,
        producer: &mut DreamerJobProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<DreamerAdmissionOutcome>> {
        let now_ms = input.now.saturating_mul(1_000);
        let outcome = self.admit_next(input)?;
        let frame = if let DreamerAdmissionOutcome::Admitted(admitted) = &outcome {
            let reservation = &admitted.reservation;
            self.publish_progress(
                producer,
                ephemeral,
                DreamerJobProgressUpdate {
                    job_id: admitted.status.job.id,
                    state: DreamerJobProgressState::Started,
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

    /// Reserves wake-budget units for a known child job.
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
        if let Some(reservation) =
            read_budget_reservation_in_txn(self.vault, &wtxn, &input.budget_id, input.child_job)?
        {
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
            job_id: input.child_job,
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
        let reservation_key = budget_reservation_key(&input.budget_id, input.child_job)?;
        let Some(reservation) =
            read_budget_reservation_in_txn(self.vault, &wtxn, &input.budget_id, input.child_job)?
        else {
            return Ok(DreamerBudgetSettlementOutcome::NoReservation);
        };

        let budget_key = budget_key(&input.budget_id)?;
        let Some(raw_budget) = self.vault.store.vault_meta.get(&wtxn, &budget_key)? else {
            return Err(invalid_dreamer_runner(
                "dreamer budget reservation missing counter",
            ));
        };
        let mut budget = decode_budget_record(raw_budget)?;
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
            child_job: input.child_job,
            actual_units: 0,
            now: input.now,
        })
    }

    /// Marks a leased Dreamer job complete through the generic queue.
    pub fn complete(&self, input: CompleteDreamerJob) -> Result<CompleteDreamerJobOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        match self.jobs.complete(CompleteJob {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            now: input.now,
        })? {
            CompleteOutcome::Completed(record) => Ok(CompleteDreamerJobOutcome::Completed(
                decode_dreamer_job_status(record)?,
            )),
            CompleteOutcome::AlreadyCompleted(record) => Ok(
                CompleteDreamerJobOutcome::AlreadyCompleted(decode_dreamer_job_status(record)?),
            ),
        }
    }

    /// Marks a leased Dreamer job complete and stops live progress production.
    #[cfg(feature = "sync")]
    pub fn complete_with_progress(
        &self,
        input: CompleteDreamerJob,
        producer: &mut DreamerJobProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<CompleteDreamerJobOutcome>> {
        let outcome = self.complete(input)?;
        let status = complete_outcome_status(&outcome);
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerJobProgressUpdate {
                job_id: status.job.id,
                state: DreamerJobProgressState::Done,
                message: None,
                completed_units: 0,
                total_units: None,
                updated_at_ms: status.job.updated_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed { outcome, frame })
    }

    /// Marks a leased Dreamer job terminally failed through the generic queue.
    pub fn fail(&self, input: FailDreamerJob) -> Result<FailDreamerJobOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        match self.jobs.fail(FailJob {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            reason: input.reason,
            now: input.now,
        })? {
            FailOutcome::Failed(record) => Ok(FailDreamerJobOutcome::Failed(
                decode_dreamer_job_status(record)?,
            )),
            FailOutcome::AlreadyFailed(record) => Ok(FailDreamerJobOutcome::AlreadyFailed(
                decode_dreamer_job_status(record)?,
            )),
        }
    }

    /// Marks a leased Dreamer job failed and stops live progress production.
    #[cfg(feature = "sync")]
    pub fn fail_with_progress(
        &self,
        input: FailDreamerJob,
        producer: &mut DreamerJobProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<FailDreamerJobOutcome>> {
        let outcome = self.fail(input)?;
        let status = fail_outcome_status(&outcome);
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerJobProgressUpdate {
                job_id: status.job.id,
                state: DreamerJobProgressState::Failed,
                message: bounded_progress_message(status.job.last_error.as_deref()),
                completed_units: 0,
                total_units: None,
                updated_at_ms: status.job.updated_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed { outcome, frame })
    }

    fn ensure_terminal_transition_target(&self, id: JobId) -> Result<()> {
        let record = self.jobs.get(id)?.ok_or(invalid_dreamer_runner(
            "dreamer terminal transition job must exist",
        ))?;
        decode_dreamer_job_status(record).map(|_| ())
    }

    /// Reads one Dreamer job by queue id.
    pub fn status(&self, id: JobId) -> Result<Option<DreamerJobStatus>> {
        self.jobs
            .get(id)?
            .map(decode_dreamer_job_status)
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
        decode_budget_record(raw).map(Some)
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
        child_job: JobId,
    ) -> Result<Option<DreamerBudgetReservation>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_reservation_key(budget_id, child_job)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_reservation(raw).map(Some)
    }

    /// Reads a private Dreamer run-tree row.
    pub fn run_tree(&self, job_id: JobId) -> Result<Option<DreamerRunTreeRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = run_tree_key(job_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_run_tree_record(raw).map(Some)
    }

    /// Parks a Dreamer job in private runner state without changing the
    /// generic queue row.
    pub fn park_job(&self, input: ParkDreamerJob) -> Result<DreamerParkedJobRecord> {
        validate_park_reason(&input.reason)?;
        if self.status(input.job_id)?.is_none() {
            return Err(invalid_dreamer_runner("dreamer parked job must exist"));
        }

        let record = DreamerParkedJobRecord {
            job_id: input.job_id,
            reason: input.reason,
            parked_at: input.now,
        };
        let encoded = encode_parked_record(&record)?;
        let key = parked_key(record.job_id);
        let mut wtxn = self.vault.store.env.write_txn()?;
        self.vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Parks a Dreamer job and emits a live parked progress row.
    #[cfg(feature = "sync")]
    pub fn park_job_with_progress(
        &self,
        input: ParkDreamerJob,
        producer: &mut DreamerJobProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<DreamerParkedJobRecord>> {
        let record = self.park_job(input)?;
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerJobProgressUpdate {
                job_id: record.job_id,
                state: DreamerJobProgressState::Parked,
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

    /// Reads a private parked-job row.
    pub fn parked_job(&self, job_id: JobId) -> Result<Option<DreamerParkedJobRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = parked_key(job_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_parked_record(raw).map(Some)
    }

    /// Returns the latest active/approved durable milestone for `job_id`.
    ///
    /// This is the coarse fallback surface for consumers that cannot reach the
    /// executing device's live ephemeral row.
    pub fn latest_durable_milestone(
        &self,
        job_id: JobId,
    ) -> Result<Option<DreamerDurableMilestone>> {
        let rtxn = self.vault.store.env.read_txn()?;
        if self
            .vault
            .store
            .vault_meta
            .get(&rtxn, DREAMER_MILESTONE_INDEX_BACKFILLED_KEY)?
            .is_some()
        {
            return latest_indexed_dreamer_milestone(&self.vault.store, &rtxn, job_id);
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
            return latest_indexed_dreamer_milestone(&self.vault.store, &rtxn, job_id);
        }
        let latest = backfill_dreamer_milestone_index(&self.vault.store, &mut wtxn, job_id)?;
        wtxn.commit()?;
        Ok(latest)
    }

    /// Returns the live ephemeral progress row when present, otherwise falls
    /// back to the latest durable milestone claim.
    #[cfg(feature = "sync")]
    pub fn progress_snapshot(
        &self,
        ephemeral: &EphemeralStore,
        job_id: JobId,
    ) -> Result<Option<DreamerJobProgressSnapshot>> {
        if let Some(value) = ephemeral.get(&dreamer_job_progress_key(job_id))
            && let Ok(update) = decode_job_progress_value(&value, job_id)
        {
            return Ok(Some(DreamerJobProgressSnapshot::from_live_update(&update)));
        }

        self.latest_durable_milestone(job_id)
            .map(|milestone| milestone.map(DreamerJobProgressSnapshot::from_milestone))
    }
}

/// Encodes a Dreamer job payload in canonical MessagePack field order.
pub fn encode_dreamer_job_payload(payload: &DreamerJobPayload) -> Result<Vec<u8>> {
    validate_job_type(&payload.job_type)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_JOB_PAYLOAD_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_JOB_TYPE),
            Value::from(payload.job_type.as_str()),
        ),
        (Value::from(KEY_INPUT), payload.input.clone()),
        (
            Value::from(KEY_PARENT_JOB),
            encode_optional_job_id(payload.parent_job),
        ),
    ]);
    encode_value(&value, "dreamer job payload MessagePack encode failed")
}

/// Decodes and validates a Dreamer job payload.
pub fn decode_dreamer_job_payload(bytes: &[u8]) -> Result<DreamerJobPayload> {
    let value = decode_value(bytes)?;
    decode_dreamer_job_payload_value(&value)
}

fn decode_dreamer_job_status(record: JobRecord) -> Result<DreamerJobStatus> {
    if !is_dreamer_queue_kind(&record.kind) {
        return Err(invalid_dreamer_runner("job is not a Dreamer runner job"));
    }
    let payload = decode_dreamer_job_payload(&record.payload)?;
    Ok(DreamerJobStatus {
        job: record,
        payload,
    })
}

#[cfg(feature = "sync")]
fn dreamer_progress_error(error: TransportError) -> Error {
    Error::SyncProtocolError(error.to_string())
}

#[cfg(feature = "sync")]
fn complete_outcome_status(outcome: &CompleteDreamerJobOutcome) -> &DreamerJobStatus {
    match outcome {
        CompleteDreamerJobOutcome::Completed(status)
        | CompleteDreamerJobOutcome::AlreadyCompleted(status) => status,
    }
}

#[cfg(feature = "sync")]
fn fail_outcome_status(outcome: &FailDreamerJobOutcome) -> &DreamerJobStatus {
    match outcome {
        FailDreamerJobOutcome::Failed(status) | FailDreamerJobOutcome::AlreadyFailed(status) => {
            status
        }
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
    kind == DREAMER_RUNNER_JOB_KIND
        || kind == DREAMER_CONSOLIDATION_MICRO_JOB_KIND
        || kind == DREAMER_CONSOLIDATION_MESO_JOB_KIND
        || kind == DREAMER_CONSOLIDATION_MACRO_JOB_KIND
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
    decode_home_node_designation(raw).map(Some)
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

fn decode_dreamer_job_payload_value(value: &Value) -> Result<DreamerJobPayload> {
    let entries = expect_map(value, "dreamer job payload must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_type = None;
    let mut input = None;
    let mut parent_job = None;
    let mut seen = [false; DREAMER_JOB_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer job payload keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_JOB_PAYLOAD_KEYS).ok_or(
            invalid_dreamer_runner("dreamer job payload key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer job payload key"));
        }
        seen[index] = true;

        match DREAMER_JOB_PAYLOAD_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer job payload schema_version must be an integer",
                )?);
            }
            KEY_JOB_TYPE => {
                let parsed = expect_string(value, "dreamer job_type must be a string")?;
                validate_job_type(&parsed)?;
                job_type = Some(parsed);
            }
            KEY_INPUT => input = Some(value.clone()),
            KEY_PARENT_JOB => parent_job = Some(decode_optional_job_id(value)?),
            _ => unreachable!("index resolved from DREAMER_JOB_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer job payload schema_version",
    ))?;
    if schema_version != DREAMER_JOB_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer job payload schema_version",
        ));
    }

    Ok(DreamerJobPayload {
        job_type: job_type.ok_or(invalid_dreamer_runner("missing dreamer job_type"))?,
        input: input.ok_or(invalid_dreamer_runner("missing dreamer job input"))?,
        parent_job: parent_job.ok_or(invalid_dreamer_runner("missing dreamer parent_job"))?,
    })
}

fn ensure_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &JobRecord,
) -> Result<()> {
    let key = run_tree_key(record.id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
        return Ok(());
    }
    let status = decode_dreamer_job_status(record.clone())?;
    put_run_tree_record_in_txn(
        vault,
        wtxn,
        &DreamerRunTreeRecord {
            job_id: status.job.id,
            parent_job: status.payload.parent_job,
            created_at: status.job.created_at,
        },
    )
}

fn put_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerRunTreeRecord,
) -> Result<()> {
    let encoded = encode_run_tree_record(record)?;
    let key = run_tree_key(record.job_id);
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
    let record = decode_budget_record(raw)?;
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
    child_job: JobId,
) -> Result<Option<DreamerBudgetReservation>> {
    let reservation_key = budget_reservation_key(budget_id, child_job)?;
    let Some(raw) = vault.store.vault_meta.get(txn, &reservation_key)? else {
        return Ok(None);
    };
    let reservation = decode_budget_reservation(raw)?;
    if reservation.budget_id != budget_id || reservation.job_id != child_job {
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
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.job_id)?;
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
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.job_id)?;
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
    job_id: JobId,
    milestone: DreamerMilestoneClaim,
) -> Result<()> {
    let value = encode_milestone_value(job_id, milestone.kind, milestone.occurred.start);
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

    let candidate_key = dreamer_milestone_candidate_key(&milestone);
    store.vault_meta.put(wtxn, &candidate_key, b"")?;
    store
        .vault_meta
        .put(wtxn, &dreamer_milestone_claim_key(claim_id), &candidate_key)?;
    Ok(())
}

pub(crate) fn deindex_dreamer_milestone_claim(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let claim_key = dreamer_milestone_claim_key(claim_id);
    let Some(candidate_key) = store.vault_meta.get(wtxn, &claim_key)?.map(<[u8]>::to_vec) else {
        return Ok(());
    };
    store.vault_meta.delete(wtxn, &candidate_key)?;
    store.vault_meta.delete(wtxn, &claim_key)?;
    Ok(())
}

fn latest_indexed_dreamer_milestone(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    job_id: JobId,
) -> Result<Option<DreamerDurableMilestone>> {
    let prefix = dreamer_milestone_candidate_prefix(job_id);
    let mut latest: Option<DreamerDurableMilestone> = None;
    for row in store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, _value) = row?;
        let Some(milestone) = indexed_dreamer_milestone_if_current(store, rtxn, key, job_id)?
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
    expected_job_id: JobId,
) -> Result<Option<DreamerDurableMilestone>> {
    let Ok((job_id, at, learned_at, claim_id)) = decode_dreamer_milestone_candidate_key(key) else {
        return Ok(None);
    };
    if job_id != expected_job_id {
        return Ok(None);
    }
    let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
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
    if milestone.job_id == job_id
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
    job_id: JobId,
) -> Result<Option<DreamerDurableMilestone>> {
    let mut milestones = Vec::new();
    for row in store.entities.iter(&*wtxn)? {
        let (key, raw) = row?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() == ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let Ok(key_bytes) = <[u8; 16]>::try_from(key) else {
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
        if milestone.job_id == job_id
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
    let Ok((job_id, kind, at)) = decode_milestone_value(&body.value) else {
        return None;
    };
    Some(DreamerDurableMilestone {
        claim_id: *claim_id,
        job_id,
        kind,
        at,
        learned_at,
    })
}

fn dreamer_milestone_candidate_prefix(job_id: JobId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX);
    key.extend_from_slice(job_id.as_bytes());
    key
}

fn dreamer_milestone_candidate_key(milestone: &DreamerDurableMilestone) -> Vec<u8> {
    let mut key = dreamer_milestone_candidate_prefix(milestone.job_id);
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

fn decode_dreamer_milestone_candidate_key(key: &[u8]) -> Result<(JobId, u64, u64, EntityId)> {
    if key.len() != DREAMER_MILESTONE_INDEX_CANDIDATE_KEY_LEN
        || !key.starts_with(DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX)
    {
        return Err(Error::CorruptedIndex("dreamer milestone index key"));
    }
    let mut cursor = DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX.len();
    let job_id = JobId::from_bytes(&key[cursor..cursor + 16])?;
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
    Ok((job_id, at, learned_at, claim_id))
}

fn encode_milestone_value(job_id: JobId, kind: DreamerMilestoneKind, at: u64) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_MILESTONE_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_JOB_ID), encode_job_id(job_id)),
        (Value::from(KEY_MILESTONE), Value::from(kind.as_str())),
        (Value::from(KEY_AT), Value::from(at)),
    ])
}

fn decode_milestone_value(value: &Value) -> Result<(JobId, DreamerMilestoneKind, u64)> {
    let entries = expect_map(value, "dreamer milestone value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_id = None;
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
            KEY_JOB_ID => job_id = Some(decode_job_id(value)?),
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
        job_id.ok_or(invalid_dreamer_runner(
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
pub fn dreamer_job_progress_key(job_id: JobId) -> String {
    let mut key = String::with_capacity(DREAMER_JOB_PROGRESS_KEY_PREFIX.len() + 32);
    key.push_str(DREAMER_JOB_PROGRESS_KEY_PREFIX);
    for byte in job_id.as_bytes() {
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

#[cfg(feature = "sync")]
fn encode_job_progress_value(
    update: &DreamerJobProgressUpdate,
) -> std::result::Result<LoroValue, TransportError> {
    update.validate()?;
    Ok(LoroValue::Map(
        vec![
            (
                KEY_SCHEMA_VERSION.to_owned(),
                LoroValue::I64(DREAMER_JOB_PROGRESS_VALUE_SCHEMA_VERSION),
            ),
            (
                KEY_JOB_ID.to_owned(),
                LoroValue::String(dreamer_job_id_hex(update.job_id).into()),
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
fn decode_job_progress_value(
    value: &LoroValue,
    expected_job_id: JobId,
) -> std::result::Result<DreamerJobProgressUpdate, TransportError> {
    let LoroValue::Map(entries) = value else {
        return Err(TransportError::InvalidPayload(
            "dreamer progress value must be a map",
        ));
    };
    if entries
        .keys()
        .any(|key| !DREAMER_JOB_PROGRESS_VALUE_KEYS.contains(&key.as_str()))
    {
        return Err(TransportError::InvalidPayload(
            "dreamer progress value key is not pinned",
        ));
    }

    let schema_version = expect_loro_i64(entries.get(KEY_SCHEMA_VERSION), KEY_SCHEMA_VERSION)?;
    if schema_version != DREAMER_JOB_PROGRESS_VALUE_SCHEMA_VERSION {
        return Err(TransportError::InvalidPayload(
            "unsupported dreamer progress schema_version",
        ));
    }

    let job_id = expect_loro_string(entries.get(KEY_JOB_ID), KEY_JOB_ID)?;
    if job_id != dreamer_job_id_hex(expected_job_id) {
        return Err(TransportError::InvalidPayload(
            "dreamer progress job_id mismatch",
        ));
    }

    let state =
        DreamerJobProgressState::parse(expect_loro_string(entries.get(KEY_STATE), KEY_STATE)?)
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

    let update = DreamerJobProgressUpdate {
        job_id: expected_job_id,
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
fn dreamer_job_id_hex(job_id: JobId) -> String {
    let mut out = String::with_capacity(32);
    for byte in job_id.as_bytes() {
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
        (Value::from(KEY_JOB_ID), encode_job_id(record.job_id)),
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
    let mut job_id = None;
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
            KEY_JOB_ID => {
                job_id = Some(decode_job_id(value)?);
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
        job_id: job_id.ok_or(invalid_dreamer_runner("missing dreamer job_id"))?,
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
        (Value::from(KEY_JOB_ID), encode_job_id(record.job_id)),
        (
            Value::from(KEY_PARENT_JOB),
            encode_optional_job_id(record.parent_job),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
    ]);
    encode_value(&value, "dreamer run-tree MessagePack encode failed")
}

fn decode_run_tree_record(bytes: &[u8]) -> Result<DreamerRunTreeRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer run-tree row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_id = None;
    let mut parent_job = None;
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
            KEY_JOB_ID => job_id = Some(decode_job_id(value)?),
            KEY_PARENT_JOB => parent_job = Some(decode_optional_job_id(value)?),
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
        job_id: job_id.ok_or(invalid_dreamer_runner("missing dreamer run-tree job_id"))?,
        parent_job: parent_job.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree parent_job",
        ))?,
        created_at: created_at.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree created_at",
        ))?,
    })
}

fn encode_parked_record(record: &DreamerParkedJobRecord) -> Result<Vec<u8>> {
    validate_park_reason(&record.reason)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_PARKED_SCHEMA_VERSION),
        ),
        (Value::from(KEY_JOB_ID), encode_job_id(record.job_id)),
        (Value::from(KEY_REASON), Value::from(record.reason.as_str())),
        (Value::from(KEY_PARKED_AT), Value::from(record.parked_at)),
    ]);
    encode_value(&value, "dreamer parked row MessagePack encode failed")
}

fn decode_parked_record(bytes: &[u8]) -> Result<DreamerParkedJobRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer parked row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_id = None;
    let mut reason = None;
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
            KEY_JOB_ID => job_id = Some(decode_job_id(value)?),
            KEY_REASON => {
                let parsed = expect_string(value, "dreamer parked reason must be a string")?;
                validate_park_reason(&parsed)?;
                reason = Some(parsed);
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

    Ok(DreamerParkedJobRecord {
        job_id: job_id.ok_or(invalid_dreamer_runner("missing dreamer parked job_id"))?,
        reason: reason.ok_or(invalid_dreamer_runner("missing dreamer parked reason"))?,
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

fn encode_job_id(job_id: JobId) -> Value {
    Value::Binary(job_id.as_bytes().to_vec())
}

fn decode_job_id(value: &Value) -> Result<JobId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_dreamer_runner("dreamer job id must be binary"));
    };
    JobId::from_bytes(bytes)
}

fn encode_optional_job_id(job_id: Option<JobId>) -> Value {
    job_id.map_or(Value::Nil, encode_job_id)
}

fn decode_optional_job_id(value: &Value) -> Result<Option<JobId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_job_id(value).map(Some)
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

fn budget_reservation_key(budget_id: &str, job_id: JobId) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let budget_id_len = u16::try_from(budget_id.len())
        .map_err(|_| invalid_dreamer_runner("dreamer budget_id exceeds 128 bytes"))?;
    let mut out = Vec::with_capacity(
        DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX.len() + 2 + budget_id.len() + 16,
    );
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX);
    out.extend_from_slice(&budget_id_len.to_be_bytes());
    out.extend_from_slice(budget_id.as_bytes());
    out.extend_from_slice(job_id.as_bytes());
    Ok(out)
}

fn run_tree_key(job_id: JobId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_RUN_TREE_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_RUN_TREE_PREFIX);
    out.extend_from_slice(job_id.as_bytes());
    out
}

fn parked_key(job_id: JobId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_PARKED_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_PARKED_PREFIX);
    out.extend_from_slice(job_id.as_bytes());
    out
}

fn validate_job_type(job_type: &str) -> Result<()> {
    if job_type.is_empty() {
        return Err(invalid_dreamer_runner("dreamer job_type must not be empty"));
    }
    if job_type.len() > MAX_DREAMER_JOB_TYPE_LEN {
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

fn validate_admission_input(input: &AdmitDreamerJob) -> Result<()> {
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
    Error::InvalidJobQueueRecord(reason)
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::job_queue::{CleanupJobLeases, JobInterventionKind, JobState, RetryJob};
    use crate::types::{
        ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, EdgeActorClass, VaultConfig, WriteActor,
        WriteProvenance,
    };

    use super::*;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    fn occurred(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn enqueue_job(
        runner: &DreamerRunnerStore<'_>,
        name: &str,
        now: u64,
    ) -> Result<DreamerJobStatus> {
        match runner.enqueue(EnqueueDreamerJob {
            job_type: name.to_owned(),
            input: Value::from(format!("input:{name}")),
            parent_job: None,
            dedupe_key: None,
            run_id: None,
            now,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => Ok(status),
        }
    }

    fn enqueue_consolidation_job(
        runner: &DreamerRunnerStore<'_>,
        scope: DreamerConsolidationScope,
        dedupe_key: Option<&str>,
        now: u64,
    ) -> Result<DreamerJobStatus> {
        match runner.enqueue_consolidation(EnqueueDreamerConsolidationJob {
            scope,
            input: Value::from(format!("input:{}", scope.as_str())),
            parent_job: None,
            dedupe_key: dedupe_key.map(str::to_owned),
            run_id: None,
            now,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => Ok(status),
        }
    }

    fn admit_consolidation(
        runner: &DreamerRunnerStore<'_>,
        scope: DreamerConsolidationScope,
        local_node_id: u64,
        lease_owner: &str,
        now: u64,
    ) -> Result<DreamerConsolidationAdmissionOutcome> {
        runner.admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope,
            local_node_id,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerJob {
                lease_owner: lease_owner.to_owned(),
                now,
                budget_id: format!("wake:{}", scope.as_str()),
                budget_total_units: 10,
                reserve_units: 1,
                started_milestone: None,
            },
        })
    }

    fn tournament_admission(
        predicate: &str,
        sample_count: u32,
        incumbent_confidence: f32,
        evidence_state: DreamerClaimEvidenceState,
        uncertainty_tau: f32,
        budget_axes: DreamerTournamentBudgetAxes,
    ) -> DreamerClaimAuthoringAdmission {
        DreamerClaimAuthoringAdmission::Tournament(DreamerTournamentAdmission {
            claim: DreamerTournamentClaim {
                predicate: predicate.to_owned(),
                sample_count,
                incumbent_confidence,
                evidence_state,
            },
            uncertainty_tau,
            budget_axes,
        })
    }

    fn different_node_id(node_id: u64) -> u64 {
        if node_id == u64::MAX { 1 } else { node_id + 1 }
    }

    fn test_ready_key(ready_at: u64, id: JobId) -> [u8; 24] {
        let mut key = [0_u8; 24];
        key[..8].copy_from_slice(&ready_at.to_be_bytes());
        key[8..].copy_from_slice(id.as_bytes());
        key
    }

    fn rewrite_ready_key(
        vault: &Vault,
        id: JobId,
        from_ready_at: u64,
        to_ready_at: u64,
    ) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_ready
            .delete(&mut wtxn, &test_ready_key(from_ready_at, id))?;
        vault
            .store
            .job_ready
            .put(&mut wtxn, &test_ready_key(to_ready_at, id), id.as_bytes())?;
        wtxn.commit()?;
        Ok(())
    }

    fn job_dedupe_points_to(vault: &Vault, id: JobId) -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault.store.job_dedupe.iter(&rtxn)? {
            let (_key, value) = row?;
            if value == id.as_bytes() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn milestone_fixture(
        vault: &Vault,
        claim_id: EntityId,
        at: u64,
    ) -> Result<DreamerMilestoneClaim> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")?;
        vault.put_entity(
            &subject,
            ENTITY_TYPE_TASK,
            occurred(at),
            at,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("dreamer-runner-test"))?,
            ClaimApprovalStatus::Approved,
        );
        Ok(DreamerMilestoneClaim {
            claim_id,
            subject,
            kind: DreamerMilestoneKind::Started,
            envelope,
            occurred: occurred(at),
            learned_at: at,
        })
    }

    #[cfg(feature = "sync")]
    fn write_milestone_for_job(
        vault: &Vault,
        job_id: JobId,
        claim_id: EntityId,
        kind: DreamerMilestoneKind,
        at: u64,
    ) -> Result<()> {
        let mut milestone = milestone_fixture(vault, claim_id, at)?;
        milestone.kind = kind;
        let mut wtxn = vault.store.env.write_txn()?;
        apply_milestone_claim_in_txn(vault, &mut wtxn, job_id, milestone)?;
        wtxn.commit()?;
        Ok(())
    }

    #[cfg(feature = "sync")]
    fn write_milestone_value_claim(
        vault: &Vault,
        claim_id: EntityId,
        value: Value,
        at: u64,
        stale: bool,
    ) -> Result<()> {
        let fixture = milestone_fixture(vault, claim_id, at)?;
        let candidate = crate::types::ClaimCandidate::new(
            DREAMER_MILESTONE_PREDICATE,
            ClaimSubject::Entity(fixture.subject),
            value,
            1.0,
        )
        .with_stale(stale);
        vault
            .batch()
            .claim_candidate(
                &claim_id,
                candidate,
                &fixture.envelope,
                occurred(at),
                fixture.learned_at,
            )
            .commit()
    }

    #[cfg(feature = "sync")]
    fn write_dreamer_boundary_claim(
        vault: &Vault,
        claim_id: EntityId,
        predicate: &'static str,
        at: u64,
    ) -> Result<()> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")?;
        vault.put_entity(
            &subject,
            ENTITY_TYPE_TASK,
            occurred(at),
            at,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("dreamer-sync-boundary-test"))?,
            ClaimApprovalStatus::Approved,
        );
        let candidate = crate::types::ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from(predicate),
            1.0,
        );
        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, occurred(at), at)
            .commit()
    }

    #[cfg(feature = "sync")]
    fn progress_update(
        job_id: JobId,
        state: DreamerJobProgressState,
        completed_units: u64,
        total_units: Option<u64>,
        updated_at_ms: u64,
    ) -> DreamerJobProgressUpdate {
        DreamerJobProgressUpdate {
            job_id,
            state,
            message: Some(format!("{}:{completed_units}", state.as_str())),
            completed_units,
            total_units,
            updated_at_ms,
        }
    }

    #[cfg(feature = "sync")]
    fn progress_i64(store: &crate::sync::EphemeralStore, key: &str, field: &str) -> i64 {
        let Some(crate::sync::LoroValue::Map(map)) = store.get(key) else {
            panic!("expected progress map for {key}");
        };
        let Some(crate::sync::LoroValue::I64(value)) = map.get(field) else {
            panic!("expected i64 field {field}");
        };
        *value
    }

    #[cfg(feature = "sync")]
    fn progress_str(store: &crate::sync::EphemeralStore, key: &str, field: &str) -> String {
        let Some(crate::sync::LoroValue::Map(map)) = store.get(key) else {
            panic!("expected progress map for {key}");
        };
        let Some(crate::sync::LoroValue::String(value)) = map.get(field) else {
            panic!("expected string field {field}");
        };
        value.to_string()
    }

    #[test]
    fn claim_authoring_strategy_defaults_to_single_pass() -> Result<()> {
        let admission = DreamerClaimAuthoringAdmission::default();

        assert_eq!(
            admission.strategy(),
            DreamerClaimAuthoringStrategy::SinglePass
        );
        assert_eq!(
            admission.gate_decision(DreamerClaimAuthoringBatchTier::batch())?,
            DreamerClaimAuthoringGateDecision::SinglePass(
                DreamerClaimAuthoringSinglePassReason::Strategy
            )
        );
        Ok(())
    }

    #[test]
    fn tournament_admission_class_axis_requires_pattern_claim_with_three_samples() -> Result<()> {
        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 2,
            reserve_units_per_step: 1,
        };

        for admission in [
            tournament_admission(
                "profile.preference",
                3,
                0.2,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            ),
            tournament_admission(
                "pattern.sleep",
                2,
                0.2,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            ),
        ] {
            assert_eq!(
                admission.gate_decision(DreamerClaimAuthoringBatchTier::batch())?,
                DreamerClaimAuthoringGateDecision::SinglePass(
                    DreamerClaimAuthoringSinglePassReason::Class
                )
            );
        }

        assert!(matches!(
            tournament_admission(
                "pattern.sleep",
                3,
                0.2,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            )
            .gate_decision(DreamerClaimAuthoringBatchTier::batch())?,
            DreamerClaimAuthoringGateDecision::Tournament(_)
        ));
        Ok(())
    }

    #[test]
    fn tournament_admission_uncertainty_axis_accepts_low_confidence_or_contested_evidence()
    -> Result<()> {
        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 2,
            reserve_units_per_step: 1,
        };

        assert_eq!(
            tournament_admission(
                "pattern.sleep",
                3,
                0.9,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            )
            .gate_decision(DreamerClaimAuthoringBatchTier::batch())?,
            DreamerClaimAuthoringGateDecision::SinglePass(
                DreamerClaimAuthoringSinglePassReason::Uncertainty
            )
        );
        assert!(matches!(
            tournament_admission(
                "pattern.sleep",
                3,
                0.4,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            )
            .gate_decision(DreamerClaimAuthoringBatchTier::batch())?,
            DreamerClaimAuthoringGateDecision::Tournament(_)
        ));
        assert!(matches!(
            tournament_admission(
                "pattern.sleep",
                3,
                0.9,
                DreamerClaimEvidenceState::Contested,
                0.7,
                axes,
            )
            .gate_decision(DreamerClaimAuthoringBatchTier::batch())?,
            DreamerClaimAuthoringGateDecision::Tournament(_)
        ));
        Ok(())
    }

    #[test]
    fn tournament_admission_schedule_axis_is_batch_tier_only() -> Result<()> {
        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 2,
            reserve_units_per_step: 1,
        };
        let tiers = [
            DreamerClaimAuthoringBatchTier::batch(),
            DreamerClaimAuthoringBatchTier::nightly(),
        ];
        assert_eq!(
            tiers.map(DreamerClaimAuthoringBatchTier::as_str),
            ["batch", "nightly"]
        );

        for tier in tiers {
            let decision = tournament_admission(
                "pattern.sleep",
                3,
                0.4,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            )
            .gate_decision(tier)?;
            assert!(matches!(
                decision,
                DreamerClaimAuthoringGateDecision::Tournament(grant)
                    if grant.schedule == tier.schedule()
            ));
        }
        Ok(())
    }

    #[test]
    fn tournament_budget_axes_use_one_lease_line_and_depletion_budget_traps() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued =
            enqueue_consolidation_job(&runner, DreamerConsolidationScope::Micro, None, 10)?;
        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 3,
            reserve_units_per_step: 2,
        };
        assert_eq!(axes.reserve_units()?, 12);

        let outcome = runner.admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: tournament_admission(
                "pattern.sleep",
                3,
                0.4,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            ),
            admission: AdmitDreamerJob {
                lease_owner: "tournament-worker".to_owned(),
                now: 20,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 11,
                reserve_units: 0,
                started_milestone: None,
            },
        })?;

        let DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(trap) = outcome else {
            panic!("tournament budget depletion must surface as BudgetTrap");
        };
        assert_eq!(trap.job_id, queued.job.id);
        assert_eq!(trap.budget_id, "wake:micro");
        assert_eq!(trap.required_units, 12);
        assert_eq!(trap.fanout_m, 2);
        assert_eq!(trap.depth_k, 3);
        assert_eq!(trap.budget.remaining_units, 11);
        assert_eq!(trap.budget.reserved_units, 0);
        assert_eq!(trap.intervention_effect, JobInterventionEffect::Paused);
        assert!(
            runner.budget("wake:micro")?.is_none(),
            "BudgetTrap must not commit an initialized budget row"
        );
        assert!(
            runner
                .budget_reservation("wake:micro", queued.job.id)?
                .is_none(),
            "BudgetTrap must not create a tournament lease"
        );

        let status = runner.status(queued.job.id)?.expect("paused job");
        assert_eq!(status.job.state, JobState::Paused);
        assert_eq!(status.job.attempt_count, 0);
        assert!(status.job.lease_owner.is_none());
        assert_eq!(status.job.events.len(), 1);
        assert_eq!(status.job.events[0].kind, JobInterventionKind::Pause);
        assert_eq!(
            status.job.events[0].actor,
            DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR
        );
        assert_eq!(
            status.job.events[0].note.as_deref(),
            Some(DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE)
        );
        Ok(())
    }

    #[test]
    fn tournament_admission_tops_up_existing_reservation_before_leasing() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queue = JobQueue::new(&vault);
        let queued =
            enqueue_consolidation_job(&runner, DreamerConsolidationScope::Micro, None, 10)?;

        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            first,
        )) = runner.admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerJob {
                lease_owner: "single-pass-worker".to_owned(),
                now: 20,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 12,
                reserve_units: 8,
                started_milestone: None,
            },
        })?
        else {
            panic!("expected initial single-pass admission");
        };
        assert_eq!(first.status.job.id, queued.job.id);
        assert_eq!(first.budget.remaining_units, 4);
        assert_eq!(first.reservation.reserved_units, 8);

        queue.retry(RetryJob {
            id: queued.job.id,
            lease_owner: "single-pass-worker".to_owned(),
            attempt_count: first.status.job.attempt_count,
            backoff_until: 25,
            last_error: Some("lease_timeout".to_owned()),
            now: 24,
        })?;

        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 3,
            reserve_units_per_step: 2,
        };
        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            second,
        )) = runner.admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::nightly(),
            claim_authoring: tournament_admission(
                "pattern.sleep",
                3,
                0.4,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            ),
            admission: AdmitDreamerJob {
                lease_owner: "tournament-worker".to_owned(),
                now: 30,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 12,
                reserve_units: 0,
                started_milestone: None,
            },
        })?
        else {
            panic!("expected tournament admission after reservation top-up");
        };

        assert_eq!(second.status.job.id, queued.job.id);
        assert_eq!(second.status.job.attempt_count, 2);
        assert_eq!(second.budget.remaining_units, 0);
        assert_eq!(second.budget.reserved_units, 12);
        assert_eq!(second.reservation.reserved_units, 12);
        assert_eq!(second.reservation.updated_at, 30);
        assert_eq!(
            runner.budget_reservation("wake:micro", queued.job.id)?,
            Some(second.reservation)
        );
        Ok(())
    }

    #[test]
    fn tournament_admission_budget_traps_when_existing_reservation_cannot_top_up() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queue = JobQueue::new(&vault);
        let queued =
            enqueue_consolidation_job(&runner, DreamerConsolidationScope::Micro, None, 10)?;

        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            first,
        )) = runner.admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerJob {
                lease_owner: "single-pass-worker".to_owned(),
                now: 20,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 11,
                reserve_units: 8,
                started_milestone: None,
            },
        })?
        else {
            panic!("expected initial single-pass admission");
        };
        let first_budget = first.budget.clone();
        let first_reservation = first.reservation.clone();
        queue.retry(RetryJob {
            id: queued.job.id,
            lease_owner: "single-pass-worker".to_owned(),
            attempt_count: first.status.job.attempt_count,
            backoff_until: 25,
            last_error: Some("lease_timeout".to_owned()),
            now: 24,
        })?;

        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 3,
            reserve_units_per_step: 2,
        };
        let DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(trap) = runner
            .admit_next_consolidation(AdmitDreamerConsolidationJob {
                scope: DreamerConsolidationScope::Micro,
                local_node_id: 77,
                claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                claim_authoring: tournament_admission(
                    "pattern.sleep",
                    3,
                    0.4,
                    DreamerClaimEvidenceState::Uncontested,
                    0.7,
                    axes,
                ),
                admission: AdmitDreamerJob {
                    lease_owner: "tournament-worker".to_owned(),
                    now: 30,
                    budget_id: "wake:micro".to_owned(),
                    budget_total_units: 11,
                    reserve_units: 0,
                    started_milestone: None,
                },
            })?
        else {
            panic!("expected tournament BudgetTrap on insufficient top-up");
        };

        assert_eq!(trap.job_id, queued.job.id);
        assert_eq!(trap.required_units, 12);
        assert_eq!(trap.budget, first_budget);
        assert_eq!(runner.budget("wake:micro")?, Some(first_budget));
        assert_eq!(
            runner.budget_reservation("wake:micro", queued.job.id)?,
            Some(first_reservation)
        );
        let status = runner.status(queued.job.id)?.expect("paused job");
        assert_eq!(status.job.state, JobState::Paused);
        assert_eq!(status.job.attempt_count, 1);
        Ok(())
    }

    #[test]
    fn tournament_budget_trap_uses_authoritative_candidate_after_ready_repairs() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queue = JobQueue::new(&vault);

        let reserved =
            enqueue_consolidation_job(&runner, DreamerConsolidationScope::Micro, None, 10)?;
        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            first,
        )) = runner.admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerJob {
                lease_owner: "reserved-worker".to_owned(),
                now: 20,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 10,
                reserve_units: 10,
                started_milestone: None,
            },
        })?
        else {
            panic!("expected reserved admission");
        };
        queue.retry(RetryJob {
            id: reserved.job.id,
            lease_owner: "reserved-worker".to_owned(),
            attempt_count: first.status.job.attempt_count,
            backoff_until: 2,
            last_error: Some("lease_timeout".to_owned()),
            now: 21,
        })?;

        let stale = enqueue_consolidation_job(&runner, DreamerConsolidationScope::Micro, None, 30)?;
        let ClaimOutcome::Claimed(stale_claim) = queue.claim_kind(
            DreamerConsolidationScope::Micro.job_kind(),
            ClaimJob {
                lease_owner: "stale-prep".to_owned(),
                now: 31,
            },
        )?
        else {
            panic!("expected to claim stale fixture job");
        };
        assert_eq!(stale_claim.id, stale.job.id);
        queue.retry(RetryJob {
            id: stale.job.id,
            lease_owner: "stale-prep".to_owned(),
            attempt_count: stale_claim.attempt_count,
            backoff_until: 1,
            last_error: Some("lease_timeout".to_owned()),
            now: 32,
        })?;
        rewrite_ready_key(&vault, stale.job.id, 1, 0)?;

        let axes = DreamerTournamentBudgetAxes {
            fanout_m: 2,
            depth_k: 3,
            reserve_units_per_step: 2,
        };
        let DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(trap) = runner
            .admit_next_consolidation(AdmitDreamerConsolidationJob {
                scope: DreamerConsolidationScope::Micro,
                local_node_id: 77,
                claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                claim_authoring: tournament_admission(
                    "pattern.sleep",
                    3,
                    0.4,
                    DreamerClaimEvidenceState::Uncontested,
                    0.7,
                    axes,
                ),
                admission: AdmitDreamerJob {
                    lease_owner: "tournament-worker".to_owned(),
                    now: 40,
                    budget_id: "wake:micro".to_owned(),
                    budget_total_units: 10,
                    reserve_units: 0,
                    started_milestone: None,
                },
            })?
        else {
            panic!("expected tournament BudgetTrap for stale ready candidate");
        };

        assert_eq!(trap.job_id, stale.job.id);
        assert_eq!(trap.budget.remaining_units, 0);
        assert_eq!(trap.budget.reserved_units, 10);
        let stale_status = runner.status(stale.job.id)?.expect("paused stale job");
        assert_eq!(stale_status.job.state, JobState::Paused);
        let reserved_status = runner.status(reserved.job.id)?.expect("reserved job");
        assert_eq!(reserved_status.job.state, JobState::Queued);
        assert_eq!(
            runner.budget_reservation("wake:micro", reserved.job.id)?,
            Some(first.reservation)
        );
        Ok(())
    }

    #[test]
    fn dreamer_payload_round_trips_with_pinned_keys() -> Result<()> {
        let payload = DreamerJobPayload {
            job_type: "expand".to_owned(),
            input: Value::from("seed"),
            parent_job: None,
        };
        let encoded = encode_dreamer_job_payload(&payload)?;
        let decoded = decode_dreamer_job_payload(&encoded)?;
        assert_eq!(decoded, payload);
        assert_eq!(
            DREAMER_JOB_PAYLOAD_KEYS,
            ["schema_version", "job_type", "input", "parent_job"]
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_progress_producer_throttles_and_reuses_one_ephemeral_key() {
        use crate::sync::{EphemeralStore, TAG_EPHEMERAL, decode_ephemeral_states};

        let store = EphemeralStore::new(30_000);
        let mut producer = DreamerJobProgressProducer::new();
        let job_id = JobId::now();
        let key = dreamer_job_progress_key(job_id);

        let first = producer
            .publish(
                &store,
                progress_update(job_id, DreamerJobProgressState::Running, 1, Some(4), 1_000),
            )
            .expect("first progress update encodes")
            .expect("first progress update emits");
        assert_eq!(first[0], TAG_EPHEMERAL);
        let states = decode_ephemeral_states(&first[1..]).expect("decode progress frame");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].key, key);
        assert_eq!(store.keys(), vec![key.clone()]);
        assert_eq!(progress_i64(&store, &key, KEY_COMPLETED_UNITS), 1);

        let throttled = producer
            .publish(
                &store,
                progress_update(job_id, DreamerJobProgressState::Running, 2, Some(4), 1_500),
            )
            .expect("throttled progress update validates");
        assert!(
            throttled.is_none(),
            "second update inside the 1s window must not emit"
        );
        assert_eq!(
            progress_i64(&store, &key, KEY_COMPLETED_UNITS),
            1,
            "throttled update must not mutate the existing row"
        );

        let second = producer
            .publish(
                &store,
                progress_update(job_id, DreamerJobProgressState::Running, 3, Some(4), 2_000),
            )
            .expect("second progress update encodes")
            .expect("second progress update emits");
        let states = decode_ephemeral_states(&second[1..]).expect("decode second progress frame");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].key, key);
        assert_eq!(
            store.keys(),
            vec![key.clone()],
            "progress must remain one mutable key"
        );
        assert_eq!(progress_i64(&store, &key, KEY_COMPLETED_UNITS), 3);
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_runner_transitions_drive_job_progress_producer() -> Result<()> {
        use crate::sync::{EphemeralStore, TAG_EPHEMERAL};

        let (_tmp, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        enqueue_job(&runner, "runner-progress", 10)?;
        let store = EphemeralStore::new(30_000);
        let mut producer = DreamerJobProgressProducer::new();

        let admitted = runner.admit_next_with_progress(
            AdmitDreamerJob {
                lease_owner: "worker-a".to_owned(),
                now: 20,
                budget_id: "wake".to_owned(),
                budget_total_units: 20,
                reserve_units: 8,
                started_milestone: None,
            },
            &mut producer,
            &store,
        )?;
        let Some(frame) = admitted.frame.as_ref() else {
            panic!("admission must emit a live progress frame");
        };
        assert_eq!(frame[0], TAG_EPHEMERAL);
        let DreamerAdmissionOutcome::Admitted(admitted_job) = admitted.outcome else {
            panic!("expected admitted job");
        };
        let job_id = admitted_job.status.job.id;
        let key = dreamer_job_progress_key(job_id);
        assert_eq!(store.keys(), vec![key.clone()]);
        assert_eq!(
            progress_str(&store, &key, KEY_STATE),
            DreamerJobProgressState::Started.as_str()
        );
        assert_eq!(progress_i64(&store, &key, KEY_TOTAL_UNITS), 8);

        let completed = runner.complete_with_progress(
            CompleteDreamerJob {
                id: job_id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: admitted_job.status.job.attempt_count,
                now: 30,
            },
            &mut producer,
            &store,
        )?;
        assert!(
            matches!(completed.outcome, CompleteDreamerJobOutcome::Completed(_)),
            "terminal queue transition should complete the leased job"
        );
        assert!(
            completed.frame.is_some(),
            "terminal progress must overwrite the live row"
        );
        assert_eq!(
            progress_str(&store, &key, KEY_STATE),
            DreamerJobProgressState::Done.as_str()
        );
        assert_eq!(
            runner.status(job_id)?.expect("completed job").job.state,
            JobState::Completed
        );

        let post_terminal = runner.publish_progress(
            &mut producer,
            &store,
            progress_update(job_id, DreamerJobProgressState::Running, 1, Some(8), 30_500),
        )?;
        assert!(
            post_terminal.is_none(),
            "runner must stop live ticks after terminal state"
        );
        assert_eq!(
            progress_str(&store, &key, KEY_STATE),
            DreamerJobProgressState::Done.as_str(),
            "post-terminal tick must not mutate the terminal live row"
        );

        producer.remove_outdated(&store, 61_000);
        let post_terminal_after_marker_ttl = runner.publish_progress(
            &mut producer,
            &store,
            progress_update(job_id, DreamerJobProgressState::Running, 2, Some(8), 61_000),
        )?;
        assert!(
            post_terminal_after_marker_ttl.is_none(),
            "durable terminal queue state must prevent progress revival after stop-marker TTL"
        );
        assert_eq!(
            progress_str(&store, &key, KEY_STATE),
            DreamerJobProgressState::Done.as_str(),
            "post-marker tick must still not mutate the terminal live row"
        );

        Ok(())
    }

    #[test]
    fn dreamer_complete_fail_reject_non_dreamer_queue_rows_before_mutation() -> Result<()> {
        let (_tmp, vault) = open_vault();
        let queue = crate::job_queue::JobQueue::new(&vault);
        let companion = match queue.enqueue(crate::job_queue::EnqueueJob {
            kind: "companion".to_owned(),
            payload: b"not-dreamer".to_vec(),
            dedupe_key: None,
            run_id: None,
            now: 10,
        })? {
            crate::job_queue::EnqueueOutcome::Enqueued(record)
            | crate::job_queue::EnqueueOutcome::Existing(record) => record,
        };
        let crate::job_queue::ClaimOutcome::Claimed(claimed) = queue.claim_kind(
            "companion",
            crate::job_queue::ClaimJob {
                lease_owner: "worker-a".to_owned(),
                now: 11,
            },
        )?
        else {
            panic!("expected companion job to be leased");
        };
        assert_eq!(claimed.id, companion.id);

        let runner = DreamerRunnerStore::new(&vault);
        runner
            .complete(CompleteDreamerJob {
                id: claimed.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: claimed.attempt_count,
                now: 12,
            })
            .expect_err("non-Dreamer queue row must be rejected before complete");
        assert_eq!(
            queue.get(claimed.id)?.expect("companion row remains").state,
            JobState::Leased,
            "complete guard must not mutate the generic queue row"
        );

        runner
            .fail(FailDreamerJob {
                id: claimed.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: claimed.attempt_count,
                reason: "should-not-commit".to_owned(),
                now: 13,
            })
            .expect_err("non-Dreamer queue row must be rejected before fail");
        assert_eq!(
            queue.get(claimed.id)?.expect("companion row remains").state,
            JobState::Leased,
            "fail guard must not mutate the generic queue row"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_fail_with_progress_bounds_terminal_reason_message() -> Result<()> {
        use crate::sync::EphemeralStore;

        let (_tmp, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        enqueue_job(&runner, "runner-progress-fail", 10)?;
        let store = EphemeralStore::new(30_000);
        let mut producer = DreamerJobProgressProducer::new();
        let admitted = runner.admit_next_with_progress(
            AdmitDreamerJob {
                lease_owner: "worker-a".to_owned(),
                now: 20,
                budget_id: "wake".to_owned(),
                budget_total_units: 20,
                reserve_units: 8,
                started_milestone: None,
            },
            &mut producer,
            &store,
        )?;
        let DreamerAdmissionOutcome::Admitted(admitted_job) = admitted.outcome else {
            panic!("expected admitted job");
        };
        let job_id = admitted_job.status.job.id;
        let reason = "x".repeat(MAX_DREAMER_PROGRESS_MESSAGE_LEN + 88);

        let failed = runner.fail_with_progress(
            FailDreamerJob {
                id: job_id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: admitted_job.status.job.attempt_count,
                reason: reason.clone(),
                now: 30,
            },
            &mut producer,
            &store,
        )?;
        assert!(
            matches!(failed.outcome, FailDreamerJobOutcome::Failed(_)),
            "durable failure transition should commit"
        );
        assert!(
            failed.frame.is_some(),
            "terminal failure should publish a bounded terminal row"
        );
        let key = dreamer_job_progress_key(job_id);
        assert_eq!(
            progress_str(&store, &key, KEY_STATE),
            DreamerJobProgressState::Failed.as_str()
        );
        let message = progress_str(&store, &key, KEY_MESSAGE);
        assert_eq!(message.len(), MAX_DREAMER_PROGRESS_MESSAGE_LEN);
        assert_eq!(message, reason[..MAX_DREAMER_PROGRESS_MESSAGE_LEN]);

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_progress_terminal_stop_ages_out_on_housekeeping() -> Result<()> {
        use crate::sync::EphemeralStore;

        let store = EphemeralStore::new(5);
        let mut producer = DreamerJobProgressProducer::with_limits(1_000, 1_000)?;
        let job_id = JobId::now();
        let key = dreamer_job_progress_key(job_id);

        assert!(
            producer
                .publish(
                    &store,
                    progress_update(job_id, DreamerJobProgressState::Running, 1, Some(2), 1_000),
                )
                .expect("running progress encodes")
                .is_some()
        );
        assert!(store.get(&key).is_some());

        let terminal = producer
            .publish(
                &store,
                progress_update(job_id, DreamerJobProgressState::Done, 2, Some(2), 1_200),
            )
            .expect("terminal progress validates");
        assert!(
            terminal.is_some(),
            "terminal state must overwrite the mutable live row"
        );
        assert_eq!(
            progress_i64(&store, &key, KEY_COMPLETED_UNITS),
            2,
            "terminal stop leaves a terminal row for TTL ageout"
        );
        assert_eq!(
            progress_str(&store, &key, KEY_STATE),
            DreamerJobProgressState::Done.as_str()
        );

        let post_terminal = producer
            .publish(
                &store,
                progress_update(job_id, DreamerJobProgressState::Running, 2, Some(2), 1_500),
            )
            .expect("post-terminal progress validates");
        assert!(
            post_terminal.is_none(),
            "producer must not resume ticking after terminal state"
        );

        std::thread::sleep(std::time::Duration::from_millis(10));
        producer.remove_outdated(&store, 1_510);
        assert!(
            store.get(&key).is_none(),
            "runner housekeeping must drive ephemeral TTL ageout"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_progress_falls_back_to_durable_milestone_when_live_row_unreachable() -> Result<()> {
        use crate::sync::EphemeralStore;

        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        write_milestone_for_job(
            &vault,
            queued.job.id,
            EntityId::now(),
            DreamerMilestoneKind::Started,
            20,
        )?;
        let done_claim = EntityId::now();
        write_milestone_for_job(
            &vault,
            queued.job.id,
            done_claim,
            DreamerMilestoneKind::Done,
            30,
        )?;
        write_milestone_value_claim(
            &vault,
            EntityId::now(),
            Value::from("malformed milestone value"),
            40,
            false,
        )?;
        write_milestone_value_claim(
            &vault,
            EntityId::now(),
            encode_milestone_value(queued.job.id, DreamerMilestoneKind::Failed, 50),
            50,
            true,
        )?;

        let live_store = EphemeralStore::new(5);
        assert!(
            live_store
                .get(&dreamer_job_progress_key(queued.job.id))
                .is_none(),
            "fixture represents an unreachable executing device"
        );

        let durable = runner
            .latest_durable_milestone(queued.job.id)?
            .expect("durable milestone fallback");
        assert_eq!(durable.claim_id, done_claim);
        assert_eq!(durable.kind, DreamerMilestoneKind::Done);

        let mut malformed_index_key = dreamer_milestone_candidate_prefix(queued.job.id);
        malformed_index_key.extend_from_slice(b"truncated");
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, &malformed_index_key, b"bad")?;
            Ok(())
        })?;

        live_store.set(
            &dreamer_job_progress_key(queued.job.id),
            crate::sync::LoroValue::String("corrupt".into()),
        );
        let snapshot = runner
            .progress_snapshot(&live_store, queued.job.id)?
            .expect("durable progress snapshot");
        assert_eq!(snapshot.source, DreamerJobProgressSource::DurableMilestone);
        assert_eq!(snapshot.state, DreamerJobProgressState::Done);
        assert_eq!(snapshot.updated_at_ms, 30_000);

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_durable_milestone_lookup_uses_job_index() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        let started_claim = EntityId::now();
        write_milestone_for_job(
            &vault,
            queued.job.id,
            started_claim,
            DreamerMilestoneKind::Started,
            20,
        )?;
        let done_claim = EntityId::now();
        write_milestone_for_job(
            &vault,
            queued.job.id,
            done_claim,
            DreamerMilestoneKind::Done,
            30,
        )?;
        for offset in 0..8 {
            write_dreamer_boundary_claim(&vault, EntityId::now(), "dreamer.effect", 100 + offset)?;
        }

        assert!(
            runner.latest_durable_milestone(queued.job.id)?.is_some(),
            "first lookup backfills the legacy milestone index"
        );
        crate::claim::reset_claim_body_decode_count();
        let durable = runner
            .latest_durable_milestone(queued.job.id)?
            .expect("durable milestone fallback");
        assert_eq!(durable.claim_id, done_claim);
        assert_eq!(durable.kind, DreamerMilestoneKind::Done);
        assert_eq!(
            crate::claim::claim_body_decode_count(),
            2,
            "indexed lookup should decode only this job's milestone candidates"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_durable_milestone_index_invalidates_lifecycle_and_soft_delete() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        let started_claim = EntityId::now();
        write_milestone_for_job(
            &vault,
            queued.job.id,
            started_claim,
            DreamerMilestoneKind::Started,
            20,
        )?;
        let done_claim = EntityId::now();
        write_milestone_for_job(
            &vault,
            queued.job.id,
            done_claim,
            DreamerMilestoneKind::Done,
            30,
        )?;
        assert!(
            runner.latest_durable_milestone(queued.job.id)?.is_some(),
            "first lookup backfills the legacy milestone index"
        );

        vault.retract_claim(&done_claim, 35)?;
        crate::claim::reset_claim_body_decode_count();
        let durable = runner
            .latest_durable_milestone(queued.job.id)?
            .expect("started milestone remains eligible");
        assert_eq!(durable.claim_id, started_claim);
        assert_eq!(durable.kind, DreamerMilestoneKind::Started);
        assert_eq!(
            crate::claim::claim_body_decode_count(),
            1,
            "retracted latest claim must be removed from the per-job index"
        );

        let outcome = vault
            .delete_entity_with_reason(&started_claim, crate::deletion::DeleteReason::UserDelete)?;
        assert!(outcome.existed);
        assert!(
            runner.latest_durable_milestone(queued.job.id)?.is_none(),
            "soft-deleted milestone claim must be removed from the fallback index"
        );

        crate::claim::reset_claim_body_decode_count();
        assert!(
            runner.latest_durable_milestone(queued.job.id)?.is_none(),
            "legacy backfill marker should preserve the empty result"
        );
        assert_eq!(
            crate::claim::claim_body_decode_count(),
            0,
            "empty indexed result should not rescan durable claims after backfill"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_durable_milestone_backfill_fails_closed_on_malformed_claim_body() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        write_milestone_for_job(
            &vault,
            queued.job.id,
            EntityId::now(),
            DreamerMilestoneKind::Started,
            20,
        )?;

        let corrupt_claim = EntityId::now();
        let mut raw = Vec::new();
        raw.push(ENTITY_TYPE_CLAIM);
        raw.extend_from_slice(&25_u64.to_be_bytes());
        raw.extend_from_slice(&25_u64.to_be_bytes());
        raw.extend_from_slice(&25_u64.to_be_bytes());
        raw.extend_from_slice(b"not a claim body");
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .entities
                .put(wtxn, corrupt_claim.as_bytes(), &raw)?;
            Ok(())
        })?;

        runner
            .latest_durable_milestone(queued.job.id)
            .expect_err("malformed claim body must fail the one-time backfill");
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, DREAMER_MILESTONE_INDEX_BACKFILLED_KEY)?
                .is_none(),
            "failed backfill must not mark the milestone index complete"
        );

        Ok(())
    }

    #[test]
    fn dreamer_home_node_election_order_persists_and_reelects() -> Result<()> {
        let (dir, vault) = open_vault();
        let (primary, always_on, cloud) = {
            let runner = DreamerRunnerStore::new(&vault);
            let local = runner.local_home_node_candidate(true, true, false)?;
            assert_ne!(local.node_id, 0);
            assert_eq!(
                runner
                    .local_home_node_candidate(false, true, false)?
                    .node_id,
                local.node_id,
                "local candidate uses the stable sync device identity"
            );

            let primary = DreamerHomeNodeCandidate::primary_device(30);
            let always_on = DreamerHomeNodeCandidate::always_on_local(20);
            let cloud_detached = DreamerHomeNodeCandidate::cloud(10, false);
            let elected = runner
                .elect_home_node(&[primary, cloud_detached, always_on], 100)?
                .expect("always-on local is eligible");
            assert_eq!(elected.node_id, 20);
            assert_eq!(elected.class, DreamerHomeNodeClass::AlwaysOnLocal);
            assert_eq!(runner.home_node_designation()?, Some(elected));

            let cloud_attached = DreamerHomeNodeCandidate::cloud(10, true);
            let cloud = runner
                .elect_home_node(&[primary, always_on, cloud_attached], 110)?
                .expect("attached cloud wins");
            assert_eq!(cloud.node_id, 10);
            assert_eq!(cloud.class, DreamerHomeNodeClass::CloudAttached);
            assert_eq!(
                [primary, always_on, cloud_attached]
                    .into_iter()
                    .filter(|candidate| candidate.node_id == cloud.node_id)
                    .count(),
                1,
                "exactly one candidate holds the MACRO designation"
            );
            (primary, always_on, cloud)
        };
        drop(vault);

        let reopened = Vault::open(dir.path(), VaultConfig::device())?;
        let reopened_runner = DreamerRunnerStore::new(&reopened);
        assert_eq!(
            reopened_runner.home_node_designation()?,
            Some(cloud),
            "designation survives restart"
        );

        let re_elected = reopened_runner
            .elect_home_node(&[primary, always_on], 120)?
            .expect("always-on local wins after cloud loss");
        assert_eq!(re_elected.node_id, 20);
        assert_eq!(re_elected.class, DreamerHomeNodeClass::AlwaysOnLocal);

        let fallback = reopened_runner
            .elect_home_node(&[primary], 130)?
            .expect("primary is the last v1 fallback");
        assert_eq!(fallback.node_id, 30);
        assert_eq!(fallback.class, DreamerHomeNodeClass::PrimaryDevice);

        assert!(reopened_runner.elect_home_node(&[], 140)?.is_none());
        assert!(
            reopened_runner.home_node_designation()?.is_none(),
            "no eligible candidates clears a stale designation"
        );
        Ok(())
    }

    #[test]
    fn dreamer_micro_meso_consolidation_uses_advisory_per_device_dedupe() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);

        let micro = enqueue_consolidation_job(
            &runner,
            DreamerConsolidationScope::Micro,
            Some("device-a:claim-1"),
            10,
        )?;
        let micro_again = enqueue_consolidation_job(
            &runner,
            DreamerConsolidationScope::Micro,
            Some("device-a:claim-1"),
            11,
        )?;
        assert_eq!(micro_again.job.id, micro.job.id);
        assert_eq!(micro_again.job.kind, DREAMER_CONSOLIDATION_MICRO_JOB_KIND);

        let meso = enqueue_consolidation_job(
            &runner,
            DreamerConsolidationScope::Meso,
            Some("device-a:claim-1"),
            12,
        )?;
        assert_ne!(
            meso.job.id, micro.job.id,
            "advisory dedupe is scoped by consolidation lane, not a global lock"
        );
        assert_eq!(meso.job.kind, DREAMER_CONSOLIDATION_MESO_JOB_KIND);

        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted_micro,
        )) = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Micro,
            77,
            "micro-worker",
            20,
        )?
        else {
            panic!("MICRO should admit per-device without a home node");
        };
        assert_eq!(
            admitted_micro.status.job.kind,
            DREAMER_CONSOLIDATION_MICRO_JOB_KIND
        );

        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted_meso,
        )) = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Meso,
            77,
            "meso-worker",
            21,
        )?
        else {
            panic!("MESO should admit per-device without a home node");
        };
        assert_eq!(
            admitted_meso.status.job.kind,
            DREAMER_CONSOLIDATION_MESO_JOB_KIND
        );
        assert!(runner.home_node_designation()?.is_none());
        Ok(())
    }

    #[test]
    fn dreamer_macro_consolidation_admits_only_the_elected_home_node() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let local = runner.local_home_node_candidate(true, true, false)?;
        let primary = DreamerHomeNodeCandidate::primary_device(different_node_id(local.node_id));
        let designation = runner
            .elect_home_node(&[primary, local], 100)?
            .expect("always-on local wins");
        assert_eq!(designation.node_id, local.node_id);

        let macro_job = enqueue_consolidation_job(
            &runner,
            DreamerConsolidationScope::Macro,
            Some("home-macro:bucket-pair"),
            10,
        )?;

        let non_home = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            primary.node_id,
            "primary",
            20,
        );
        assert!(matches!(
            non_home,
            Err(Error::InvalidJobQueueRecord(
                "dreamer local node_id does not match vault identity"
            ))
        ));
        let still_queued = runner.status(macro_job.job.id)?.expect("macro job");
        assert_eq!(still_queued.job.state, JobState::Queued);
        assert_eq!(still_queued.job.attempt_count, 0);

        let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            local.node_id,
            "home",
            21,
        )?
        else {
            panic!("elected home node should admit MACRO consolidation");
        };
        assert_eq!(admitted.status.job.id, macro_job.job.id);
        assert_eq!(
            admitted.status.job.kind,
            DREAMER_CONSOLIDATION_MACRO_JOB_KIND
        );
        assert_eq!(admitted.status.job.lease_owner.as_deref(), Some("home"));
        Ok(())
    }

    #[test]
    fn dreamer_macro_consolidation_rejects_spoofed_remote_home_node_id() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let local = runner.local_home_node_candidate(true, false, true)?;
        let remote_home = DreamerHomeNodeCandidate::cloud(different_node_id(local.node_id), true);
        let designation = runner
            .elect_home_node(&[local, remote_home], 100)?
            .expect("attached cloud wins");
        assert_eq!(designation.node_id, remote_home.node_id);

        let macro_job =
            enqueue_consolidation_job(&runner, DreamerConsolidationScope::Macro, None, 10)?;

        let spoofed_home_id = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            designation.node_id,
            "spoof",
            20,
        );
        assert!(matches!(
            spoofed_home_id,
            Err(Error::InvalidJobQueueRecord(
                "dreamer local node_id does not match vault identity"
            ))
        ));

        let honest_local = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            local.node_id,
            "local",
            21,
        )?;
        assert_eq!(
            honest_local,
            DreamerConsolidationAdmissionOutcome::NotHomeNode(designation)
        );
        let still_queued = runner.status(macro_job.job.id)?.expect("macro job");
        assert_eq!(still_queued.job.state, JobState::Queued);
        assert_eq!(still_queued.job.attempt_count, 0);
        Ok(())
    }

    #[test]
    fn dreamer_macro_consolidation_without_home_does_not_claim() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let local = runner.local_home_node_candidate(true, true, false)?;
        let macro_job =
            enqueue_consolidation_job(&runner, DreamerConsolidationScope::Macro, None, 10)?;

        let outcome = admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            local.node_id,
            "worker",
            20,
        )?;
        assert_eq!(outcome, DreamerConsolidationAdmissionOutcome::NoHomeNode);
        let still_queued = runner.status(macro_job.job.id)?.expect("macro job");
        assert_eq!(still_queued.job.state, JobState::Queued);
        assert_eq!(still_queued.job.attempt_count, 0);
        Ok(())
    }

    #[test]
    fn dreamer_admission_claims_job_reserves_budget_and_writes_started_milestone_atomically()
    -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        let claim_id = EntityId::now();
        let milestone = milestone_fixture(&vault, claim_id, 20)?;
        let milestone_subject = milestone.subject;

        let admitted = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 4,
            started_milestone: Some(milestone),
        })?;

        let DreamerAdmissionOutcome::Admitted(admitted) = admitted else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.status.job.id, queued.job.id);
        assert_eq!(admitted.status.job.state, JobState::Leased);
        assert_eq!(
            admitted.status.job.lease_owner.as_deref(),
            Some("dreamer-worker")
        );
        assert_eq!(admitted.status.job.attempt_count, 1);
        assert_eq!(admitted.budget.remaining_units, 6);
        assert_eq!(admitted.budget.reserved_units, 4);
        assert_eq!(admitted.reservation.budget_id, "wake");
        assert_eq!(admitted.reservation.job_id, queued.job.id);
        assert_eq!(admitted.reservation.reserved_units, 4);

        let stored_budget = runner.budget("wake")?.expect("budget row");
        assert_eq!(stored_budget, admitted.budget);
        assert_eq!(runner.remaining_budget("wake")?, Some(6));
        assert_eq!(
            runner.budget_reservation("wake", queued.job.id)?,
            Some(admitted.reservation)
        );
        let stored_claim = vault
            .get_claim(&claim_id)?
            .expect("started milestone claim");
        assert_eq!(stored_claim.predicate, DREAMER_MILESTONE_PREDICATE);
        assert_eq!(
            stored_claim.subject,
            ClaimSubject::Entity(milestone_subject)
        );
        assert_eq!(stored_claim.approval, ClaimApprovalStatus::Approved);

        let Value::Map(entries) = stored_claim.value else {
            panic!("milestone value must be a map");
        };
        assert!(entries.iter().any(|(key, value)| {
            key.as_str() == Some(KEY_MILESTONE)
                && value.as_str() == Some(DreamerMilestoneKind::Started.as_str())
        }));
        assert!(entries.iter().any(|(key, value)| {
            key.as_str() == Some(KEY_JOB_ID)
                && matches!(value, Value::Binary(bytes) if bytes.as_slice() == queued.job.id.as_bytes())
        }));

        Ok(())
    }

    #[test]
    fn dreamer_admission_budget_denial_does_not_lease_or_persist_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let stale = match runner.enqueue(EnqueueDreamerJob {
            job_type: "stale".to_owned(),
            input: Value::from("stale"),
            parent_job: None,
            dedupe_key: Some("stale-dedupe".to_owned()),
            run_id: None,
            now: 5,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => status,
        };
        let queued = enqueue_job(&runner, "expand", 10)?;
        let stale_ready_key = test_ready_key(5, stale.job.id);
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_records
                .delete(&mut wtxn, stale.job.id.as_bytes())?;
            wtxn.commit()?;
        }
        assert!(
            job_dedupe_points_to(&vault, stale.job.id)?,
            "fixture must leave a stale dedupe index before denial"
        );

        let denied = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 3,
            reserve_units: 4,
            started_milestone: None,
        })?;

        let DreamerAdmissionOutcome::BudgetExhausted(budget) = denied else {
            panic!("expected budget denial");
        };
        assert_eq!(budget.remaining_units, 3);
        assert_eq!(budget.reserved_units, 0);
        assert!(
            runner.budget("wake")?.is_none(),
            "denied admission must not commit an initialized budget row"
        );
        assert!(
            runner.budget_reservation("wake", queued.job.id)?.is_none(),
            "denied admission must not commit a child reservation row"
        );
        let status = runner.status(queued.job.id)?.expect("queued job");
        assert_eq!(status.job.state, JobState::Queued);
        assert_eq!(status.job.attempt_count, 0);
        assert!(status.job.lease_owner.is_none());
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .job_ready
                .get(&rtxn, &stale_ready_key)?
                .is_none(),
            "budget denial must commit stale ready-row repairs"
        );
        drop(rtxn);
        assert!(
            !job_dedupe_points_to(&vault, stale.job.id)?,
            "budget denial must commit stale dedupe cleanup"
        );

        Ok(())
    }

    #[test]
    fn dreamer_private_rows_stay_out_of_vault_entities_while_milestones_are_claims() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        let claim_id = EntityId::now();
        let milestone = milestone_fixture(&vault, claim_id, 20)?;

        runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 4,
            started_milestone: Some(milestone),
        })?;
        let parked = runner.park_job(ParkDreamerJob {
            job_id: queued.job.id,
            reason: "waiting for wake budget settle".to_owned(),
            now: 30,
        })?;
        assert_eq!(runner.parked_job(queued.job.id)?, Some(parked));

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &budget_key("wake")?)?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &budget_reservation_key("wake", queued.job.id)?)?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &run_tree_key(queued.job.id))?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &parked_key(queued.job.id))?
                .is_some()
        );
        assert!(
            vault
                .store
                .job_records
                .get(&rtxn, queued.job.id.as_bytes())?
                .is_some()
        );
        assert!(
            vault
                .store
                .entities
                .get(&rtxn, queued.job.id.as_bytes())?
                .is_none(),
            "job ids and local runner rows must not become vault entities"
        );
        assert!(
            vault
                .store
                .entities
                .get(&rtxn, claim_id.as_bytes())?
                .is_some(),
            "milestone claims are the durable vault claim surface"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_sync_boundary_exports_claims_not_runner_private_rows() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::map_get_bytes;
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window;
        use loro::{ExportMode, LoroDoc};

        let learned_at = 1_772_000_000;
        let window_key = WindowKey::from_timestamp(learned_at);
        let (_dir_a, vault_a) = open_vault();
        let runner_a = DreamerRunnerStore::new(&vault_a);
        let queued = enqueue_job(&runner_a, "expand", learned_at)?;
        let milestone_id = EntityId::now();
        let milestone = milestone_fixture(&vault_a, milestone_id, learned_at)?;

        runner_a.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: learned_at,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 4,
            started_milestone: Some(milestone),
        })?;
        runner_a.park_job(ParkDreamerJob {
            job_id: queued.job.id,
            reason: "waiting for wake budget settle".to_owned(),
            now: learned_at + 1,
        })?;

        let consent_id = EntityId::now();
        let effect_id = EntityId::now();
        let checkpoint_id = EntityId::now();
        write_dreamer_boundary_claim(&vault_a, consent_id, "dreamer.consent", learned_at)?;
        write_dreamer_boundary_claim(&vault_a, effect_id, "dreamer.effect", learned_at)?;
        write_dreamer_boundary_claim(&vault_a, checkpoint_id, "dreamer.checkpoint", learned_at)?;

        let durable_claims = [milestone_id, consent_id, effect_id, checkpoint_id];
        let doc_a = create_window_doc("node-a", &window_key);
        let mirrored = window::reverse_rematerialize(&vault_a, &doc_a, &window_key)?;
        assert!(
            mirrored >= durable_claims.len() as u32,
            "reverse rematerialize must mirror durable Dreamer claims"
        );

        let entities = doc_a.get_map("entities");
        for claim_id in durable_claims {
            assert_eq!(
                map_get_bytes(&entities, claim_id.to_hex().as_str()).as_deref(),
                vault_a.get_raw(&claim_id)?.as_deref(),
                "durable Dreamer claim must be present in the sync doc"
            );
        }

        let queued_as_entity = EntityId::from_bytes(*queued.job.id.as_bytes())?;
        assert!(
            map_get_bytes(&entities, queued_as_entity.to_hex().as_str()).is_none(),
            "queue job rows and leases must not be emitted as sync entities"
        );
        assert!(
            map_get_bytes(&entities, "dreamer:budget:wake").is_none(),
            "private runner keys must not be emitted into the sync entity map"
        );
        assert!(
            map_get_bytes(&entities, "dreamer:budget_reservation:wake").is_none(),
            "private child budget reservations must not be emitted into the sync entity map"
        );

        let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
        let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();
        let (_dir_b, vault_b) = open_vault();
        let materializer = Materializer::new();
        let restored = window::forward_rematerialize(&vault_b, &doc_b, &materializer, &window_key)?;
        assert!(
            restored >= durable_claims.len() as u32,
            "forward rematerialize must restore durable Dreamer claims"
        );
        for claim_id in durable_claims {
            assert!(
                vault_b.get_claim(&claim_id)?.is_some(),
                "durable Dreamer claim must survive CRDT sync"
            );
        }

        let rtxn = vault_b.store.env.read_txn()?;
        assert!(
            vault_b
                .store
                .job_records
                .get(&rtxn, queued.job.id.as_bytes())?
                .is_none(),
            "queue leases must remain private to the runner store"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &budget_key("wake")?)?
                .is_none(),
            "private budget rows must not sync"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &budget_reservation_key("wake", queued.job.id)?)?
                .is_none(),
            "private budget reservation rows must not sync"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &run_tree_key(queued.job.id))?
                .is_none(),
            "private run-tree rows must not sync"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &parked_key(queued.job.id))?
                .is_none(),
            "private parked rows must not sync"
        );

        Ok(())
    }

    #[test]
    fn dreamer_concurrent_admission_cannot_overspend_private_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let config = DreamerWakeBudgetConfig::default();
        config.validate()?;
        assert_eq!(
            config.child_reserve_units,
            DEFAULT_DREAMER_CHILD_RESERVE_UNITS
        );
        let first = enqueue_job(&runner, "first", 10)?;
        let second = enqueue_job(&runner, "second", 11)?;
        let third = enqueue_job(&runner, "third", 12)?;
        let barrier = Barrier::new(3);

        let (left, middle, right) = thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "left-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: config.child_reserve_units * 2,
                    reserve_units: config.child_reserve_units,
                    started_milestone: None,
                })
            });
            let middle = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "middle-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: config.child_reserve_units * 2,
                    reserve_units: config.child_reserve_units,
                    started_milestone: None,
                })
            });
            let right = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "right-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: config.child_reserve_units * 2,
                    reserve_units: config.child_reserve_units,
                    started_milestone: None,
                })
            });
            (
                left.join().expect("left join"),
                middle.join().expect("middle join"),
                right.join().expect("right join"),
            )
        });

        let outcomes = [left?, middle?, right?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DreamerAdmissionOutcome::Admitted(_)))
                .count(),
            2
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DreamerAdmissionOutcome::BudgetExhausted(_)))
                .count(),
            1
        );
        let budget = runner.budget("wake")?.expect("committed budget");
        assert_eq!(budget.remaining_units, 0);
        assert_eq!(budget.reserved_units, config.child_reserve_units * 2);

        let first_status = runner.status(first.job.id)?.expect("first status");
        let second_status = runner.status(second.job.id)?.expect("second status");
        let third_status = runner.status(third.job.id)?.expect("third status");
        let leased = [
            first_status.job.state,
            second_status.job.state,
            third_status.job.state,
        ]
        .into_iter()
        .filter(|state| *state == JobState::Leased)
        .count();
        let queued = [
            first_status.job.state,
            second_status.job.state,
            third_status.job.state,
        ]
        .into_iter()
        .filter(|state| *state == JobState::Queued)
        .count();
        assert_eq!(leased, 2);
        assert_eq!(queued, 1);

        Ok(())
    }

    #[test]
    fn dreamer_settle_reconciles_actual_usage_and_refund() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "settle", 10)?;

        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 20,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.reservation.job_id, queued.job.id);
        assert_eq!(admitted.budget.remaining_units, 12);
        assert_eq!(admitted.budget.reserved_units, 8);

        let DreamerBudgetSettlementOutcome::Settled(settlement) =
            runner.settle_budget(SettleDreamerBudget {
                budget_id: "wake".to_owned(),
                child_job: queued.job.id,
                actual_units: 5,
                now: 30,
            })?
        else {
            panic!("expected settlement");
        };
        assert_eq!(settlement.actual_units, 5);
        assert_eq!(settlement.refunded_units, 3);
        assert_eq!(settlement.over_reserved_units, 0);
        assert_eq!(settlement.budget.remaining_units, 15);
        assert_eq!(settlement.budget.reserved_units, 0);
        assert_eq!(
            runner.budget("wake")?.expect("settled budget"),
            settlement.budget
        );
        assert!(runner.budget_reservation("wake", queued.job.id)?.is_none());

        let second = enqueue_job(&runner, "settle-over-reserve", 40)?;
        let DreamerBudgetReserveOutcome::Reserved(reserved) =
            runner.reserve_budget(ReserveDreamerBudget {
                budget_id: "wake".to_owned(),
                child_job: second.job.id,
                budget_total_units: 20,
                reserve_units: 8,
                now: 50,
            })?
        else {
            panic!("expected explicit reserve");
        };
        assert_eq!(reserved.budget.remaining_units, 7);
        assert_eq!(reserved.budget.reserved_units, 8);

        let DreamerBudgetSettlementOutcome::Settled(over) =
            runner.settle_budget(SettleDreamerBudget {
                budget_id: "wake".to_owned(),
                child_job: second.job.id,
                actual_units: 10,
                now: 60,
            })?
        else {
            panic!("expected over-reserve settlement");
        };
        assert_eq!(over.refunded_units, 0);
        assert_eq!(over.over_reserved_units, 2);
        assert_eq!(over.budget.remaining_units, 5);
        assert_eq!(over.budget.reserved_units, 0);

        Ok(())
    }

    #[test]
    fn dreamer_settle_rejects_actual_usage_beyond_remaining_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "settle-overspend", 10)?;

        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.budget.remaining_units, 2);
        assert_eq!(admitted.budget.reserved_units, 8);

        let result = runner.settle_budget(SettleDreamerBudget {
            budget_id: "wake".to_owned(),
            child_job: queued.job.id,
            actual_units: 11,
            now: 30,
        });
        assert!(matches!(
            result,
            Err(Error::InvalidJobQueueRecord(
                "dreamer budget settlement exceeds remaining units"
            ))
        ));
        assert_eq!(
            runner.budget("wake")?.expect("unchanged budget"),
            admitted.budget
        );
        assert_eq!(
            runner.budget_reservation("wake", queued.job.id)?,
            Some(admitted.reservation)
        );

        Ok(())
    }

    #[test]
    fn dreamer_admission_reuses_existing_reservation_after_lease_timeout_requeue() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queue = JobQueue::new(&vault);
        let queued = enqueue_job(&runner, "requeued", 10)?;

        let DreamerAdmissionOutcome::Admitted(first) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "first-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected first admission");
        };
        assert_eq!(first.status.job.id, queued.job.id);
        assert_eq!(first.status.job.attempt_count, 1);
        assert_eq!(first.budget.remaining_units, 2);
        assert_eq!(first.budget.reserved_units, 8);
        let first_budget = first.budget.clone();
        let first_reservation = first.reservation.clone();

        let report = queue.cleanup_leases(CleanupJobLeases {
            now: 40,
            lease_timeout_secs: 10,
        })?;
        assert_eq!(report.stale_requeued, 1);
        let requeued = runner.status(queued.job.id)?.expect("requeued job");
        assert_eq!(requeued.job.state, JobState::Queued);
        assert_eq!(requeued.job.last_error.as_deref(), Some("lease_timeout"));

        let DreamerAdmissionOutcome::Admitted(second) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "second-worker".to_owned(),
            now: 50,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected second admission");
        };
        assert_eq!(second.status.job.id, queued.job.id);
        assert_eq!(second.status.job.state, JobState::Leased);
        assert_eq!(second.status.job.attempt_count, 2);
        assert_eq!(
            second.status.job.lease_owner.as_deref(),
            Some("second-worker")
        );
        assert_eq!(second.budget, first_budget);
        assert_eq!(second.reservation, first_reservation);
        assert_eq!(
            runner.budget("wake")?.expect("unchanged budget"),
            first_budget
        );
        assert_eq!(
            runner.budget_reservation("wake", queued.job.id)?,
            Some(first_reservation)
        );

        Ok(())
    }

    #[test]
    fn dreamer_abort_refunds_unspent_child_reservation() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "abort", 10)?;

        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.budget.remaining_units, 2);
        assert_eq!(admitted.budget.reserved_units, 8);

        let DreamerBudgetSettlementOutcome::Settled(aborted) =
            runner.abort_budget_reservation(AbortDreamerBudgetReservation {
                budget_id: "wake".to_owned(),
                child_job: queued.job.id,
                now: 30,
            })?
        else {
            panic!("expected abort refund");
        };
        assert_eq!(aborted.actual_units, 0);
        assert_eq!(aborted.refunded_units, 8);
        assert_eq!(aborted.over_reserved_units, 0);
        assert_eq!(aborted.budget.remaining_units, 10);
        assert_eq!(aborted.budget.reserved_units, 0);
        assert!(runner.budget_reservation("wake", queued.job.id)?.is_none());
        assert_eq!(
            runner.abort_budget_reservation(AbortDreamerBudgetReservation {
                budget_id: "wake".to_owned(),
                child_job: queued.job.id,
                now: 40,
            })?,
            DreamerBudgetSettlementOutcome::NoReservation
        );

        Ok(())
    }
}
