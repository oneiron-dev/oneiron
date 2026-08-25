//! OF-366/OF-267 claim-authoring admission gate: single-pass vs tournament.

use crate::attempt_queue::{AttemptId, AttemptInterventionEffect};
use crate::error::{Error, Result};

use super::codec::invalid_dreamer_runner;
use super::constants::{
    DEFAULT_DREAMER_CHILD_RESERVE_UNITS, DEFAULT_DREAMER_TOURNAMENT_DEPTH_K,
    DEFAULT_DREAMER_TOURNAMENT_FANOUT_M, MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT,
};
use super::types::DreamerBudgetRecord;

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
