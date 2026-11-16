//! Moved from `crates/oneiron/src/memory/coping_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::claim_admission::ClaimScope;
use oneiron_contracts::affect::Vad;
use oneiron_store::write_envelope::coping_outcome::CopingStrategy;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingOutcomeRecordRequest {
    pub affected_person_ref: String,
    /// The turn in which the strategy was offered: the canonical strategyRef.
    pub baseline_turn_ref: String,
    pub later_turn_ref: String,
    pub strategy: CopingStrategy,
    pub confidence: f32,
    pub scope: ClaimScope,
    pub sensitivity: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingOutcomeUpdateRequest {
    pub prior_claim_ref: String,
    pub baseline_turn_ref: String,
    pub later_turn_ref: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingAggregateRequest {
    pub affected_person_ref: String,
    pub scope: Option<ClaimScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingVadDelta {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingOutcomeView {
    pub claim_ref: String,
    pub affected_person_ref: String,
    pub strategy_ref: String,
    pub strategy: CopingStrategy,
    pub vad_delta: CopingVadDelta,
    pub confidence: f32,
    pub successful: bool,
    pub observed_n: u64,
    pub scope: ClaimScope,
    pub approval: String,
    pub source: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub evidence_refs: Vec<String>,
    pub made_by: Option<oneiron_store::write_envelope::provenance::made_by::MadeBy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingOutcomeReceipt {
    pub outcome: CopingOutcomeView,
    pub superseded_claim_refs: Vec<String>,
    pub receipt_ref: String,
}

/// Every admitted active strategy aggregate, including unsuccessful observations.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingAggregate {
    pub affected_person_ref: String,
    pub outcomes: Vec<CopingOutcomeView>,
    pub observed_n: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingLookupRequest {
    pub affected_person_ref: String,
    /// The turn whose VAD is the current state: a turn the person spoke in.
    pub current_turn_ref: String,
    pub scope: Option<ClaimScope>,
}

/// What a coping lookup answers from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CopingLookupBasis {
    /// The person's own outcomes reach the cold-start floor.
    Outcomes,
    /// Below the floor: generic regulation priors at low confidence.
    GenericPriors,
}

/// One ranked outcome and the state it was used in.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingLookupOutcome {
    pub outcome: CopingOutcomeView,
    /// The VAD of the outcome's baseline turn (its strategyRef).
    pub state: Vad,
    /// PAD distance from the current state over the canonical VAD floats.
    pub pad_distance: f32,
    /// When the vault learned this head: the recency the rank reads.
    pub learned_at: u64,
}

/// A generic regulation prior: no claim about this person.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingPrior {
    pub strategy: CopingStrategy,
    pub confidence: f32,
}

/// Outcomes nearest the current state first; within one distance, worked
/// first, then the most recent, then the most confident.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingLookup {
    pub affected_person_ref: String,
    pub current_turn_ref: String,
    pub current_state: Vad,
    pub basis: CopingLookupBasis,
    /// Observations over the ranked outcomes, compared against the floor.
    pub observed_n: u64,
    pub cold_start_min_outcomes: u64,
    pub outcomes: Vec<CopingLookupOutcome>,
    /// Listed only below the floor.
    pub priors: Vec<CopingPrior>,
}
