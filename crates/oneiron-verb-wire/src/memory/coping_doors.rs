//! Moved from `crates/oneiron/src/memory/coping_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

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
