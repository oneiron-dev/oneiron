//! Moved from `crates/oneiron/src/skill_optimize/offer_pilot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::sufficiency::SufficiencyInput;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotPrepare {
    pub candidate: EntityId,
    pub cohort: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotRef {
    pub pilot: EntityId,
}

/// Measurements supplied by the owner's evaluator, not by the offer skill.
/// Unknowns stay null. `one_off_cost` includes pilot, migration and re-embed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotMeasurement {
    pub sufficiency: SufficiencyInput,
    pub receipt_refs: Vec<String>,
    pub currency: String,
    pub one_off_cost: Option<f64>,
    pub incumbent_score: Option<f64>,
    pub candidate_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotComplete {
    pub pilot: EntityId,
    pub measurement: OfferPilotMeasurement,
}
