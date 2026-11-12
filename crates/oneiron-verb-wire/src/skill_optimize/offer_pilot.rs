//! Moved from `crates/oneiron/src/skill_optimize/offer_pilot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::cohort::EvalExposure;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyCard;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyInput;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilot {
    pub id: EntityId,
    pub candidate: EntityId,
    pub exposure: EvalExposure,
    pub membership_digest: String,
    pub rubric_revision: String,
    pub families: u32,
    pub floor_slices: BTreeMap<String, u32>,
    pub prepared_at: u64,
    pub measurement: Option<OfferPilotMeasurement>,
    pub card: Option<SufficiencyCard>,
    pub completed_at: Option<u64>,
    /// The rows the released cohort's cases and labels were read from,
    /// frozen in the exposure's own transaction (FIX 5761); `None` when any
    /// of them is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_source_rows: Option<Vec<EntityId>>,
    /// The rows the measurement was read from: the release rows it was
    /// scored from, plus the evaluator's own trace of its receipts, scores,
    /// costs and sufficiency when one was recorded (FIX 5761, FIX 11885).
    /// `None` until measured; after completion `None` only when the
    /// release's own rows are unknown. An evaluator's receipt keys are
    /// never read as rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_source_rows: Option<Vec<EntityId>>,
}
