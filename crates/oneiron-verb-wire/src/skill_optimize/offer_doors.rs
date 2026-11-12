//! Moved from `crates/oneiron/src/skill_optimize/offer_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::offer::snapshot::OfferAnswer;
use crate::skill_optimize::offer::snapshot::OfferCheck;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_state::AttemptState;
use oneiron_store::dreamer_attempt_payload::DreamerAttemptPayload;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassRef {
    pub attempt: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferRef {
    pub offer: EntityId,
}

/// All five engine choices are served, not just the switch approval.
/// A train yes records intent; the existing training-offer owner routes
/// prepare and authorize its run and retain the separate result-swap choice.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerRequest {
    pub offer: EntityId,
    pub digest: String,
    pub answer: OfferAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferUndoReceipt {
    pub offer: EntityId,
    pub at: u64,
    pub restored_model: String,
}

/// A training run, by id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrainingRunRef {
    pub run: EntityId,
}
