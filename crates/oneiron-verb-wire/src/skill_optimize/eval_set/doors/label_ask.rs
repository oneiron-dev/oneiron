//! Moved from `crates/oneiron/src/skill_optimize/eval_set/doors/label_ask.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::offer::snapshot::OfferCandidate;
use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::principal_record::NoStanding;
use oneiron_store::principal_record::PACT_STANDING_LAPSED;
use serde::Deserialize;
use serde::Serialize;

/// `vault.evals.labels.ask`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalLabelAskRequest {
    /// The pending stock-switch training offer that waits on the label.
    pub offer: EntityId,
    /// The case the responsible owner is asked to label.
    pub case: EntityId,
    /// The two answers the owner picks between.
    pub option_a: String,
    pub option_b: String,
}
