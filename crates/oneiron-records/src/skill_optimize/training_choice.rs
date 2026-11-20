//! Moved from `crates/oneiron/src/skill_optimize/training_choice.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill_optimize::training_choice::SwapChoice;
use serde::Deserialize;
use serde::Serialize;

/// There is no default destination. External explicitly approves this run's egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComputeChoice {
    OwnerMachines,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrainingState {
    Prepared,
    /// The owner authorized this exact spec; the host dispatches it once.
    Authorized,
    Running,
    ConnectorFailed,
    Returned,
    Scored,
    Bound,
}

/// Where an authorization came from: the owner's own door, or their yes on
/// a training offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrainingAuthorizationSource {
    Direct,
    Offer {
        offer: EntityId,
        offer_digest: String,
    },
}
