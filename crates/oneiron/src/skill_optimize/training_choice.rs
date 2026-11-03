//! Training compute choices, authorization provenance and run states.
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// There is no default destination. External explicitly approves this run's egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeChoice {
    OwnerMachines,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// A separate owner decision; an override keeps the failed checks on its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SwapChoice {
    Evaluated,
    ExplicitOverride { reason: String },
}
