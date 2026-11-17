//! Moved from `crates/oneiron/src/self_heal/distillation.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReviewedFinding {
    pub family: String,
    #[serde(with = "super::receipt_serde::id")]
    #[schemars(with = "String")]
    pub event_id: EntityId,
    #[serde(with = "super::receipt_serde::id")]
    #[schemars(with = "String")]
    pub reviewer: EntityId,
    pub positive: bool,
}
