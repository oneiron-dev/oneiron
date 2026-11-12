//! Moved from `crates/oneiron/src/skill_optimize/training_choice.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A separate owner decision; an override keeps the failed checks on its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SwapChoice {
    Evaluated,
    ExplicitOverride { reason: String },
}
