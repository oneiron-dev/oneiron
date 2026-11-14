//! Moved from `crates/oneiron/src/vault_shape/card.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::reach::ShapeReach;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The vault's shape card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeCard {
    /// The stored seed's revision; none until a seed is first stored.
    pub seed_id: Option<String>,
    /// The live setup rows the caller reads, counted by kind.
    pub counts: BTreeMap<String, u32>,
    /// Applies with an item still waiting for the owner's word, or torn.
    pub open_applies: u32,
    /// Every send path the caller reads.
    pub reach: ShapeReach,
    /// The reach in one line.
    pub line: String,
}
