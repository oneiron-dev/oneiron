//! Moved from `crates/oneiron/src/dreamer_wake/sieve/evidence.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::sieve::*;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveEvidenceRequest {
    pub turn: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveEvidenceCursor {
    pub learned_at: u64,
    pub turn: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveEvidenceView {
    /// The original ingress identity, unchanged by a replay.
    pub turn: EntityId,
    /// The sieve's digest of the source chunks it read, not a text-match key.
    pub reading: Option<[u8; 32]>,
    pub cursor: Option<SieveEvidenceCursor>,
    pub owed: bool,
    pub continuing: bool,
}
