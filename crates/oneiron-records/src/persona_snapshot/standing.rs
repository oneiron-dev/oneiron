//! Moved from `crates/oneiron/src/persona_snapshot/standing.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingBlockEviction {
    pub block: String,
    #[serde(with = "oneiron_contracts::serialize::entity_ref::sequence")]
    pub claims: Vec<EntityId>,
}
