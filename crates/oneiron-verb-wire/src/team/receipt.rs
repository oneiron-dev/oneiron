//! Moved from `crates/oneiron/src/team/receipt.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The pattern skill revision a team ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PatternSkillRef {
    pub skill: EntityId,
    pub version: String,
}
