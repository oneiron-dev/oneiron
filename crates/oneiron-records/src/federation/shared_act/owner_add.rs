//! Moved from `crates/oneiron/src/federation/shared_act/owner_add.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::federation::shared_act::*;
use std::collections::BTreeSet;

/// Payload of an `add_owner` act: `owner` gains the Owner role; nobody loses it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddOwnerPlan {
    pub v: u8,
    pub owner: String,
}
