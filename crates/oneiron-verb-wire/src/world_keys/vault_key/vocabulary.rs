//! Moved from `crates/oneiron/src/world_keys/vault_key/vocabulary.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::world_keys::vault_key::*;
use serde::Deserialize;
use serde::Serialize;

/// Whether this vault has a data key, and whether this handle holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VaultKeyStatus {
    NoKey,
    Locked,
    Unlocked,
}
