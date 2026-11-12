//! Moved from `crates/oneiron/src/vault_shape/seed.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::bytes_to_hex_lower;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

pub fn hex(bytes: &[u8]) -> String {
    bytes_to_hex_lower(bytes)
}
