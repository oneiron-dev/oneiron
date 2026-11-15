//! Moved from `crates/oneiron/src/edit_distance/routing/keys.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Only accepted schema version for any row this module stores.
pub const ROW_VERSION: u8 = 1;

pub const MEMBER_ROW_LABEL: &str = "routing membership row";

/// Separator between a key's parts. No part may contain it, which the key
/// builder enforces rather than assumes.
pub const KEY_SEPARATOR: u8 = 0;

// ---------------------------------------------------------------------------
// Keys + rows
// ---------------------------------------------------------------------------

pub fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

pub fn decode_row<T: serde::de::DeserializeOwned>(raw: &[u8], label: &'static str) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}
