//! Moved from `crates/oneiron/src/dreamer_runner/program/replica.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

pub fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("turn program row refused: {reason}"))
}

pub fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| refused("does not encode"))
}
