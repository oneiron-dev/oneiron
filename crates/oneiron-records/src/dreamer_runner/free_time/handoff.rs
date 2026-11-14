//! Moved from `crates/oneiron/src/dreamer_runner/free_time/handoff.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time home handoff: {reason}"))
}
pub mod actor_content;
