//! Moved from `crates/oneiron/src/dreamer_consolidation/failure_rules.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Extraction,
    Conflict,
}

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer failure rule rows".into())
}
