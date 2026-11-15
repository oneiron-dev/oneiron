//! Moved from `crates/oneiron/src/agent_def/portable.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Why a knowledge claim stays home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmittedClaimReason {
    /// Its value names an entity or an edge.
    RefValue,
    /// Its value is not text, and names no entity or edge.
    TypedValue,
}

pub fn invalid() -> Error {
    Error::InvariantViolation("agent facet encoding failed")
}
