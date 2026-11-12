//! Moved from `crates/oneiron/src/skill_optimize/response_pair.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::measurement::PreferredResponse;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// The owner's pick on one blind preference pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResponsePairPick {
    pub pair_ref: String,
    pub preferred: PreferredResponse,
    /// The person who picked, 32 hex.
    pub by: String,
    /// Unix seconds.
    pub picked_at: u64,
}
