//! Moved from `crates/oneiron/src/memory/hook_regen_doors/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::hook_regen_doors::types::*;
use serde::Deserialize;
use serde::Serialize;

/// What one pack put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackPutOutcome {
    Installed,
    /// Its code waits for its sandbox to qualify it.
    Candidate,
    /// The vault's install rules refused it; `reason` says why.
    Blocked,
}
pub mod types;
