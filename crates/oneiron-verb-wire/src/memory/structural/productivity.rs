//! Moved from `crates/oneiron/src/memory/structural/productivity.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The productivity tree under one TASK.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProductivityTreeRequest {
    /// Root TASK ref (short-id ref or hex).
    pub root_ref: String,
    /// Levels below the root to walk; `0` ⇒ the root alone.
    pub max_depth: u32,
}
