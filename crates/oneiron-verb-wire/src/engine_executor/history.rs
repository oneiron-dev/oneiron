//! Moved from `crates/oneiron/src/engine_executor/history.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldHistoryEpoch {
    pub summary_ref: String,
    pub epoch: u64,
    pub from: u64,
    pub through: u64,
    /// None when the source was withdrawn; the retained boundary remains.
    pub text: Option<String>,
}
