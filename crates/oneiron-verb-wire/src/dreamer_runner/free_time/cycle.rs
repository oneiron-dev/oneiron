//! Moved from `crates/oneiron/src/dreamer_runner/free_time/cycle.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whether a cycle still admits its items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeCycleState {
    Open,
    /// Ended: no new item runs; calls already made settle normally.
    Closed,
}
