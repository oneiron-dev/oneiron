//! Moved from `crates/oneiron/src/training_pack/timeline.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::task_verb::brief::hex32;
use serde::Deserialize;
use serde::Serialize;

/// A point inside one run: the optimizer step and the tokens trained so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingBoundary {
    pub step: u64,
    pub tokens: u64,
}

impl TrainingBoundary {
    /// The run's start, at its starting checkpoint.
    pub const START: Self = Self { step: 0, tokens: 0 };
}

/// The earlier checkpoint a phase restarted from, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentCheckpoint {
    pub step: u64,
    #[serde(with = "hex32")]
    pub blake3: [u8; 32],
    pub reason: String,
}

/// How an executed phase ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcome {
    Completed,
    Failed,
    Aborted,
}
