//! Moved from `crates/oneiron/src/edit_roundtrip/pipeline.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whether a recalc stage ran, and why not when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecalcStatus {
    NotNeeded,
    Performed,
    /// Edited bytes could not be reparsed before recalc; the gate will reject.
    Skipped,
}
