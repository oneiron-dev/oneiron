//! Moved from `crates/oneiron/src/failure_signals/code_fix/exact.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How a code fix's replay ran the real failure (FIX 1662).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayFidelity {
    /// The request the failing call sent, as it was sent.
    Exact,
    /// That request, with each secret in it, or in its rung's route prompt,
    /// masked into its custody handle.
    ExactMasked,
    /// Rebuilt from the failure's instructions, briefing and task: not the
    /// request the call sent.
    Rebuilt,
}
