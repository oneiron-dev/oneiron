//! Moved from `crates/oneiron/src/scope_summary/arc_gate.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why an Arc is still owed (FIX 7509 P8, PR3): typed, on its row, never a
/// silent hold. A failure is retried at the backstop; work in progress
/// keeps its queued attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArcPendingCause {
    /// A closed sitting below the Arc has no summary yet.
    #[serde(rename = "arc_lower_pending")]
    LowerPending { session: String },
    /// A TURN the Arc must read could not be opened, by its full id.
    #[serde(rename = "arc_source_unavailable")]
    SourceUnavailable { handle: String },
    /// The Arc composes in parts (PR3): the id of its work generation, whose
    /// queued attempt goes on at its next wake. Never written smaller.
    #[serde(rename = "arc_composition_pending")]
    CompositionPending { work_id: String },
    /// The model's window holds the call's frame and not one character of
    /// a source beside it.
    #[serde(rename = "arc_window_too_small")]
    WindowTooSmall { window: u64, frame_tokens: u64 },
}

impl ArcPendingCause {
    /// The cause's static code, for logs.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LowerPending { .. } => "arc_lower_pending",
            Self::SourceUnavailable { .. } => "arc_source_unavailable",
            Self::CompositionPending { .. } => "arc_composition_pending",
            Self::WindowTooSmall { .. } => "arc_window_too_small",
        }
    }
}
