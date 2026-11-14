//! Moved from `crates/oneiron/src/edit_distance/delta/schema.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How an [`AmendmentDelta`] was measured. Ordered by precedence, and the
/// token is pinned: a receipt's Δ payload carries it on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaSource {
    /// Replayed from ED-00's recorded op window.
    RecordedOps,
    /// Structured per-field diff of two canonical-MessagePack bodies.
    FieldDiff,
    /// Reconstructed after the fact by diffing the two endpoint texts.
    Reconstructed,
}

impl DeltaSource {
    /// The pinned on-disk token for this lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordedOps => "recorded_ops",
            Self::FieldDiff => "field_diff",
            Self::Reconstructed => "reconstructed",
        }
    }
}
