//! Moved from `crates/oneiron/src/tagging/freshness.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How current a saved tag set, or a view derived from it, is.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct TaggingFreshness {
    /// The set was read from text the turn no longer shows as published,
    /// or its mood is an earlier set's kept beside a turn read in windows.
    pub stale: bool,
    /// A tag pass is owed to the turn and has not settled.
    pub pending_retag: bool,
}

impl TaggingFreshness {
    /// The shared affect label for a view derived from the set.
    #[must_use]
    pub fn derivation(self) -> oneiron_contracts::affect::DerivationFreshness {
        oneiron_contracts::affect::DerivationFreshness {
            stale: self.stale,
            pending_retag: self.pending_retag,
        }
    }
}

/// The mood a model measured over one window of a turn it read in several
/// (FIX 9518): never averaged into a mood of the whole turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingMoodPartView {
    /// The MESSAGE the window starts in, and its byte there.
    pub message_ref: String,
    pub start: usize,
    /// The MESSAGE the window ends in, and its byte there.
    pub end_message_ref: String,
    pub end: usize,
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}
