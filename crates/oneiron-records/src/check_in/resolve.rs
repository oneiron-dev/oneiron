//! Moved from `crates/oneiron/src/check_in/resolve.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why an act waits for a proof from the ladder.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitReason {
    /// The mode is `AlwaysAsk`.
    AlwaysAsk,
    /// The unsure test was unsure.
    Unsure,
    /// The unsure test failed.
    UnsureTestFailed,
    /// `AskWhenUnsure`, but the model may not decide this act.
    ModelNotAllowed,
}

impl WaitReason {
    /// The receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAsk => "always_ask",
            Self::Unsure => "unsure",
            Self::UnsureTestFailed => "unsure_test_failed",
            Self::ModelNotAllowed => "model_not_allowed",
        }
    }
}
