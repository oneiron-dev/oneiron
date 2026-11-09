//! Moved from `crates/oneiron/src/attempt_queue/cancel/types.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::store::attempt_cancel::AttemptResumePoint;
use crate::store::attempt_cancel::LandingTrigger;

impl LandingTrigger {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancelRequest => "cancel_request",
            Self::BudgetWarning => "budget_warning",
            Self::LeaseWarning => "lease_warning",
        }
    }
}

impl AttemptResumePoint {
    /// Builds a resume point with no artifact reference.
    #[must_use]
    pub fn new(marker: impl Into<String>, recorded_at: u64) -> Self {
        Self {
            marker: marker.into(),
            artifact_ref: None,
            recorded_at,
        }
    }

    /// Attaches the durable artifact a successor should read first.
    #[must_use]
    pub fn with_artifact_ref(mut self, artifact_ref: impl Into<String>) -> Self {
        self.artifact_ref = Some(artifact_ref.into());
        self
    }
}
