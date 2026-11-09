//! Moved from `crates/oneiron/src/dreamer_runner/types/retry_policy.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::types::DreamerParkCause;

impl DreamerParkCause {
    /// Whether a later wake pass resumes a park of this cause as the same
    /// try (DOOR-144): a Checkpoint, a Paused or a Retry park.
    #[must_use]
    pub const fn resumes_on_later_pass(self) -> bool {
        matches!(self, Self::Checkpoint | Self::Paused | Self::Retry)
    }

    /// How long after it parked a later wake pass resumes a park of this
    /// cause: a Checkpoint or a Paused park at once, a Retry after
    /// `retry_secs`, the vault's resolved pause. `None` for a park no later
    /// pass resumes.
    #[must_use]
    pub const fn later_pass_resume_delay(self, retry_secs: u64) -> Option<u64> {
        match self {
            Self::Checkpoint | Self::Paused => Some(0),
            Self::Retry => Some(retry_secs),
            _ => None,
        }
    }
}
