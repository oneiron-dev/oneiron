//! Moved from `crates/oneiron/src/dreamer_runner/types/retry_policy.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::park_resume::{ParkResume, ParkResumer};
use crate::dreamer_runner::types::DreamerParkCause;

impl DreamerParkCause {
    /// How long after it parked a later wake pass resumes a park of this
    /// cause (DOOR-144; the park resume table's LaterPass row): a Checkpoint
    /// or a Paused park at once, a Retry after `retry_secs`, the vault's
    /// resolved pause. `None` for a park no later pass resumes.
    #[must_use]
    pub const fn later_pass_resume_delay(self, retry_secs: u64) -> Option<u64> {
        if !ParkResume::cause_may_resume(self, ParkResumer::LaterPass) {
            return None;
        }
        Some(if matches!(self, Self::Retry) {
            retry_secs
        } else {
            0
        })
    }
}
