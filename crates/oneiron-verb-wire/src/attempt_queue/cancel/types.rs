//! Moved from `crates/oneiron/src/attempt_queue/cancel/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::attempt_cancel::AttemptCancelPressure;
pub use crate::store::attempt_cancel::AttemptLanding;
pub use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
pub use oneiron_wake_contract::store::attempt_cancel::LandingTrigger;

/// Refused soft cancel requests after which repeated refusal is an observable
/// pathology rather than a legitimate "not yet".
///
/// Crossing it never changes the attempt's state: only the hard rung
/// (`AttemptQueue::force_cancel`)
/// can stop a worker that will not land, and this is the signal that says so.
pub const SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD: u32 = 3;

impl AttemptCancelPressure {
    /// True once refusals have crossed
    /// [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`]. Observability only: it
    /// never terminates anything by itself.
    #[must_use]
    pub const fn is_pathological(&self) -> bool {
        self.rejections >= SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    }
}
