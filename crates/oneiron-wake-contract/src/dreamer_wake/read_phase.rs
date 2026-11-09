//! Moved from `crates/oneiron/src/dreamer_wake/read_phase.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::deadline::WakeCancellation;

/// What stops a read phase before its write: the host's pause or a stop
/// raised on the pass's cancellation. A read phase holds no writer, so the
/// pass deadline does not stop it.
#[derive(Clone, Copy, Default)]
pub struct WakeStop<'a> {
    cancel: Option<&'a WakeCancellation>,
}

impl<'a> WakeStop<'a> {
    /// A read phase nothing stops.
    pub const NEVER: Self = Self { cancel: None };

    pub const fn new(cancel: Option<&'a WakeCancellation>) -> Self {
        Self { cancel }
    }

    /// Whether the pass was cancelled or paused.
    pub fn stopped(&self) -> bool {
        self.cancel.is_some_and(WakeCancellation::is_cancelled)
    }
}
