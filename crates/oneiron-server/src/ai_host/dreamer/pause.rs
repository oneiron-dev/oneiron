//! The owner's own pause cause over the Dreamer (`POST /dreamer/pause`,
//! `POST /dreamer/resume`), apart from the managed reap freeze: the two
//! causes read as the one pause the passes hold on, so a resume never lifts
//! a managed freeze.

use super::DreamerControl;

impl DreamerControl {
    /// Sets the owner's own pause cause: no new pass starts, and the running
    /// attempt parks at its next boundary. Never touches the managed freeze.
    pub(crate) fn set_owner_paused(&self, paused: bool) {
        (self.set_owner_pause)(paused);
    }

    /// Clears the owner's own pause cause; a managed freeze still holds the
    /// pause.
    pub(crate) fn resume(&self) {
        self.set_owner_paused(false);
    }

    /// The owner's own pause cause now (not the managed freeze).
    pub(crate) fn owner_paused(&self) -> bool {
        (self.read_owner_pause)()
    }

    /// The pause the passes read now: the managed freeze or the owner's own
    /// cause.
    pub(crate) fn paused(&self) -> bool {
        *(self.pause)().borrow()
    }
}
