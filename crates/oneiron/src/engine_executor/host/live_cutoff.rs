//! A scoped child's guest reads stop at its live cutoff (FIX 8233).
//!
//! Its runner binds the child's dispatcher to a [`ScopedCallControl`]. The
//! guest read entry checks it for every result the child reads: its own, a
//! delegated source or a finding. A facet or card read carries it on its
//! `ResultRead`, and a raw chunk read checks it around its chunk. A read it
//! cuts answers `reader_task_settled`, and a cut selection is never
//! published. Each check latches the control, so the runner ends the
//! child's entry at its cutoff. A run that is no scoped child has no
//! control and its reads read no clock. No new file or result is readable.

use std::time::Instant;

use super::RecordingJsHost;
use crate::code_run::{READER_TASK_SETTLED, ScopedCallControl};
use crate::{Error, Result};

impl RecordingJsHost<'_, '_> {
    /// The live cutoff of the scoped child this run is, as its runner bound
    /// it. `None` for any other run.
    pub(super) fn live_cutoff(&self) -> Option<&ScopedCallControl> {
        self.gated_write.scoped_call_control()
    }

    /// Whether this run is a scoped child whose live cutoff is reached now.
    /// A reached cutoff stays reached.
    pub(super) fn live_cutoff_reached(&self) -> bool {
        self.live_cutoff()
            .is_some_and(|control| control.expired(Instant::now()))
    }

    /// `Ok` while the live cutoff is not reached; else a raw chunk read's
    /// refusal, worded as that read's other refusals are: `{read} read
    /// refused: reader_task_settled`.
    pub(super) fn check_live_cutoff(&self, read: &str) -> Result<()> {
        if self.live_cutoff_reached() {
            return Err(Error::InvalidConfig(format!(
                "{read} read refused: {READER_TASK_SETTLED}"
            )));
        }
        Ok(())
    }
}
