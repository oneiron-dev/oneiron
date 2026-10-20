//! A call its caller sizes from what it lends (Rule 5): a booking and a
//! process grant that grow with the input, never a fixed size the input
//! must fit, and what the call measured, however it ended.

use std::sync::Arc;

use oneiron::Vault;

use super::{OrganHost, unvouched};
use crate::error::HostError;
use crate::handlers::AskHandlers;
use crate::outcome::OrganOutcome;
use crate::process::OrganProcess;
use crate::slot::Slot;
use crate::spec::{LentInput, OrganCall, OrganSpec};

/// The resources one call runs with, sized by its caller. Neither is ever
/// less than the install grant's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSize {
    /// Memory the call books from the shared budget; its answers and
    /// outputs draw on it, and it grows past it as they need. A booking
    /// past the whole budget runs alone, once the budget drains.
    pub booking: u64,
    /// The memory grant of the process started for the call alone.
    pub process: u64,
}

/// What one sized call measured, however it ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallMeasure {
    /// Memory the call booked.
    pub booked: u64,
    /// The largest frame body the host sent the call's process, as
    /// encoded: the call, or an answer to one of its asks.
    pub largest_sent_frame: u64,
    /// The largest frame body the process sent back: its reply, or an ask.
    pub largest_received_frame: u64,
}

/// How one call runs: in the organ's warm process, in one of its own, or in
/// one of its own at a size its caller measured.
pub(super) enum Run<'m> {
    Warm,
    Fresh,
    Sized(CallSize, &'m mut CallMeasure),
}

impl Run<'_> {
    pub(super) fn fresh(&self) -> bool {
        !matches!(self, Self::Warm)
    }

    /// What the call books, noted in its measure.
    pub(super) fn booking(&mut self, spec: &OrganSpec) -> u64 {
        match self {
            Self::Sized(size, measure) => {
                measure.booked = size.booking.max(spec.call_memory_bytes);
                measure.booked
            }
            Self::Warm | Self::Fresh => spec.call_memory_bytes,
        }
    }

    /// The process grant of a sized call's own process.
    pub(super) fn process_memory(&self, spec: &OrganSpec) -> Option<u64> {
        match self {
            Self::Sized(size, _) => Some(size.process.max(spec.memory_bytes)),
            Self::Warm | Self::Fresh => None,
        }
    }

    /// Notes the frames the call's process carried. A sized call runs in a
    /// process of its own, so they are this call's alone.
    pub(super) fn measured(&mut self, process: &OrganProcess) {
        if let Self::Sized(_, measure) = self {
            (measure.largest_sent_frame, measure.largest_received_frame) = process.largest_frames();
        }
    }
}

impl OrganHost {
    /// [`Self::call_fresh_with`], at `size` rather than the install grant's
    /// booking and process grant: the caller sizes the call from what it
    /// lends, so no input is refused for outgrowing a fixed grant. The
    /// call's answers and outputs draw on its booking, which grows to hold
    /// them; none is refused for its size. `measure` is filled in however
    /// the call ends.
    ///
    /// # Errors
    /// As [`Self::call_with`].
    pub fn call_sized_with(
        &self,
        vault: &Vault,
        call: OrganCall,
        lent: Vec<LentInput>,
        asks: &AskHandlers<'_>,
        size: CallSize,
        measure: &mut CallMeasure,
    ) -> Result<OrganOutcome, HostError> {
        self.run(
            vault,
            call,
            unvouched(lent),
            asks,
            Run::Sized(size, measure),
        )
    }
}

/// Stops a one-call process when its call ends.
pub(super) struct OneCall<'a> {
    pub(super) slot: &'a Slot,
    pub(super) process: Arc<OrganProcess>,
}

impl Drop for OneCall<'_> {
    /// A process that ended on its own before its call let it go crashed,
    /// as a warm process found dead does, even when the reader has not yet
    /// seen its socket close; one the host stopped did not.
    fn drop(&mut self) {
        let ended = !self.process.is_alive() || self.process.exited();
        if ended && !self.process.stopped_by_host() {
            self.slot.crashed(&self.process);
        } else {
            self.slot.stopped(&self.process);
        }
        self.process.stop();
        self.slot.prune();
    }
}
