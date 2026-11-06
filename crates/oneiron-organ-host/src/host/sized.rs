//! A call its caller sizes from what it lends (Rule 5): a booking and a
//! process grant that grow with the input, never a fixed size the input
//! must fit, and what the call measured, however it ended.

use std::sync::Arc;
use std::time::Instant;

use oneiron::Vault;
use oneiron_organ_protocol::{Hash32, SharedRegion};

use super::{Held, Lent, OrganHost, Resolved, unvouched};
use crate::error::HostError;
use crate::handlers::AskHandlers;
use crate::outcome::OrganOutcome;
use crate::process::OrganProcess;
use crate::slot::Slot;
use crate::spec::{LentInput, OrganCall, OrganSpec, OrganTier};

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
    /// The provenance tier of the actual slot selected for this call, not
    /// a separate install lookup that could race a reinstall.
    pub tier: Option<OrganTier>,
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
    SizedUntil(CallSize, &'m mut CallMeasure, Instant),
}

impl Run<'_> {
    pub(super) fn until(&self) -> Option<Instant> {
        match self {
            Self::SizedUntil(_, _, until) => Some(*until),
            _ => None,
        }
    }

    pub(super) fn fresh(&self) -> bool {
        !matches!(self, Self::Warm)
    }

    /// What the call books, noted in its measure.
    pub(super) fn booking(&mut self, spec: &OrganSpec) -> u64 {
        match self {
            Self::Sized(size, measure) | Self::SizedUntil(size, measure, _) => {
                measure.tier = Some(spec.tier);
                measure.booked = size.booking.max(spec.call_memory_bytes);
                measure.booked
            }
            Self::Warm | Self::Fresh => spec.call_memory_bytes,
        }
    }

    /// The process grant of a sized call's own process.
    pub(super) fn process_memory(&self, spec: &OrganSpec) -> Option<u64> {
        match self {
            Self::Sized(size, _) | Self::SizedUntil(size, _, _) => {
                Some(size.process.max(spec.memory_bytes))
            }
            Self::Warm | Self::Fresh => None,
        }
    }

    /// Notes the frames the call's process carried. A sized call runs in a
    /// process of its own, so they are this call's alone.
    pub(super) fn measured(&mut self, process: &OrganProcess) {
        if let Self::Sized(_, measure) | Self::SizedUntil(_, measure, _) = self {
            (measure.largest_sent_frame, measure.largest_received_frame) = process.largest_frames();
        }
    }
}

/// One call-owned immutable input. Its hash is computed from the same bytes
/// copied into its region; callers cannot supply a different receipt hash.
/// Unlike cached inputs, this region leaves memory when the call ends.
#[derive(Debug)]
pub struct LentRegion {
    media_type: String,
    hash: Hash32,
    region: SharedRegion,
}

impl LentRegion {
    /// Copies `bytes` once into an immutable region. The caller must admit
    /// its length before this call and hold that reservation through the
    /// organ call. No intermediate owned byte buffer is constructed.
    pub fn copy_from(bytes: &[u8], media_type: impl Into<String>) -> std::io::Result<Self> {
        Ok(Self {
            media_type: media_type.into(),
            hash: Hash32::of(bytes),
            region: SharedRegion::from_bytes(bytes)?,
        })
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.region.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.region.is_empty()
    }

    pub(super) fn resolve(self, spec: &OrganSpec) -> Result<Resolved, HostError> {
        if !spec
            .media_types
            .iter()
            .any(|media| media == &self.media_type)
        {
            return Err(HostError::MediaTypeNotGranted(self.media_type));
        }
        Ok(Resolved {
            input: None,
            media_type: self.media_type,
            hash: self.hash,
            len: self.region.len(),
            held: Held::Region(Arc::new(self.region)),
        })
    }
}

impl OrganHost {
    /// A sized call over one already admitted, call-owned region, bounded
    /// by the caller's original absolute deadline. Budget waits do not move
    /// this deadline; existing duration-based calls keep their own clocks.
    /// The input is not copied again or retained in the region cache.
    pub fn call_sized_region_until_with(
        &self,
        vault: &Vault,
        call: OrganCall,
        input: LentRegion,
        asks: &AskHandlers<'_>,
        size: CallSize,
        measure: &mut CallMeasure,
        deadline: Instant,
    ) -> Result<OrganOutcome, HostError> {
        self.run(
            vault,
            call,
            vec![Lent::Region(input)],
            asks,
            Run::SizedUntil(size, measure, deadline),
        )
    }

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
