//! The geometry door's PDF parse on this machine's memory (FIX 8065). The
//! lease that admitted the PDF's own bytes (FIX 7649) grows as the parse
//! proceeds: every table, copy and decode the inspection is about to allocate
//! is admitted through [`MemoryLease::grow`], on the same line and until the
//! same deadline the input waited to, and refused only as that lease is, at
//! the machine's floor or that deadline. What a finished stage of the parse
//! gives back stays in the lease for the next one, so the lease holds the
//! parse's peak. It is held until the door answers.
use crate::machine::{MemoryLease, MemoryRefusal};
use oneiron::blob_artifact::esign::render::{DecodeAdmissionError, InspectionMemory};
use oneiron::office_body::RESERVE_STEP;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// One geometry inspection's lease, and why it stopped growing, if it did.
pub(super) struct ParseLease {
    leased: Mutex<Leased>,
    /// The input lease's own deadline: the parse waits no longer.
    deadline: Instant,
}

struct Leased {
    lease: MemoryLease,
    /// Bytes the lease holds that no admitted allocation holds now.
    spare: u64,
    /// The first refusal, which the door answers with.
    refused: Option<MemoryRefusal>,
}

impl ParseLease {
    /// `lease`, which holds the PDF's bytes, grown for its parse until
    /// `deadline`.
    pub(super) fn new(lease: MemoryLease, deadline: Instant) -> Self {
        Self {
            leased: Mutex::new(Leased {
                lease,
                spare: 0,
                refused: None,
            }),
            deadline,
        }
    }

    /// The refusal that stopped the parse, when memory stopped it.
    pub(super) fn refused(&self) -> Option<MemoryRefusal> {
        lock(&self.leased).refused
    }
}

impl InspectionMemory for ParseLease {
    fn admit(&self, bytes: u64) -> Result<(), DecodeAdmissionError> {
        let mut leased = lock(&self.leased);
        if let Some(spare) = leased.spare.checked_sub(bytes) {
            leased.spare = spare;
            return Ok(());
        }
        let need = bytes - leased.spare;
        // Grown a reservation step at a time, so the parse does not ask once
        // per allocation; where only the step could never fit, the measured
        // need waits its turn instead.
        let step = need.max(RESERVE_STEP);
        let grown = match leased.lease.grow(step, self.deadline, &|| false) {
            Err(MemoryRefusal::Floor { .. }) if step > need => leased
                .lease
                .grow(need, self.deadline, &|| false)
                .map(|()| need),
            grown => grown.map(|()| step),
        };
        match grown {
            Ok(grown) => {
                leased.spare = leased.spare.saturating_add(grown).saturating_sub(bytes);
                Ok(())
            }
            Err(refusal) => {
                leased.refused.get_or_insert(refusal);
                Err(match refusal {
                    MemoryRefusal::Floor { needed, available } => {
                        DecodeAdmissionError::MemoryFloor { needed, available }
                    }
                    MemoryRefusal::WaitedOut { .. } => DecodeAdmissionError::Deadline,
                })
            }
        }
    }

    fn release(&self, bytes: u64) {
        let mut leased = lock(&self.leased);
        leased.spare = leased.spare.saturating_add(bytes);
    }
}

/// The lease's state changes in one step under its lock, so a holder that
/// panicked left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
