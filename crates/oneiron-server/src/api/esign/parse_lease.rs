//! A PDF inspection's parse on this machine's memory (FIX 8065): the
//! editor's geometry door, the anonymous one and the ceremony preview (FIX
//! 12230). The lease that admitted the PDF's own bytes (FIX 7649) grows as
//! the parse proceeds: every table, copy, decode and parsed object the
//! inspection is about to allocate is admitted through [`MemoryLease::grow`],
//! on the same line and until the deadline its door gives it (the input's
//! own; the anonymous door's runs from when its body is read, FIX 12304),
//! and refused only as that lease is, at the machine's floor or that deadline.
//! What a finished stage of the parse gives back stays in the lease for the
//! next one, so the lease holds the parse's peak. It is held until the
//! inspection returns.
use super::ingress::{MEMORY_WAIT, memory_refused};
use crate::machine::{MachineMemory, MemoryLease, MemoryRefusal};
use axum::response::Response;
use oneiron::blob_artifact::esign::render::{
    self, DecodeAdmissionError, InspectionMemory, PageGeometry,
};
use oneiron::office_body::RESERVE_STEP;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// `pdf`'s pages, inspected on `lease`, which holds its bytes, grown for its
/// parse until `deadline`. A parse memory stopped is answered as the input
/// lease's refusal is ([`memory_refused`]); any other failed inspection is
/// refused.
pub(super) fn inspected(
    lease: MemoryLease,
    deadline: Instant,
    pdf: &[u8],
    stream_decode_bytes: u64,
) -> Result<Vec<PageGeometry>, Response> {
    let parse = Arc::new(ParseLease::new(lease, deadline));
    render::inspect_pdf_pages_admitted(pdf, stream_decode_bytes, parse.clone()).map_err(|_| {
        match parse.refused() {
            Some(refusal) => memory_refused(refusal),
            None => super::refused(),
        }
    })
}

/// A PDF the vault holds, inspected as the editor's geometry door inspects
/// its own, its bytes leased before they are read (FIX 12304): `bytes`, its
/// length as the vault measured it unread, leased from this machine's
/// memory, waiting at most [`MEMORY_WAIT`]; then `read` reads it within what
/// the lease holds. A PDF that came to need more since it was measured (the
/// sealed output in place of the original) grows the lease to its length on
/// the same deadline and is read then. The lease is then grown for its parse
/// ([`inspected`]). Blocks its thread while it waits.
pub(super) fn inspected_from_vault(
    memory: &MachineMemory,
    bytes: u64,
    stream_decode_bytes: u64,
    read: impl Fn(u64) -> oneiron::Result<Result<Vec<u8>, u64>>,
) -> Result<Vec<PageGeometry>, Response> {
    let deadline = Instant::now() + MEMORY_WAIT;
    let mut lease = memory.lease(bytes, deadline).map_err(memory_refused)?;
    let pdf = loop {
        match read(lease.bytes()) {
            Ok(Ok(pdf)) => break pdf,
            Ok(Err(needed)) => lease
                .grow(needed.saturating_sub(lease.bytes()), deadline, &|| false)
                .map_err(memory_refused)?,
            Err(_) => return Err(super::refused()),
        }
    };
    inspected(lease, deadline, &pdf, stream_decode_bytes)
}

/// One inspection's lease, and why it stopped growing, if it did.
struct ParseLease {
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
    fn new(lease: MemoryLease, deadline: Instant) -> Self {
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
    fn refused(&self) -> Option<MemoryRefusal> {
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
