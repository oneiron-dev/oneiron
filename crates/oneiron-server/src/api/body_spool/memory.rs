//! Fixed spool-reader and streamed string-decoder buffers on the process line.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::machine::{MachineMemory, MemoryLease, MemoryRefusal};

use super::{BodySpool, SPOOL_PIECE};

/// Cancels a worker's memory wait when its awaiting body future leaves.
pub(super) struct StopOnDrop(pub(super) Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl BodySpool {
    /// Admits a spool reader on the transfer worker, before returning a spool
    /// to any native writer or allocating its reader buffer.
    pub(in crate::api) fn admit_reader(&self) -> Result<MemoryLease, MemoryRefusal> {
        MachineMemory::process()
            .lease_untimed(SPOOL_PIECE as u64, &|| self.stopped.load(Ordering::Relaxed))
    }

    /// Admits one text sink and one JSON reader before either allocates.
    /// Schema-name matching uses the caller's fixed-size stack array;
    /// native proposal decoding is separate.
    /// Called only on the transfer worker, outside every vault transaction.
    pub(in crate::api) fn admit_string_decode_buffers(&self) -> Result<MemoryLease, MemoryRefusal> {
        MachineMemory::process().lease_untimed((2 * SPOOL_PIECE) as u64, &|| {
            self.stopped.load(Ordering::Relaxed)
        })
    }
}

/// The existing API catalog answers a buffer that could not be admitted.
/// The untimed line returns WaitedOut only when the awaiting future left.
pub(in crate::api) fn decode_memory_refused(refusal: MemoryRefusal) -> crate::error::ApiError {
    match refusal {
        MemoryRefusal::Floor { .. } => crate::error::ApiError::internal_server_error(
            "this machine cannot allocate the widen request's decode buffers",
        ),
        MemoryRefusal::WaitedOut { .. } => super::not_whole(),
    }
}

/// A spool-reader allocation is memory capacity, never disk capacity or JSON.
pub(in crate::api) fn reader_memory_refused(refusal: MemoryRefusal) -> crate::error::ApiError {
    match refusal {
        MemoryRefusal::Floor { .. } => crate::error::ApiError::internal_server_error(
            "this machine cannot allocate the request body's spool reader buffer",
        ),
        MemoryRefusal::WaitedOut { .. } => super::not_whole(),
    }
}
