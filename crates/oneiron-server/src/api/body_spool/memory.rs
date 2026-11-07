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
        MachineMemory::process().lease_untimed(SPOOL_PIECE as u64, &|| {
            self.stopped.load(Ordering::Relaxed)
        })
    }

    /// Admits the sealed object's source reader, head writer, base64 text
    /// and decoded output before any buffer allocates or holds a partial lease.
    pub(in crate::api) fn admit_sealed_decode_buffers(&self) -> Result<MemoryLease, MemoryRefusal> {
        let bytes = 2 * SPOOL_PIECE
            + super::json::BASE64_TEXT_BUFFER_BYTES
            + super::json::BASE64_DECODE_BUFFER_BYTES;
        MachineMemory::process().lease_untimed(bytes as u64, &|| {
            self.stopped.load(Ordering::Relaxed)
        })
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

/// The combined sealed-reader working buffers keep memory's own response.
pub(in crate::api) fn sealed_decode_memory_refused(refusal: MemoryRefusal) -> crate::error::ApiError {
    match refusal {
        MemoryRefusal::Floor { .. } => crate::error::ApiError::internal_server_error(
            "this machine cannot allocate the custody request's decode buffers",
        ),
        MemoryRefusal::WaitedOut { .. } => super::not_whole(),
    }
}

/// The raw spool's finite payload phase, on one original process lease.
/// The queue, producer, current piece and worker buffer share its room.
pub(in crate::api) struct RawSpoolMemory(std::sync::Mutex<MemoryLease>);

impl RawSpoolMemory {
    pub(in crate::api) fn admit(bytes: u64, stopped: &AtomicBool) -> Result<Arc<Self>, MemoryRefusal> {
        let memory = MachineMemory::process()
            .lease_untimed(bytes, &|| stopped.load(Ordering::Relaxed))?;
        Ok(Arc::new(Self(std::sync::Mutex::new(memory))))
    }

    pub(in crate::api) fn materialized(&self, actual: u64) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .materialized(actual, actual);
    }

    pub(in crate::api) fn reclaimed_after(&self, bytes: u64, free: impl FnOnce()) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reclaimed_after(bytes, free);
    }
}

/// Owns the complete feed future until all producer payloads are dropped.
/// Only then can its completion wake the raw worker for the next phase.
pub(super) struct FeedCompletion<F: std::future::Future<Output = ()>> {
    feed: Option<std::pin::Pin<Box<F>>>,
    completed: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<F: std::future::Future<Output = ()>> FeedCompletion<F> {
    pub(super) fn new(
        feed: F,
        completed: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            feed: Some(Box::pin(feed)),
            completed: Some(completed),
        }
    }

    pub(super) fn future(&mut self) -> std::pin::Pin<&mut F> {
        self.feed.as_mut().expect("feed remains until completion").as_mut()
    }

    pub(super) fn finish(mut self) {
        drop(self.feed.take());
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(());
        }
    }
}

impl<F: std::future::Future<Output = ()>> Drop for FeedCompletion<F> {
    fn drop(&mut self) {
        drop(self.feed.take());
        // The completion sender closes only after the producer's future is gone.
    }
}
