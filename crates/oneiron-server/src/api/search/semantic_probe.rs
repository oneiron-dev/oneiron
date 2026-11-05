//! Route-local semantic question and probe custody on one memory lease.
//!
//! Text and returned vector storage are charged at their actual capacities.
//! A ready native slot's non-deadline call opportunistically pre-grows its
//! configured logical output footprint on that same lease only when the native
//! line grants it without a memory-FIFO wait, then reconciles the actual
//! capacity. Under contention the call keeps the original adoption-only path
//! with no reservation, so full cover before growth and queueing stay open
//! here. Deadline and space calls remain adoption-only. Provider scratch and
//! device memory are not covered.

use std::mem::size_of;
use std::sync::Arc;
use std::time::Instant;

use oneiron::host_memory::{MachineMemory, MemoryLease, MemoryRefusal};
use oneiron::llm::WorkCancel;

use crate::embedder::EmbedQueryRefusal;
use crate::server::SyncServer;

/// Request-drop pre-call checkpoint, not a memory wait or inference cancellation.
struct CancelOnDrop(WorkCancel);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The trimmed semantic question with the lease that names its text.
///
/// `text` is declared first so the query `String` frees before the guard on
/// every drop path.
pub(super) struct Question {
    pub(super) text: String,
    pub(super) memory: MemoryLease,
}

impl Question {
    /// Owns the same trimmed text allocation and adopts its actual capacity.
    pub(super) fn new(trimmed: &str) -> Self {
        let mut memory = MachineMemory::process().empty_lease();
        let text = trimmed.to_owned();
        memory.materialized(0, text.capacity() as u64);
        Self { text, memory }
    }

    /// Borrows the exact owned question text.
    pub(super) fn as_str(&self) -> &str {
        &self.text
    }

    /// Adopts the actual embedding capacity on the same lease and bundles the probe.
    pub(super) fn finish(self, embedding: Vec<f32>) -> OwnedProbe {
        self.finish_reserved(embedding, 0)
    }

    /// Replaces pending logical output bytes with actual vector capacity.
    fn finish_reserved(mut self, embedding: Vec<f32>, reserved: u64) -> OwnedProbe {
        self.memory.materialized(
            reserved,
            (embedding.capacity() as u64).saturating_mul(size_of::<f32>() as u64),
        );
        OwnedProbe {
            embedding,
            question: self.text,
            memory: self.memory,
        }
    }

    /// Pre-grows a ready slot's output only when immediately available, then calls that same slot off-runtime.
    ///
    /// The single growth attempt carries an already-due deadline, so the native
    /// line grants it only on an immediate fit and otherwise drops this
    /// attempt's own waiter before any Condvar wait. This adds no new
    /// memory-FIFO wait or hold-and-wait cycle while the question text is
    /// retained; native mutex acquisition may still contend. Under contention
    /// the call falls back to the original adoption-only path with zero
    /// reservation and no retry, queue wait, or new busy refusal. The logical
    /// minimum is not an allocator-capacity bound; the actual vector capacity
    /// is reconciled after the call. The worker retains the question and lease
    /// if the request drops. Request drop is only a pre-call checkpoint here,
    /// not a new memory wait or an already-running inference cancellation. The
    /// native floor stays the real dynamic reserve check and keeps the existing
    /// generic failure shape; no new cap, default, physical-floor constant,
    /// queue deadline, or timer is added.
    pub(super) async fn embed_off_runtime(
        self,
        server: &Arc<SyncServer>,
    ) -> Result<OwnedProbe, EmbedQueryRefusal> {
        let stopped = WorkCancel::new();
        let worker_stopped = stopped.clone();
        let _cancel = CancelOnDrop(stopped);
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            let mut this = self;
            let Some(slot) = server.embedder_slot() else {
                return Err(EmbedQueryRefusal::NotConfigured);
            };
            if slot.admitted_provider().is_none() {
                return Err(EmbedQueryRefusal::NotReady);
            }
            let output_bytes =
                (slot.config().dimensions as u64).saturating_mul(size_of::<f32>() as u64);
            // Opportunistic pre-growth only: the already-due deadline grants on
            // an immediate fit, else the native line drops this attempt's own
            // waiter before any Condvar wait. Contention adopts with zero.
            let reserved = match this.memory.grow(output_bytes, Instant::now(), &|| {
                worker_stopped.is_cancelled()
            }) {
                Ok(()) => output_bytes,
                Err(MemoryRefusal::WaitedOut { .. }) => 0,
                Err(refusal @ MemoryRefusal::Floor { .. }) => {
                    tracing::warn!(?refusal, "semantic query output reservation refused");
                    return Err(EmbedQueryRefusal::Failed);
                }
            };
            if worker_stopped.is_cancelled() {
                return Err(EmbedQueryRefusal::Failed);
            }
            let embedding = slot.embed_query(this.as_str())?;
            Ok(this.finish_reserved(embedding, reserved))
        })
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(
                panicked = error.is_panic(),
                "query embedding task failed to join"
            );
            Err(EmbedQueryRefusal::Failed)
        })
    }
}

/// The owned semantic probe: actual embedding and question with their lease.
///
/// `embedding` and `question` are declared before `memory` so both free before
/// the guard on every drop path.
pub(super) struct OwnedProbe {
    pub(super) embedding: Vec<f32>,
    pub(super) question: String,
    pub(super) memory: MemoryLease,
}
