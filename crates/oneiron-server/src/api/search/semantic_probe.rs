//! Route-local owned semantic probe: the trimmed question and its embedding with one lease.
//!
//! The trimmed question `String` and the embedded `Vec<f32>` are adopted after
//! they allocate, on the process memory line's empty lease, with
//! `materialized(0, actual)`. Nothing here preadmits, waits for memory admission,
//! refuses, grows a reservation, or caps the probe; the byte counts name physical
//! capacity only. The native accounting mutex can still contend.

use std::mem::size_of;
use std::sync::Arc;

use oneiron::host_memory::{MachineMemory, MemoryLease};

use crate::embedder::EmbedQueryRefusal;
use crate::server::SyncServer;

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
    pub(super) fn finish(mut self, embedding: Vec<f32>) -> OwnedProbe {
        self.memory
            .materialized(0, (embedding.capacity() as u64) * (size_of::<f32>() as u64));
        OwnedProbe {
            embedding,
            question: self.text,
            memory: self.memory,
        }
    }

    /// Embeds the owned question on a blocking thread, adopting the result.
    ///
    /// The whole question moves into the task before the blocking embed call,
    /// so no request, handle, or result drop frees the lease before the actual
    /// text and vector. The join failure maps exactly as the server wrapper.
    pub(super) async fn embed_off_runtime(
        self,
        server: &Arc<SyncServer>,
    ) -> Result<OwnedProbe, EmbedQueryRefusal> {
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            let embedding = server.embed_query(self.as_str())?;
            Ok(self.finish(embedding))
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
