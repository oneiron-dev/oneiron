//! The recall verb as every server transport runs it.
//!
//! One place builds recall's execution inputs, so the HTTP facade and the
//! WebSocket read RPC return the same pack for the same request: the query is
//! embedded whenever the vault's embedder is serving, and the caller's
//! `as_of` rides along. A vault with no embedder, or one still loading its
//! model, recalls on its sparse signals and says so (`sparse: true`).

use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryPack, MemoryResult};
use oneiron::task_verb::sdk::RecallRequest;
use oneiron::{EdgeActorClass, EntityId};

use super::core::SyncServer;
use crate::embedder::EmbedQueryRefusal;

impl SyncServer {
    /// Runs `recall` for `memory` with the server's execution inputs.
    ///
    /// Blocking: it may embed the query and it reads the vault. Async callers
    /// take [`Self::recall_off_runtime`]; a synchronous caller that may sit on
    /// a runtime worker wraps it in [`blocking`].
    pub(crate) fn recall(
        &self,
        memory: &Memory<'_>,
        input: RecallRequest,
    ) -> MemoryResult<MemoryPack> {
        oneiron::task_verb::sdk::recall_with_vector(memory, input, |query| {
            self.recall_query_vector(query)
        })
    }

    /// [`Self::recall`] for `actor`, on the blocking pool.
    pub(crate) async fn recall_off_runtime(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        input: RecallRequest,
    ) -> MemoryResult<MemoryPack> {
        let server = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            server.recall(&server.vault.memory(actor, class), input)
        })
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "recall task failed to join");
            Err(MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "recall did not finish",
                &["Retry the call."],
            ))
        })
    }

    /// The query's vector, or `None` when no embedder is serving.
    fn recall_query_vector(&self, query: &str) -> Option<Vec<f32>> {
        match self.embedder.as_ref()?.embed_query(query) {
            Ok(vector) => Some(vector),
            // The model is still loading; the worker logs its own progress.
            Err(EmbedQueryRefusal::NotReady | EmbedQueryRefusal::NotConfigured) => None,
            Err(EmbedQueryRefusal::Failed) => {
                tracing::debug!("recall runs sparse: the query did not embed");
                None
            }
        }
    }
}

/// Runs blocking work from a synchronous caller that may sit on a runtime
/// worker. On a multi-thread runtime worker the worker hands its other tasks
/// to another thread first; inside a current-thread runtime the work runs on
/// a thread of its own, outside the async context; anywhere else it simply
/// runs. Not for use inside a `LocalSet`, which the server never runs.
pub(crate) fn blocking<R: Send>(work: impl FnOnce() -> R + Send) -> R {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        Ok(_) => std::thread::scope(|scope| {
            scope
                .spawn(work)
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }),
        Err(_) => work(),
    }
}
