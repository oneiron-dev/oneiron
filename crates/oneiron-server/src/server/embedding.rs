//! The embedding worker: the one thing that drives the engine's reconciler.
//!
//! The engine queues pending rows, leases them and stores the vectors; it never
//! starts a thread. This loop is the host half: make the provider ready, then
//! drain until the queue is empty, sleep, repeat. Everything it calls is sync,
//! so every pass runs on a blocking thread rather than on a runtime worker.

use std::sync::Arc;
use std::time::Duration;

use oneiron::embed::{Embedder, PendingEmbeddingReconcileReport, PendingEmbeddingReconciler};

use super::core::SyncServer;
use crate::embedder::{EmbedQueryRefusal, QueryEmbedder};

/// Ceiling on the error backoff. Long enough that a sleeping laptop or a
/// stopped endpoint does not spin, short enough that recovery is automatic.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const FIRST_BACKOFF: Duration = Duration::from_secs(5);

/// What the read path needs to report about the active provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmbedderDescriptor {
    pub(crate) provider: &'static str,
    pub(crate) model_id: String,
    pub(crate) dimensions: usize,
}

impl SyncServer {
    /// The active provider's identity, or `None` at rung 0.
    pub(crate) fn embedder_descriptor(&self) -> Option<EmbedderDescriptor> {
        let slot = self.embedder.as_ref()?;
        Some(EmbedderDescriptor {
            provider: slot.provider().as_str(),
            model_id: slot.config().model_id.clone(),
            dimensions: slot.config().dimensions,
        })
    }

    /// Embeds query text through the active provider.
    ///
    /// Blocking: the endpoint provider makes a blocking HTTP call and the local
    /// provider runs a forward pass. Neither may happen on a runtime worker
    /// thread, so async callers take [`Self::embed_query_off_runtime`].
    fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedQueryRefusal> {
        let Some(slot) = self.embedder.as_ref() else {
            return Err(EmbedQueryRefusal::NotConfigured);
        };
        slot.embed_query(text)
    }

    /// Embeds query text on a blocking thread.
    ///
    /// The door every async caller uses. `reqwest`'s blocking client refuses to
    /// run inside an async context — it panics rather than deadlocking — and a
    /// local forward pass would stall a runtime worker for the length of the
    /// model, so the work goes to the blocking pool either way.
    pub(crate) async fn embed_query_off_runtime(
        self: &Arc<Self>,
        text: String,
    ) -> Result<Vec<f32>, EmbedQueryRefusal> {
        let server = Arc::clone(self);
        tokio::task::spawn_blocking(move || server.embed_query(&text))
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "query embedding task failed to join");
                Err(EmbedQueryRefusal::Failed)
            })
    }

    /// Starts the worker, or returns `None` when no embedder is configured.
    pub(crate) fn spawn_embedding_worker(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let slot = self.embedder.as_ref()?;
        let idle = Duration::from_millis(slot.config().idle_interval_ms.max(1));
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            let Some(reconciler) = server.prepare_reconciler().await else {
                return;
            };
            server.drain_forever(reconciler, idle).await;
        }))
    }

    /// Blocks (on a blocking thread) until the provider is serving.
    ///
    /// An unreachable endpoint or an unfetched model is not an error the server
    /// dies of: the vault is already open and already answering lexical and
    /// graph reads, so this retries with backoff and logs once per state change
    /// (OF-022, the two-tier write rule).
    async fn prepare_reconciler(self: &Arc<Self>) -> Option<Arc<PendingEmbeddingReconciler>> {
        let mut backoff = FIRST_BACKOFF;
        let mut complained = false;
        loop {
            match self.build_reconciler().await {
                Ok(reconciler) => {
                    if complained {
                        tracing::info!("embedder is ready; filling pending vectors");
                    }
                    return Some(reconciler);
                }
                Err(error) => {
                    if !complained {
                        tracing::warn!(
                            ?error,
                            "embedder is not ready; the vault serves lexical and graph reads and the worker keeps retrying"
                        );
                        complained = true;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    async fn build_reconciler(
        self: &Arc<Self>,
    ) -> oneiron::Result<Arc<PendingEmbeddingReconciler>> {
        let server = Arc::clone(self);
        let built = tokio::task::spawn_blocking(move || {
            let slot = server
                .embedder
                .as_ref()
                .ok_or(oneiron::Error::InvariantViolation(
                    "embedding worker started without an embedder",
                ))?;
            let embedder: Arc<dyn QueryEmbedder> = slot.ensure_ready()?;
            let config = slot.config();
            // No remote rung: one embedder, its locality recorded truthfully,
            // and no third-party route to gate, so no egress predicate is wired.
            Ok(PendingEmbeddingReconciler::new(
                Arc::clone(server.vault()),
                embedder as Arc<dyn Embedder>,
            )
            .with_batch_size(config.batch_size)
            .with_lease_duration_ms(config.lease_ms))
        })
        .await
        .map_err(|_| oneiron::Error::InvariantViolation("embedder load task failed to join"))?;
        built.map(Arc::new)
    }

    /// Drains while there is work, sleeps when there is none.
    async fn drain_forever(
        self: &Arc<Self>,
        reconciler: Arc<PendingEmbeddingReconciler>,
        idle: Duration,
    ) {
        let mut backoff = FIRST_BACKOFF;
        let mut failing = false;
        loop {
            let pass = Arc::clone(&reconciler);
            let outcome = tokio::task::spawn_blocking(move || pass.reconcile_once()).await;
            match outcome {
                Ok(Ok(report)) => {
                    if failing {
                        tracing::info!("embedding reconciliation recovered");
                        failing = false;
                        backoff = FIRST_BACKOFF;
                    }
                    if report.leased == 0 {
                        tokio::time::sleep(idle).await;
                        continue;
                    }
                    self.log_pass(&report);
                }
                Ok(Err(error)) => {
                    if !failing {
                        tracing::warn!(?error, "embedding reconciliation failed; backing off");
                        failing = true;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                // The blocking pool only fails to join on shutdown or a panic
                // inside the pass. Either way the loop has nothing left to
                // drive, and a silent exit would leave rows pending with no
                // trace of why.
                Err(error) => {
                    tracing::error!(%error, "embedding reconciliation task ended; worker stopping");
                    return;
                }
            }
        }
    }

    fn log_pass(&self, report: &PendingEmbeddingReconcileReport) {
        let truncations = self
            .embedder
            .as_ref()
            .and_then(crate::embedder::EmbedderSlot::truncations)
            .unwrap_or(0);
        tracing::info!(
            leased = report.leased,
            embedded = report.embedded,
            filled = report.filled,
            stale_fills = report.stale_fills,
            stale_jobs = report.stale_jobs,
            active_leases = report.active_leases,
            truncations,
            "embedding reconcile pass"
        );
    }
}
