//! The tagging worker: the one thing that drives the engine's tagging
//! reconciler.
//!
//! The engine commits the markers with the writes, leases them and settles
//! them; it never starts a thread. This loop is the host half, shaped like the
//! embedding worker: make sure the tagger is the configured one, then drain
//! what is ready, then wait. Pickup is level-triggered: every pass reads the
//! markers that are ready now, and a commit to the job tables only wakes the
//! loop early. Everything the reconciler does is sync, so every pass runs on
//! a blocking thread.

use std::sync::Arc;
use std::time::Duration;

use oneiron::memory::extraction::ExtractionEncoder;
use oneiron::tagging::{TaggingBackoff, TaggingPass, TaggingReconciler};

use super::core::SyncServer;
use crate::oneironer::endpoint::ProbeOutcome;

/// Ceiling on the worker's own backoff while the tagger is down.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
/// The shortest wait between two passes that found nothing ready.
const MIN_IDLE: Duration = Duration::from_millis(250);

impl SyncServer {
    /// The model-slot workers serve starts: embedding and tagging, each only
    /// when its slot is configured.
    pub(crate) fn spawn_slot_workers(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        [self.spawn_embedding_worker(), self.spawn_tagging_worker()]
            .into_iter()
            .flatten()
            .collect()
    }

    /// Starts the worker, or returns `None` when no tagger is configured.
    pub(crate) fn spawn_tagging_worker(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        self.tagger.as_ref()?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move { server.tag_forever().await }))
    }

    async fn tag_forever(self: Arc<Self>) {
        // Subscribed before the first pass, so a commit between that pass and
        // the first wait still wakes the loop.
        let mut wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
        let Some(reconciler) = self.prepare_tagging().await else {
            return;
        };
        let idle = self.tagger.as_ref().map_or(MIN_IDLE, |slot| {
            Duration::from_millis(slot.config().idle_interval_ms).max(MIN_IDLE)
        });
        let mut backoff = FIRST_BACKOFF;
        loop {
            // Level-triggered: the pass reads what is ready, so every wake
            // queued before it is already answered by it.
            while wake.try_recv().is_ok() {}
            let pass = Arc::clone(&reconciler);
            let server = Arc::clone(&self);
            let outcome = tokio::task::spawn_blocking(move || {
                let drained = pass.drain_once_with(|trace| {
                    if let Some(slot) = server.tagger.as_ref() {
                        slot.log(trace);
                    }
                })?;
                let next = pass.next_ready_at()?;
                Ok::<(TaggingPass, Option<u64>), oneiron::Error>((drained, next))
            })
            .await;
            match outcome {
                Ok(Ok((pass, next_ready_at))) => {
                    let claimed = pass.traces.len();
                    let call_failed = pass.failed_calls > 0;
                    if call_failed {
                        // The tagger may come back as another model: probe
                        // before the next pass, then back off.
                        tracing::warn!("tagger call failed; backing off");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        if !self.tagger_still_configured().await {
                            return;
                        }
                        continue;
                    }
                    backoff = FIRST_BACKOFF;
                    if claimed > 0 {
                        continue;
                    }
                    let wait = self.until_ready(next_ready_at, idle);
                    tokio::select! {
                        _ = wake.recv() => {}
                        () = tokio::time::sleep(wait) => {}
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(?error, "tagging pass failed; backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(error) => {
                    tracing::error!(%error, "tagging pass task ended; worker stopping");
                    return;
                }
            }
        }
    }

    /// How long to wait for the next marker that will become ready, bounded
    /// by the idle interval.
    fn until_ready(&self, next_ready_at: Option<u64>, idle: Duration) -> Duration {
        let Some(at) = next_ready_at else {
            return idle;
        };
        let now = self.vault().now_recorded_at();
        Duration::from_secs(at.saturating_sub(now)).clamp(MIN_IDLE, idle)
    }

    /// Waits until the tagger answers as the configured one, then builds the
    /// reconciler and returns this worker's stale leases from a previous
    /// process to the queue. `None` when the tagger is refused.
    async fn prepare_tagging(self: &Arc<Self>) -> Option<Arc<TaggingReconciler>> {
        let mut backoff = FIRST_BACKOFF;
        loop {
            if !self.tagger_still_configured().await {
                return None;
            }
            if self
                .tagger
                .as_ref()
                .is_some_and(|slot| slot.card().is_some())
            {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        let server = Arc::clone(self);
        let built = tokio::task::spawn_blocking(move || {
            let slot = server
                .tagger
                .as_ref()
                .ok_or(oneiron::Error::InvariantViolation(
                    "tagging worker started without a tagger",
                ))?;
            let config = slot.config();
            let tagger = Arc::clone(slot.tagger()) as Arc<dyn ExtractionEncoder>;
            let reconciler = TaggingReconciler::new(Arc::clone(server.vault()), tagger)?
                .with_batch_size(config.batch_size)
                .with_backoff(TaggingBackoff {
                    first_secs: config.retry_backoff_secs,
                    max_secs: config.max_retry_backoff_secs,
                })
                .with_label_kinds(config.label_kinds());
            let released = reconciler.release_stale_leases()?;
            if released > 0 {
                tracing::info!(
                    released,
                    "tagging markers left leased by a stopped worker resume"
                );
            }
            Ok::<_, oneiron::Error>(reconciler)
        })
        .await;
        match built {
            Ok(Ok(reconciler)) => Some(Arc::new(reconciler)),
            Ok(Err(error)) => {
                tracing::error!(?error, "tagging worker cannot start; markers wait");
                None
            }
            Err(error) => {
                tracing::error!(%error, "tagging worker start task failed");
                None
            }
        }
    }

    /// Probes the tagger. `false` when it answers as another model, which
    /// stops the worker: the markers wait for a tagger that is the
    /// configured one. An unreachable tagger is still configured.
    async fn tagger_still_configured(self: &Arc<Self>) -> bool {
        let server = Arc::clone(self);
        let probed = tokio::task::spawn_blocking(move || {
            let slot = server.tagger.as_ref()?;
            Some(match slot.tagger().probe() {
                Ok(ProbeOutcome::Ready(card)) => {
                    slot.accept_card(card);
                    Ok(())
                }
                Ok(ProbeOutcome::Unreachable(_)) => Ok(()),
                Err(error) => Err(error),
            })
        })
        .await;
        match probed {
            Ok(Some(Ok(_))) => true,
            Ok(Some(Err(error))) => {
                tracing::error!(%error, "the tagger is not the configured one; tagging stops and markers wait");
                false
            }
            Ok(None) | Err(_) => false,
        }
    }
}
