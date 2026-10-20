//! The tagging worker: the one thing that drives the engine's tagging
//! reconciler.
//!
//! The engine commits the markers with the writes, leases them and settles
//! them; it never starts a thread. This loop is the host half, shaped like the
//! embedding worker: make sure the tagger is the configured one before every
//! pass, drain what is ready, then wait. Pickup is level-triggered: every pass
//! reads the markers that are ready now, and a commit to the job tables only
//! wakes the loop early. Everything the reconciler does is sync, so every pass
//! runs on a blocking thread.

use std::sync::Arc;
use std::time::Duration;

use oneiron::memory::extraction::ExtractionEncoder;
use oneiron::tagging::{TaggingBackoff, TaggingReconciler};

use super::core::SyncServer;
use super::housekeeping::{PassControl, admit_every_pass};
use crate::oneironer::endpoint::ProbeOutcome;

/// Ceiling on the worker's own backoff while the tagger is down.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
/// The shortest wait between two passes that found nothing ready.
const MIN_IDLE: Duration = Duration::from_millis(250);

impl SyncServer {
    /// The model-slot workers serve starts: embedding and tagging, each only
    /// when its slot is configured, the resident run pump when a code host
    /// serves, and the connector-call settler (ONE-2510) always.
    pub(crate) fn spawn_slot_workers(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        [self.spawn_embedding_worker(), self.spawn_tagging_worker()]
            .into_iter()
            .chain([
                self.spawn_media_embedding_worker(),
                self.spawn_resident_pump(),
                Some(self.spawn_connector_settler()),
            ])
            .flatten()
            .collect()
    }

    /// Starts the worker, or returns `None` when no tagger is configured.
    pub(crate) fn spawn_tagging_worker(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        self.spawn_tagging_worker_admitted(PassControl::unpaused(admit_every_pass()))
    }

    /// Starts the worker on a host with a write freeze: the start that
    /// releases stale leases and each drain pass are admitted through
    /// `pass`'s admission, and hold it on their blocking thread through
    /// every marker they settle. A refused pass tags nothing and waits.
    /// While `pass` is paused (FIX 6902), a running pass claims no next
    /// marker and ends as a pass with nothing more ready does.
    pub(crate) fn spawn_tagging_worker_admitted(
        self: &Arc<Self>,
        pass: PassControl,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.tagger.as_ref()?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move { server.tag_forever(pass).await }))
    }

    async fn tag_forever(self: Arc<Self>, control: PassControl) {
        // Subscribed before the first pass, so a commit between that pass and
        // the first wait still wakes the loop.
        let mut wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
        let Some(reconciler) = self.prepare_tagging(&control).await else {
            return;
        };
        let admit = control.admission();
        let idle = self.tagger.as_ref().map_or(MIN_IDLE, |slot| {
            Duration::from_millis(slot.config().idle_interval_ms).max(MIN_IDLE)
        });
        // The reconciler claims at least one marker a pass.
        let batch = self
            .tagger
            .as_ref()
            .map_or(1, |slot| slot.config().batch_size.max(1));
        let mut backoff = FIRST_BACKOFF;
        // The earliest retry a pass of this worker scheduled that no later
        // pass has reached: the next wake when no commit comes first.
        let mut next_retry: Option<u64> = None;
        loop {
            // Level-triggered: the pass reads what is ready, so every wake
            // queued before it is already answered by it.
            while wake.try_recv().is_ok() {}
            let Some(admission) = admit() else {
                tokio::time::sleep(idle).await;
                continue;
            };
            let started = reconciler.now();
            let pass = Arc::clone(&reconciler);
            let server = Arc::clone(&self);
            let pause = control.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                pass.drain_until_paused(&|| pause.paused(), |trace| {
                    if let Some(slot) = server.tagger.as_ref() {
                        slot.log(trace);
                    }
                })
            })
            .await;
            match outcome {
                Ok(Ok(pass)) => {
                    if pass.paused {
                        tracing::debug!(
                            settled = pass.traces.len(),
                            batch_left = batch.saturating_sub(pass.traces.len()),
                            "tagging pass paused by the reap freeze; unclaimed markers stay ready"
                        );
                    }
                    // A retry due when this pass began was claimable by it.
                    next_retry = next_retry
                        .filter(|at| *at > started)
                        .into_iter()
                        .chain(pass.earliest_retry_at())
                        .min();
                    if pass.failed_calls > 0 {
                        tracing::warn!("tagger call failed; backing off");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    } else {
                        backoff = FIRST_BACKOFF;
                        if pass.traces.is_empty() {
                            let wait = until_ready(reconciler.now(), next_retry, idle);
                            tokio::select! {
                                _ = wake.recv() => {}
                                () = tokio::time::sleep(wait) => {}
                            }
                        }
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "tagging pass failed; backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(error) => {
                    tracing::error!(
                        panicked = error.is_panic(),
                        "tagging pass task ended; worker stopping"
                    );
                    return;
                }
            }
            // Every pass settles its answers under the configured checkpoint,
            // so every pass follows a probe: the tagger may have been swapped
            // while the loop waited, backed off, or drained the last batch.
            if !self.tagger_still_configured().await {
                return;
            }
        }
    }

    /// Waits until the tagger answers as the configured one and `control`
    /// admits the start, then builds the reconciler and returns this
    /// worker's stale leases from a previous process to the queue, until
    /// `control` pauses; the first pass releases what is left. `None` when
    /// the tagger is refused.
    async fn prepare_tagging(
        self: &Arc<Self>,
        control: &PassControl,
    ) -> Option<Arc<TaggingReconciler>> {
        let admit = control.admission();
        let mut backoff = FIRST_BACKOFF;
        let admission = loop {
            if !self.tagger_still_configured().await {
                return None;
            }
            if self
                .tagger
                .as_ref()
                .is_some_and(|slot| slot.card().is_some())
                && let Some(admission) = admit()
            {
                break admission;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        };
        let server = Arc::clone(self);
        let pause = control.clone();
        let built = tokio::task::spawn_blocking(move || {
            let _admission = admission;
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
                });
            match reconciler.release_stale_leases_until_paused(&|| pause.paused()) {
                Ok(0) => {}
                Ok(released) => tracing::info!(
                    released,
                    "tagging markers left leased by a stopped worker resume"
                ),
                // The reconciler keeps them and its next pass releases them;
                // every other marker is served meanwhile.
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "tagging markers left leased by a stopped worker are released on the next pass"
                ),
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
                tracing::error!(
                    panicked = error.is_panic(),
                    "tagging worker start task failed"
                );
                None
            }
        }
    }

    /// Probes the tagger. `false` when it answers as another model, or when
    /// the vault's manifest binds another extraction encoder, which stops
    /// the worker: the markers wait for a tagger that is the configured and
    /// bound one. An unreachable tagger is still configured.
    async fn tagger_still_configured(self: &Arc<Self>) -> bool {
        let server = Arc::clone(self);
        let selected = tokio::task::spawn_blocking(move || {
            server
                .tagger
                .as_ref()
                .map(|slot| slot.selected_by(server.vault()))
        })
        .await;
        match selected {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(error)))
                if error
                    .downcast_ref::<crate::oneironer::EncoderNotSelected>()
                    .is_some() =>
            {
                tracing::error!(%error, "the vault does not select this tagger; tagging stops and markers wait");
                return false;
            }
            // A manifest that cannot be read this pass selects nothing new:
            // the configured tagger keeps serving and the next pass reads
            // it again.
            Ok(Some(Err(error))) => {
                tracing::warn!(%error, "the vault's extraction_encoder binding is unreadable; tagging continues");
            }
            Ok(None) | Err(_) => return false,
        }
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

/// How long to wait for the earliest scheduled retry, bounded by the idle
/// interval. `now` is the reconciler's clock, which no read moves.
fn until_ready(now: u64, next_retry: Option<u64>, idle: Duration) -> Duration {
    let Some(at) = next_retry else {
        return idle;
    };
    Duration::from_secs(at.saturating_sub(now)).clamp(MIN_IDLE, idle)
}
