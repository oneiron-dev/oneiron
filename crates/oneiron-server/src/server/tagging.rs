//! The tagging worker: the one thing that drives the engine's tagging
//! reconciler.
//!
//! The engine commits the markers with the writes, leases them and settles
//! them; it never starts a thread. This loop is the host half: make sure the
//! tagger is the configured one, release what a stopped worker left leased,
//! then hand the vault to its one [`coordinator`] (FIX 6755), which keeps live
//! and bulk markers in flight through the slot's dispatcher, live first.
//! Pickup is level-triggered: every claim reads the markers that are ready
//! now, and a commit to the job tables only wakes the loop early. Everything
//! the reconciler does is sync, so each of its units runs on a blocking
//! thread; only the wait for dispatcher room and for a call's answer is
//! async, and neither holds a transaction or an admission it has not claimed.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use oneiron::memory::extraction::ExtractionEncoder;
use oneiron::tagging::{TaggingBackoff, TaggingReconciler};

use super::core::SyncServer;
use super::housekeeping::{PassControl, admit_every_pass};
use crate::oneironer::endpoint::ProbeOutcome;
use coordinator::{Coordinator, StopFuture};

mod coordinator;

/// Ceiling on the worker's own backoff while the tagger is down.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
/// The shortest wait between two passes that found nothing ready.
const MIN_IDLE: Duration = Duration::from_millis(250);

/// What a probe of the tagger found: `Ready` when it answered as the
/// configured one and its card was accepted, `Unreachable` when it did not
/// answer but is still configured, `Refused` when it answered as another
/// model or the vault binds another extraction encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaggerConfigured {
    Ready,
    Unreachable,
    Refused,
}

impl SyncServer {
    /// The model-slot workers serve starts: embedding and tagging, each only
    /// when its slot is configured, the resident run pump when a code host
    /// serves, the seat host on the person's own runtime (FIX 4552), and the
    /// connector-call settler (ONE-2510) always.
    pub(crate) fn spawn_slot_workers(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        [self.spawn_embedding_worker(), self.spawn_tagging_worker()]
            .into_iter()
            .chain([
                self.spawn_media_embedding_worker(),
                self.spawn_resident_pump(),
                self.spawn_seat_host(),
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
    /// releases stale leases, each round's upkeep and each marker's claim
    /// are admitted through `pass`'s admission, and a claimed marker holds
    /// its admission through its call to the end of its settlement's write.
    /// A refused claim tags nothing and waits. While `pass` is paused (FIX
    /// 6902), no next marker is claimed; one already claimed settles.
    pub(crate) fn spawn_tagging_worker_admitted(
        self: &Arc<Self>,
        pass: PassControl,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.spawn_tagging_worker_until(pass, std::future::pending::<()>())
    }

    /// Starts the worker as [`Self::spawn_tagging_worker_admitted`] does,
    /// until `stop` resolves (FIX 7252): from then on no marker is claimed
    /// and no upkeep runs, a start not yet admitted ends at once, and the
    /// task ends once every call it made has settled. A claim or a start
    /// already admitted runs to its end, and a ready marker's call settles.
    pub(crate) fn spawn_tagging_worker_until(
        self: &Arc<Self>,
        pass: PassControl,
        stop: impl Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.tagger.as_ref()?;
        let server = Arc::clone(self);
        let stop: StopFuture = Box::pin(stop);
        Some(tokio::spawn(server.tag_forever(pass, stop)))
    }

    async fn tag_forever(self: Arc<Self>, control: PassControl, mut stop: StopFuture) {
        // Subscribed before the first read, so a commit between it and the
        // first wait still wakes the loop.
        let mut wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
        let Some(reconciler) = self.prepare_tagging(&control, &mut stop).await else {
            return;
        };
        // A failed coordinator restarts after a backoff, doubling from 1 s
        // to at most 60 s; a clean stop still stops it.
        let mut backoff = FIRST_BACKOFF;
        loop {
            let Some(coordinator) = Coordinator::new(
                Arc::clone(&self),
                Arc::clone(&reconciler),
                control.clone(),
                wake,
                stop,
            ) else {
                return;
            };
            let Some(mut pending) = coordinator.run().await else {
                return;
            };
            tracing::warn!(
                ?backoff,
                "tagging coordinator failed; restarting after its backoff"
            );
            tokio::select! {
                biased;
                () = pending.as_mut() => return,
                () = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
            wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
            stop = pending;
        }
    }

    /// Waits until the tagger answers as the configured one and `control`
    /// admits the start, then builds the reconciler and returns this
    /// worker's stale leases from a previous process to the queue, until
    /// `control` pauses; the first round's upkeep releases what is left.
    /// `None` when the tagger is refused, or when `stop` comes before the
    /// start is admitted; an admitted start runs to its end.
    async fn prepare_tagging(
        self: &Arc<Self>,
        control: &PassControl,
        stop: &mut StopFuture,
    ) -> Option<Arc<TaggingReconciler>> {
        let admit = control.admission();
        let mut backoff = FIRST_BACKOFF;
        let admission = loop {
            let configured = tokio::select! {
                biased;
                () = stop.as_mut() => return None,
                configured = self.tagger_still_configured() => configured,
            };
            if matches!(configured, TaggerConfigured::Refused) {
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
            tokio::select! {
                biased;
                () = stop.as_mut() => return None,
                () = tokio::time::sleep(backoff) => {}
            }
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

    /// Probes the tagger: `Ready` when it answers as the configured one,
    /// `Unreachable` when it does not answer but is still configured, and
    /// `Refused` when it answers as another model or the vault's manifest
    /// binds another extraction encoder, which stops the worker once what
    /// it owns has settled: the markers wait for a tagger that is the
    /// configured and bound one.
    async fn tagger_still_configured(self: &Arc<Self>) -> TaggerConfigured {
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
                return TaggerConfigured::Refused;
            }
            // A manifest that cannot be read this pass selects nothing new:
            // the configured tagger keeps serving and the next pass reads
            // it again.
            Ok(Some(Err(error))) => {
                tracing::warn!(%error, "the vault's extraction_encoder binding is unreadable; tagging continues");
            }
            Ok(None) | Err(_) => return TaggerConfigured::Refused,
        }
        let server = Arc::clone(self);
        let probed = tokio::task::spawn_blocking(move || {
            let slot = server.tagger.as_ref()?;
            Some(match slot.tagger().probe() {
                Ok(ProbeOutcome::Ready(card)) => {
                    slot.accept_card(card);
                    Ok(TaggerConfigured::Ready)
                }
                Ok(ProbeOutcome::Unreachable(_)) => Ok(TaggerConfigured::Unreachable),
                Err(error) => Err(error),
            })
        })
        .await;
        match probed {
            Ok(Some(Ok(configured))) => configured,
            Ok(Some(Err(error))) => {
                tracing::error!(%error, "the tagger is not the configured one; tagging stops and markers wait");
                TaggerConfigured::Refused
            }
            Ok(None) | Err(_) => TaggerConfigured::Refused,
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
