//! The tagging coordinator (FIX 6755): one loop per vault that keeps live and
//! bulk markers in flight through the slot's one dispatcher.
//!
//! Each claim reads which class is ready, awaits room in that class with
//! nothing held, then reads the pause, takes a housekeeping admission and
//! reads the pause again; the claim itself runs on a short blocking unit,
//! which reads the pause once more. A ready marker's call is submitted at
//! once, and its admission rides with it through the call to the end of its
//! settlement's write. A ready live marker is never passed over for bulk: a
//! wake that shows one drops a bulk wait, and while live is held or full no
//! bulk is claimed. A running call is never pre-empted; under unbroken live
//! load the dispatcher still gives bulk a unit after each live streak
//! (FIX 9519), with no timer. The markers resident in a class,
//! claimed through settled, stay within the dispatcher's pending cap for it;
//! the rest wait in the store. A failed call holds new claims in its class
//! for its backoff (a live failure holds bulk too), while every call
//! already issued settles and wakes stay observed. A store error holds bulk
//! claims and the upkeep for its own backoff, never live. A call
//! already claimed can outlast the managed reap's bound: nothing times it
//! out, cancels it or refuses it. A stop from the host (FIX 7252) ends new
//! claims and upkeep, and the loop returns once every call it made has
//! settled.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use oneiron::memory::extraction::{EncoderAttempt, ExtractionWork};
use oneiron::tagging::{
    PreparedTagging, TaggingOutcome, TaggingPreparation, TaggingReconciler, TaggingTrace,
};
use tokio::sync::broadcast;
use tokio::task::JoinError;
use tokio::time::Instant;

use super::{FIRST_BACKOFF, MAX_BACKOFF, MIN_IDLE, TaggerConfigured, until_ready};
use crate::oneironer::{DispatchClaim, ProviderTagger};
use crate::server::core::SyncServer;
use crate::server::housekeeping::{HousekeepingAdmission, PassControl};

mod event_loop;

/// Room a claim awaits in its class.
type RoomFuture = Pin<Box<dyn std::future::Future<Output = DispatchClaim> + Send>>;
/// A call in flight, until its worker answers.
type CallFuture = Pin<Box<dyn std::future::Future<Output = Box<Called>> + Send>>;
/// A settlement's end, with the class of its marker.
type Settled = (ExtractionWork, Result<Box<Settlement>, JoinError>);
/// A settlement on its blocking unit.
type SettleFuture = Pin<Box<dyn std::future::Future<Output = Settled> + Send>>;
/// The probe of the tagger between rounds.
type ProbeFuture = Pin<Box<dyn std::future::Future<Output = TaggerConfigured> + Send>>;
/// The host's stop: once it resolves, no new claim and no upkeep.
pub(super) type StopFuture = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// A call whose worker answered, with what its settlement needs.
struct Called {
    prepared: PreparedTagging,
    /// The admission its marker was claimed under.
    admission: Box<dyn Send>,
    attempt: EncoderAttempt,
    /// From its submission to its answer.
    timing: Duration,
}

/// A settlement that ran, with the admission it held: dropped only once its
/// trace is logged.
struct Settlement {
    trace: oneiron::Result<TaggingTrace>,
    admission: Box<dyn Send>,
}

/// One hold's backoff: how long its next failure holds its claims, and
/// until when the last one does.
#[derive(Clone, Copy)]
struct Backoff {
    delay: Duration,
    until: Option<Instant>,
}

/// The loop's state. Only it claims, so one vault has one drain owner.
pub(super) struct Coordinator {
    server: Arc<SyncServer>,
    reconciler: Arc<TaggingReconciler>,
    tagger: Arc<ProviderTagger>,
    control: PassControl,
    admit: HousekeepingAdmission,
    wake: broadcast::Receiver<()>,
    /// Whether the store's wake channel is still open.
    wake_open: bool,
    idle: Duration,
    /// Claims a round makes before the tagger is probed and the upkeep runs.
    batch: usize,
    /// The class a claim awaits room in, and that room.
    want: Option<(ExtractionWork, RoomFuture)>,
    calls: FuturesUnordered<CallFuture>,
    settlements: FuturesUnordered<SettleFuture>,
    probe: Option<ProbeFuture>,
    /// The host's stop, until it comes.
    stop: Option<StopFuture>,
    /// Markers resident in each class, claimed through settled.
    resident: [usize; 2],
    backoff: [Backoff; 2],
    /// The store's own hold over bulk claims and the upkeep.
    store_backoff: Backoff,
    /// No claim and no upkeep before this: the host paused or refused.
    paused_until: Option<Instant>,
    /// When the loop reads the store again with no wake: the idle or retry
    /// wait.
    idle_until: Option<Instant>,
    /// When the pacing slice ends while a hold parks the loop: its expiry
    /// probes the tagger, without ending the round.
    probe_slice: Option<Instant>,
    /// The pacing slice's own delay: the next slice lands this long after
    /// the last arming. It doubles while holds park the loop, capped, and
    /// returns to the first backoff once no hold is left or the tagger
    /// answers again, so the first slice of an outage lands before any
    /// hold longer than the first backoff expires.
    probe_slice_delay: Duration,
    /// The earliest retry a settled marker was given that no read has
    /// reached since.
    next_retry: Option<u64>,
    /// Whether the store may hold ready work no read has seen.
    dirty: bool,
    upkeep_due: bool,
    probe_due: bool,
    /// The probe went unanswered since the tagger last answered: its next
    /// ready answer wakes what waited out the outage.
    probe_outage: bool,
    /// Claims since the round began.
    claimed: usize,
    /// The tagger is not the configured one, a unit failed or the stop
    /// came: no new claim, and the loop ends once what it owns has settled.
    stopping: bool,
    /// A claim, settle, upkeep or read unit ended: the supervisor restarts
    /// the loop once what it owns has settled, unless the stop came too.
    failed: bool,
}

impl Coordinator {
    /// The round ends: the tagger is probed and the upkeep runs before the
    /// next claim.
    fn end_round(&mut self) {
        self.claimed = 0;
        self.probe_due = true;
        self.upkeep_due = true;
    }

    /// The upkeep a round starts with: admitted, on a blocking unit that reads
    /// the pause between its units. A pause or an error leaves it due.
    async fn upkeep(&mut self) {
        let Some(admission) = self.admitted() else {
            self.pause();
            return;
        };
        let reconciler = Arc::clone(&self.reconciler);
        let control = self.control.clone();
        let done = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            reconciler.upkeep_until_paused(&|| control.paused())
        })
        .await;
        match done {
            Ok(Ok(false)) => self.upkeep_due = false,
            Ok(Ok(true)) => self.pause(),
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "tagging upkeep failed; backing off");
                self.fail_store();
            }
            Err(error) => {
                tracing::error!(
                    panicked = error.is_panic(),
                    "tagging upkeep task ended; coordinator restarting"
                );
                self.stopping = true;
                self.failed = true;
            }
        }
    }

    /// The pause, then an admission, then the pause again (FIX 6902): `None`
    /// when either read finds the host paused or it refuses the admission.
    fn admitted(&self) -> Option<Box<dyn Send>> {
        if self.control.paused() {
            return None;
        }
        let admission = (self.admit)()?;
        if self.control.paused() {
            return None;
        }
        Some(admission)
    }

    /// The host paused background work or refused its admission: no claim
    /// and no upkeep for the idle interval. Calls in flight settle under the
    /// admissions they hold, and every unclaimed marker stays ready.
    fn pause(&mut self) {
        tracing::debug!("tagging paused; claimed markers settle, the rest stay ready");
        self.paused_until = Some(Instant::now() + self.idle);
        self.dirty = true;
    }

    /// A call in `work`'s class failed: no new claim in the class for its
    /// backoff, and a live failure holds bulk too. A class already held
    /// keeps its hold, so calls that fail together count once. Whether this
    /// failure started a hold.
    fn fail(&mut self, work: ExtractionWork) -> bool {
        let now = Instant::now();
        let backoff = &mut self.backoff[lane(work)];
        if backoff.until.is_some_and(|until| now < until) {
            return false;
        }
        let until = now + backoff.delay;
        backoff.until = Some(until);
        backoff.delay = (backoff.delay * 2).min(MAX_BACKOFF);
        if work == ExtractionWork::Live {
            let bulk = &mut self.backoff[lane(ExtractionWork::Bulk)];
            bulk.until = Some(bulk.until.map_or(until, |held| held.max(until)));
        }
        if self.probe_slice.is_none() {
            self.probe_slice = Some(now + self.probe_slice_delay);
        }
        true
    }

    /// A store read, claim, settlement or upkeep failed: bulk claims and
    /// the upkeep wait out the store's own backoff, while live claims go
    /// on. A store already held keeps its hold, so errors that fail
    /// together count once. Whether this failure started a hold.
    fn fail_store(&mut self) -> bool {
        let now = Instant::now();
        let store = &mut self.store_backoff;
        if store.until.is_some_and(|until| now < until) {
            return false;
        }
        store.until = Some(now + store.delay);
        store.delay = (store.delay * 2).min(MAX_BACKOFF);
        if self.probe_slice.is_none() {
            self.probe_slice = Some(now + self.probe_slice_delay);
        }
        true
    }

    /// The class a claim awaits room in, if one does.
    fn wanted(&self) -> Option<ExtractionWork> {
        self.want.as_ref().map(|(work, _)| *work)
    }

    /// Whether new claims in `work`'s class wait out a failure: its own
    /// backoff, or, for bulk, the store's hold.
    fn held(&self, work: ExtractionWork) -> bool {
        if work == ExtractionWork::Bulk && self.store_held() {
            return true;
        }
        self.backoff[lane(work)]
            .until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Whether a store error still holds bulk claims and the upkeep.
    fn store_held(&self) -> bool {
        self.store_backoff
            .until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Whether the host's pause or refusal still holds new claims.
    fn paused(&self) -> bool {
        self.paused_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Whether a failure hold still parks new claims: the pacing slice
    /// only probes while one does.
    fn holds_pending(&self) -> bool {
        self.held(ExtractionWork::Live) || self.held(ExtractionWork::Bulk)
    }

    /// When the loop wakes with no event: the end of a hold, of the pacing
    /// slice or of the idle wait.
    fn deadline(&self) -> Option<Instant> {
        [
            self.paused_until,
            self.backoff[0].until,
            self.backoff[1].until,
            self.store_backoff.until,
            self.idle_until,
            self.probe_slice,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// The index of `work`'s class in the per-class state.
fn lane(work: ExtractionWork) -> usize {
    match work {
        ExtractionWork::Live => 0,
        ExtractionWork::Bulk => 1,
    }
}

/// Clears `until` once `now` has reached it; whether it did.
fn passed(until: &mut Option<Instant>, now: Instant) -> bool {
    if until.is_some_and(|at| at <= now) {
        *until = None;
        return true;
    }
    false
}

/// Awaits `future` when there is one; with none, never resolves.
async fn wait_on<F: std::future::Future + Unpin>(future: Option<&mut F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// Sleeps until `deadline`; with none, never wakes.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
