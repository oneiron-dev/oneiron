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
    /// The coordinator of `server`'s tagger over `reconciler`, waking on
    /// `wake` and stopping on `stop`; `None` when no tagger is configured.
    pub(super) fn new(
        server: Arc<SyncServer>,
        reconciler: Arc<TaggingReconciler>,
        control: PassControl,
        wake: broadcast::Receiver<()>,
        stop: StopFuture,
    ) -> Option<Self> {
        let slot = server.tagger.as_ref()?;
        let tagger = Arc::clone(slot.tagger());
        let idle = Duration::from_millis(slot.config().idle_interval_ms).max(MIN_IDLE);
        // A round claims at least one marker.
        let batch = slot.config().batch_size.max(1);
        let backoff = Backoff {
            delay: FIRST_BACKOFF,
            until: None,
        };
        let admit = control.admission();
        Some(Self {
            server,
            reconciler,
            tagger,
            control,
            admit,
            wake,
            wake_open: true,
            idle,
            batch,
            want: None,
            calls: FuturesUnordered::new(),
            settlements: FuturesUnordered::new(),
            probe: None,
            stop: Some(stop),
            resident: [0; 2],
            backoff: [backoff; 2],
            store_backoff: backoff,
            paused_until: None,
            idle_until: None,
            probe_slice: None,
            next_retry: None,
            dirty: true,
            // The first round starts with the upkeep a pass starts with.
            upkeep_due: true,
            probe_due: false,
            probe_outage: false,
            claimed: 0,
            stopping: false,
            failed: false,
        })
    }

    /// Runs until the tagger is refused, a unit fails or the stop comes, and
    /// what it owns has settled. The stop to restart on when a unit failed
    /// and shutdown was not asked for; `None` on a clean stop.
    pub(super) async fn run(mut self) -> Option<StopFuture> {
        loop {
            self.read_stop();
            if self.drained() {
                return self.restart();
            }
            self.refill().await;
            if self.drained() {
                return self.restart();
            }
            let deadline = self.deadline();
            tokio::select! {
                () = wait_on(self.stop.as_mut()) => self.on_stop(),
                claim = wait_on(self.want.as_mut().map(|(_, room)| room)) => {
                    self.on_room(claim).await;
                }
                Some(called) = self.calls.next(), if !self.calls.is_empty() => {
                    self.on_called(*called);
                }
                Some((work, done)) = self.settlements.next(), if !self.settlements.is_empty() => {
                    self.on_settled(work, done);
                }
                woke = self.wake.recv(), if self.wake_open => self.on_wake(woke),
                configured = wait_on(self.probe.as_mut()) => self.on_probe(configured).await,
                () = sleep_until(deadline) => self.on_timer(),
            }
        }
    }

    /// Starts what is due and allowed: the probe between rounds, the upkeep a
    /// round starts with, and a read of the store when it may have changed.
    /// No new claim starts while the tagger is probed. The pause is read
    /// before a due probe starts, so a paused pass starts no probe.
    async fn refill(&mut self) {
        if self.stopping {
            self.want = None;
            return;
        }
        if self.paused() {
            return;
        }
        if self.probe_due && self.probe.is_none() {
            self.probe_due = false;
            let server = Arc::clone(&self.server);
            let probe = async move { server.tagger_still_configured().await };
            self.probe = Some(Box::pin(probe));
        }
        if self.probe.is_some() {
            return;
        }
        if self.upkeep_due {
            if self.held(ExtractionWork::Live) || self.store_held() {
                return;
            }
            self.upkeep().await;
            if self.upkeep_due || self.stopping {
                return;
            }
        }
        // A live claim already waiting for room is the claim to make.
        if self.dirty && self.wanted() != Some(ExtractionWork::Live) {
            self.dirty = false;
            self.look().await;
        }
    }

    /// Reads which class is ready, on a short blocking unit, and unless that
    /// class is held or full starts awaiting room in it. A ready live marker
    /// drops a bulk wait, so bulk never goes ahead of it.
    async fn look(&mut self) {
        // Level-triggered: this read answers every wake queued before it.
        while self.wake.try_recv().is_ok() {}
        let looked_at = self.reconciler.now();
        let reconciler = Arc::clone(&self.reconciler);
        let ready = tokio::task::spawn_blocking(move || reconciler.ready_class()).await;
        // A retry due by this read was claimable by it.
        self.next_retry = self.next_retry.filter(|at| *at > looked_at);
        let class = match ready {
            Ok(Ok(class)) => class,
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "tagging read failed; backing off");
                self.fail_store();
                return;
            }
            Err(error) => {
                tracing::error!(
                    panicked = error.is_panic(),
                    "tagging read task ended; coordinator restarting"
                );
                self.stopping = true;
                self.failed = true;
                return;
            }
        };
        let Some(work) = class else {
            // Nothing ready: a commit, a scheduled retry or the idle interval
            // starts the next read, and a round that claimed ends here.
            self.want = None;
            if self.claimed > 0 {
                self.end_round();
            }
            let wait = until_ready(self.reconciler.now(), self.next_retry, self.idle);
            self.idle_until = Some(Instant::now() + wait);
            return;
        };
        self.idle_until = None;
        if self.wanted() == Some(work) {
            return;
        }
        self.want = None;
        if self.held(work) || self.resident[lane(work)] >= self.tagger.pending_cap(work) {
            return;
        }
        // The vault's background tagging waits its own turn beside every
        // other caller's claims (FIX 9519).
        let caller = self.reconciler.caller().clone();
        self.want = Some((work, Box::pin(self.tagger.claim_room(work, caller))));
    }

    /// Room came in the wanted class: the pause, an admission and the pause
    /// again, then the claim on a blocking unit that reads the pause once
    /// more. A ready marker's call is submitted at once and keeps the
    /// admission; anything else gives back the room, and the admission once
    /// the unit's writes have ended.
    async fn on_room(&mut self, claim: DispatchClaim) {
        let Some((work, _)) = self.want.take() else {
            return;
        };
        // A stop that came with the room goes first.
        self.read_stop();
        if self.stopping || self.held(work) {
            return;
        }
        let Some(admission) = self.admitted() else {
            self.pause();
            return;
        };
        self.resident[lane(work)] += 1;
        let reconciler = Arc::clone(&self.reconciler);
        let tagger = Arc::clone(&self.tagger);
        let control = self.control.clone();
        let unit = tokio::task::spawn_blocking(move || {
            let prepared = (!control.paused()).then(|| reconciler.prepare_next(work));
            // A ready call's windows are planned here, on the blocking unit,
            // so its tokenizer encode never runs on this task (FIX 7331).
            let window = match &prepared {
                Some(Ok(TaggingPreparation::Ready(ready))) => {
                    Some(tagger.plan_windows(ready.input()))
                }
                _ => None,
            };
            (prepared, window, admission)
        })
        .await;
        let (prepared, window, admission) = match unit {
            Ok(unit) => unit,
            Err(error) => {
                tracing::error!(
                    panicked = error.is_panic(),
                    "tagging claim task ended; coordinator restarting"
                );
                self.resident[lane(work)] -= 1;
                self.stopping = true;
                self.failed = true;
                return;
            }
        };
        let (prepared, window) = match (prepared, window) {
            (Some(Ok(TaggingPreparation::Ready(prepared))), Some(window)) => (prepared, window),
            (outcome, _) => {
                self.unprepared(outcome);
                drop(admission);
                drop(claim);
                self.resident[lane(work)] -= 1;
                return;
            }
        };
        self.claimed += 1;
        if self.claimed >= self.batch {
            self.end_round();
        }
        // Refilled at once, without waiting for older calls.
        self.dirty = true;
        let started = Instant::now();
        let completion = self.tagger.submit(claim, window);
        self.calls.push(Box::pin(async move {
            let attempt = completion.answer().await;
            Box::new(Called {
                prepared,
                admission,
                attempt,
                timing: started.elapsed(),
            })
        }));
    }

    /// A claim that made no call: the pause read on its unit, a class with
    /// nothing ready, a live marker ready while bulk was asked, a marker that
    /// settled with no call, or an error that leaves its marker held for the
    /// next upkeep's hand-back.
    fn unprepared(&mut self, outcome: Option<oneiron::Result<TaggingPreparation>>) {
        match outcome {
            None => self.pause(),
            Some(Ok(TaggingPreparation::Settled(trace))) => {
                self.settled(&trace);
                self.dirty = true;
            }
            Some(Ok(_)) => self.dirty = true,
            Some(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "tagging claim failed; backing off");
                self.fail_store();
                self.upkeep_due = true;
            }
        }
    }

    /// A worker answered: the settlement goes to a blocking unit, carrying
    /// the admission its marker was claimed under. A failed call holds new
    /// claims in its class for the backoff.
    fn on_called(&mut self, called: Called) {
        let Called {
            prepared,
            admission,
            attempt,
            timing,
        } = called;
        let work = prepared.work();
        if attempt.result.is_ok() {
            self.backoff[lane(work)].delay = FIRST_BACKOFF;
        } else if self.fail(work) {
            tracing::warn!(?work, "tagger call failed; backing off");
        }
        let reconciler = Arc::clone(&self.reconciler);
        let settling = tokio::task::spawn_blocking(move || {
            let trace = reconciler.settle(prepared, attempt, timing);
            Box::new(Settlement { trace, admission })
        });
        let settled = async move { (work, settling.await) };
        self.settlements.push(Box::pin(settled));
    }

    /// A settlement ended: its trace is logged, then its admission and its
    /// resident place go. An error leaves its marker held for the next
    /// upkeep's hand-back.
    fn on_settled(&mut self, work: ExtractionWork, settled: Result<Box<Settlement>, JoinError>) {
        self.dirty = true;
        let Settlement { trace, admission } = match settled {
            Ok(settlement) => *settlement,
            Err(error) => {
                tracing::error!(
                    panicked = error.is_panic(),
                    "tagging settlement task ended; coordinator restarting"
                );
                self.resident[lane(work)] -= 1;
                self.stopping = true;
                self.failed = true;
                return;
            }
        };
        match trace {
            Ok(trace) => self.settled(&trace),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "tagging settlement failed; backing off");
                self.fail_store();
                self.upkeep_due = true;
            }
        }
        drop(admission);
        self.resident[lane(work)] -= 1;
    }

    /// Logs a settled marker's trace and keeps the retry it was given.
    fn settled(&mut self, trace: &TaggingTrace) {
        if let Some(slot) = self.server.tagger.as_ref() {
            slot.log(trace);
        }
        let retry_at = match trace.outcome {
            TaggingOutcome::Failed { retry_at, .. } | TaggingOutcome::Deferred { retry_at } => {
                retry_at
            }
            _ => return,
        };
        self.next_retry = Some(self.next_retry.map_or(retry_at, |at| at.min(retry_at)));
    }

    /// A commit woke the loop; a lagged wake missed some, so the store is
    /// read afresh either way. A wake into an idle loop starts a round, so the
    /// tagger is probed before its first claim, as it was before every pass.
    fn on_wake(&mut self, woke: Result<(), broadcast::error::RecvError>) {
        match woke {
            Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                if self.resident == [0; 2] {
                    self.end_round();
                }
                self.dirty = true;
            }
            Err(broadcast::error::RecvError::Closed) => self.wake_open = false,
        }
    }

    /// The probe answered: a tagger that is not the configured one stops new
    /// claims, and what is owned settles under the facts it was prepared
    /// with; every other marker waits in the store. An unanswered probe
    /// marks the outage, and the next ready answer after one wakes what
    /// waited it out: the holds clear and the engine's waiting retries run
    /// now. A ready answer with no outage behind it does nothing.
    async fn on_probe(&mut self, configured: TaggerConfigured) {
        self.probe = None;
        match configured {
            TaggerConfigured::Refused => {
                self.stopping = true;
                self.want = None;
            }
            TaggerConfigured::Unreachable => {
                self.probe_outage = true;
            }
            TaggerConfigured::Ready => {
                if !self.probe_outage {
                    return;
                }
                self.probe_outage = false;
                for backoff in &mut self.backoff {
                    backoff.until = None;
                    backoff.delay = FIRST_BACKOFF;
                }
                self.store_backoff.until = None;
                self.store_backoff.delay = FIRST_BACKOFF;
                self.probe_slice = None;
                self.dirty = true;
                let reconciler = Arc::clone(&self.reconciler);
                let now = reconciler.now();
                let done =
                    tokio::task::spawn_blocking(move || reconciler.wake_tagging_retries(now)).await;
                match done {
                    Ok(Ok(0)) => {}
                    Ok(Ok(woke)) => {
                        tracing::info!(
                            woke,
                            "the tagger recovered; waiting tagging retries run now"
                        )
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(kind = ?error.kind(), "tagging retries did not wake on the tagger's recovery")
                    }
                    // Best-effort: the wake never fails the loop, and the
                    // commit broadcast re-drives the claims it moved.
                    Err(error) => {
                        tracing::warn!(
                            panicked = error.is_panic(),
                            "tagging retry wake task ended; retries wait out their backoff"
                        )
                    }
                }
            }
        }
    }

    /// The stop came (FIX 7252): the room a claim awaits and the probe go,
    /// no claim or upkeep starts after, and every call already made settles
    /// before the loop ends. The stop is read once.
    fn on_stop(&mut self) {
        self.stop = None;
        self.stopping = true;
        self.want = None;
        self.probe = None;
    }

    /// Takes the stop if it has come, without waiting for it.
    fn read_stop(&mut self) {
        if self
            .stop
            .as_mut()
            .is_some_and(|stop| stop.as_mut().now_or_never().is_some())
        {
            self.on_stop();
        }
    }

    /// Whether the loop is stopping and owns nothing left to settle.
    fn drained(&self) -> bool {
        self.stopping && self.calls.is_empty() && self.settlements.is_empty()
    }

    /// The stop to restart on: a failed unit hands its still-pending stop
    /// back to the supervisor, which runs the next loop on it. A clean stop
    /// took the stop already, and a refused tagger keeps none.
    fn restart(self) -> Option<StopFuture> {
        if self.failed { self.stop } else { None }
    }

    /// A hold, the pacing slice or the idle wait ran out. The idle wait's
    /// end starts a round, as an empty pass's wait did: a probe, the upkeep,
    /// a read. The slice's end only probes, while a hold still parks the
    /// loop.
    fn on_timer(&mut self) {
        let now = Instant::now();
        if passed(&mut self.probe_slice, now) && self.holds_pending() {
            self.probe_due = true;
            self.probe_slice = Some(now + self.probe_slice_len());
        }
        if passed(&mut self.idle_until, now) {
            self.end_round();
        }
        passed(&mut self.paused_until, now);
        for backoff in &mut self.backoff {
            passed(&mut backoff.until, now);
        }
        passed(&mut self.store_backoff.until, now);
        self.dirty = true;
    }

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
        self.probe_slice = Some(now + self.probe_slice_len());
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
        self.probe_slice = Some(now + self.probe_slice_len());
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

    /// The pacing slice while holds park the loop: the largest live
    /// backoff delay, at least one first backoff.
    fn probe_slice_len(&self) -> Duration {
        let now = Instant::now();
        let mut len = FIRST_BACKOFF;
        for backoff in self
            .backoff
            .iter()
            .chain(std::iter::once(&self.store_backoff))
        {
            if backoff.until.is_some_and(|until| now < until) {
                len = len.max(backoff.delay);
            }
        }
        len
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
