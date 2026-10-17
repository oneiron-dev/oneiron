//! Per-request retrieval deadlines: stage boundaries, in-stage checkpoints and
//! the share of the budget the answer keeps.
use crate::embed::InputKind;
use crate::error::{Error, Result};
use crate::rerank::Reranker;
use crate::store::RetrievalSignal;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The share of a [`RetrievalDeadline::hard`] budget the retrieval stages may
/// spend, in quarters. The last quarter is the answer's: fusion of the stages
/// that finished, the read fences and the pack assembly run in it.
const STAGE_QUARTERS: u32 = 3;

/// A deadline shared by the stages of exactly one retrieval.
///
/// No stage starts once the stage time is spent, and a running stage yields
/// at its next checkpoint (every candidate its scope gate reads) when its
/// share of that time runs out: the stage drops its partial work, and the
/// stages that finished are fused and returned. A channel cut that way is not
/// opened again in the same retrieval: a context pack reads its memory, skill
/// and agent lanes in turn, and the slow channel would spend the share of the
/// stages after it in each. Admission and the final filters always run.
/// `was_cut_short` means requested work was actually skipped or cut, not just
/// that time passed.
pub struct RetrievalDeadline {
    /// When the answer is due.
    at: Instant,
    /// When the retrieval stages stop; the time after it is the answer's.
    stages_by: Instant,
    /// The instant the open stage's share counts from.
    origin: Instant,
    /// Nanoseconds after `origin` the open stage may run to; 0 when no stage
    /// is open, so a checkpoint outside a stage never fires.
    stage_until: AtomicU64,
    /// The open stage's channel, as its bit in `cut_channels`; 0 when none.
    open_channel: AtomicU32,
    /// The channels cut at their share so far, one bit per signal.
    cut_channels: AtomicU32,
    cut_short: AtomicBool,
    cancelled: AtomicBool,
    /// A deadline test's still clock: how far a slow test stage has moved it
    /// past `origin` ([`still_deadline_clock_for_test`]); `None` on the
    /// monotonic clock.
    #[cfg(any(test, feature = "test-hooks"))]
    still: Option<AtomicU64>,
}
impl RetrievalDeadline {
    /// Raw monotonic deadline, including deadlines that already passed. The
    /// stages may run up to it; the answer's assembly runs after it.
    pub fn at(at: Instant) -> Self {
        Self::split(Instant::now(), at, at)
    }
    /// Convenience budget for anytime retrieval.
    pub fn after(duration: Duration) -> Self {
        Self::at(Instant::now() + duration)
    }
    /// A hard deadline: the answer is due `budget` after `started`, and the
    /// retrieval stages stop at three quarters of it so that fusion and the
    /// fenced assembly fit in the rest. Call mode and every request
    /// `deadline_ms` run under one.
    pub fn hard(started: Instant, budget: Duration) -> Self {
        Self::split(
            started,
            started + budget,
            started + budget / 4 * STAGE_QUARTERS,
        )
    }
    fn split(origin: Instant, at: Instant, stages_by: Instant) -> Self {
        Self {
            at,
            stages_by,
            origin,
            stage_until: AtomicU64::new(0),
            open_channel: AtomicU32::new(0),
            cut_channels: AtomicU32::new(0),
            cut_short: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-hooks"))]
            still: STILL_CLOCK
                .with(std::cell::Cell::get)
                .then_some(AtomicU64::new(0)),
        }
    }
    /// The clock every stage, share and answer check reads.
    fn now(&self) -> Instant {
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(moved) = &self.still {
            return self.origin + Duration::from_nanos(moved.load(Ordering::Relaxed));
        }
        Instant::now()
    }
    /// When the answer is due. A door that cannot wait longer stops here.
    #[must_use]
    pub fn answer_at(&self) -> Instant {
        self.at
    }
    /// Whether execution skipped or cut a requested stage at the deadline.
    pub fn was_cut_short(&self) -> bool {
        self.cut_short.load(Ordering::Relaxed)
    }
    /// Requests the best admitted pack at the next stage boundary or checkpoint.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    /// Whether the answer's time has come: optional work after the stages
    /// (such as the scope census) stops here.
    pub(crate) fn answer_due(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed) || self.now() >= self.at
    }
    pub(crate) fn stop_before_stage(&self) -> bool {
        if self.cancelled.load(Ordering::Relaxed) || self.now() >= self.stages_by {
            self.cut_short.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    /// Opens the next of `stages_left` stages, the `signal` channel's, with
    /// an equal share of the stage time left, so one slow stage cannot
    /// starve the ones after it. `false`, with nothing opened, once the stage
    /// time is spent or when this channel was already cut.
    pub(crate) fn open_stage(&self, signal: RetrievalSignal, stages_left: usize) -> bool {
        if self.stop_before_stage() {
            return false;
        }
        let channel = channel_bit(signal);
        if self.cut_channels.load(Ordering::Relaxed) & channel != 0 {
            self.cut_short.store(true, Ordering::Relaxed);
            return false;
        }
        let now = self.now();
        let share = self.stages_by.saturating_duration_since(now)
            / u32::try_from(stages_left.max(1)).unwrap_or(u32::MAX);
        let until = (now + share).saturating_duration_since(self.origin);
        let nanos = u64::try_from(until.as_nanos()).unwrap_or(u64::MAX).max(1);
        self.stage_until.store(nanos, Ordering::Relaxed);
        self.open_channel.store(channel, Ordering::Relaxed);
        true
    }
    pub(crate) fn close_stage(&self) {
        self.stage_until.store(0, Ordering::Relaxed);
        self.open_channel.store(0, Ordering::Relaxed);
    }
    /// The in-stage checkpoint. Inside an open stage whose share has run out
    /// it marks the run cut and raises [`Error::RetrievalStageCut`], which
    /// the stage runner catches; outside a stage it never fires.
    pub(crate) fn checkpoint(&self) -> Result<()> {
        let until = self.stage_until.load(Ordering::Relaxed);
        if until == 0 {
            return Ok(());
        }
        let elapsed = self.now().saturating_duration_since(self.origin);
        if self.cancelled.load(Ordering::Relaxed)
            || u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX) >= until
        {
            self.cut_short.store(true, Ordering::Relaxed);
            self.cut_channels
                .fetch_or(self.open_channel.load(Ordering::Relaxed), Ordering::Relaxed);
            return Err(Error::RetrievalStageCut);
        }
        Ok(())
    }
    /// When a typed decision's work stops. A quarter of the time stays the answer's, for
    /// validation, the receipt and delivery, under [`Self::at`] as under [`Self::hard`].
    fn decision_work_by(&self) -> Instant {
        let total = self.at.saturating_duration_since(self.origin);
        self.stages_by.min(self.origin + total / 4 * STAGE_QUARTERS)
    }
    /// The work time a typed decision has left. A provider's client waits no longer.
    #[must_use]
    pub fn decision_time_left(&self) -> Duration {
        self.decision_work_by()
            .saturating_duration_since(self.now())
    }
    /// Whether a typed decision may start a measurement: the caller has not taken the
    /// answer early, and the work time is not spent.
    pub(crate) fn decision_may_start(&self) -> bool {
        !self.cancelled.load(Ordering::Relaxed) && self.now() < self.decision_work_by()
    }
    /// The call's whole budget, from its start to the answer's time.
    pub(crate) fn budget(&self) -> Duration {
        self.at.saturating_duration_since(self.origin)
    }
    /// The time the call has used so far.
    pub(crate) fn used(&self) -> Duration {
        self.now().saturating_duration_since(self.origin)
    }
}

/// `signal`'s bit in [`RetrievalDeadline`]'s channel sets.
fn channel_bit(signal: RetrievalSignal) -> u32 {
    1 << signal as u32
}

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static STILL_CLOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Makes the deadlines this thread creates read a still clock, which moves
/// only as a slow test stage spends time ([`SlowRetrievalStage`]): whether a
/// stage opens, where its share ends and whether the answer is late no
/// longer depend on how fast the host runs. Returns the setting it replaced.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn still_deadline_clock_for_test(still: bool) -> bool {
    STILL_CLOCK.with(|clock| clock.replace(still))
}

#[cfg(any(test, feature = "test-hooks"))]
impl RetrievalDeadline {
    /// Spends `step` of a slow test stage: moves a still clock, or sleeps.
    fn spend(&self, step: Duration) {
        match &self.still {
            Some(moved) => {
                let nanos = u64::try_from(step.as_nanos()).unwrap_or(u64::MAX);
                moved.fetch_add(nanos, Ordering::Relaxed);
            }
            None => std::thread::sleep(step),
        }
    }
    /// Spends `step` of a slow test decision provider, on the call's own clock.
    #[doc(hidden)]
    pub fn spend_for_test(&self, step: Duration) {
        self.spend(step);
    }
}

/// A deliberately slow retrieval stage, for deadline tests: the stage of
/// `signal` first spends `duration`, checking its deadline every millisecond
/// when `yields` (a slow stage that yields) or never (a stalled one).
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct SlowRetrievalStage {
    pub signal: crate::store::RetrievalSignal,
    pub duration: Duration,
    pub yields: bool,
}

#[cfg(any(test, feature = "test-hooks"))]
impl crate::Vault {
    /// Arms (or, with `None`, disarms) this vault's slow retrieval stage.
    #[doc(hidden)]
    pub fn arm_slow_retrieval_stage_for_test(&self, stage: Option<SlowRetrievalStage>) {
        *self
            .slow_retrieval_stage
            .lock()
            .expect("slow retrieval stage hook") = stage;
    }

    pub(crate) fn run_slow_retrieval_stage(
        &self,
        signal: crate::store::RetrievalSignal,
        deadline: &RetrievalDeadline,
    ) -> Result<()> {
        let armed = *self
            .slow_retrieval_stage
            .lock()
            .expect("slow retrieval stage hook");
        let Some(slow) = armed.filter(|slow| slow.signal == signal) else {
            return Ok(());
        };
        let until = deadline.now() + slow.duration;
        loop {
            let left = until.saturating_duration_since(deadline.now());
            if left.is_zero() {
                return Ok(());
            }
            if slow.yields {
                deadline.checkpoint()?;
            }
            deadline.spend(left.min(Duration::from_millis(1)));
        }
    }
}

/// One query vector in a declared embedding space: recall searches that
/// space's list with it, for every kind of item the space holds (OF-370; on
/// the one-space preset the text query enters the text slot's space here).
#[derive(Debug, Clone, Copy)]
pub struct RecallMediaSeed<'a> {
    pub space: &'a str,
    /// The kind of query the vector encodes.
    pub kind: InputKind,
    pub vector: &'a [f32],
}

/// What a recall door's host embedded the query into: the vault's own text
/// index, and declared spaces.
#[derive(Debug, Clone, Default)]
pub struct RecallQueryVectors {
    pub text_index: Option<Vec<f32>>,
    /// Space id, query kind and vector.
    pub media: Vec<(String, InputKind, Vec<f32>)>,
}

impl RecallQueryVectors {
    /// The declared-space vectors as [`RecallExecution::media`] seeds.
    #[must_use]
    pub fn media_seeds(&self) -> Vec<RecallMediaSeed<'_>> {
        self.media
            .iter()
            .map(|(space, kind, vector)| RecallMediaSeed {
                space,
                kind: *kind,
                vector,
            })
            .collect()
    }
}

/// Additional execution inputs for the regular memory recall pipeline.
/// No implicit embedding or model is invented when a host supplies neither.
#[derive(Default)]
pub struct RecallExecution<'a> {
    pub deadline: Option<&'a RetrievalDeadline>,
    pub reranker: Option<&'a dyn Reranker>,
    pub embedding: Option<&'a [f32]>,
    /// Query vectors in declared embedding spaces, each searched as its
    /// space's list beside the text index's.
    pub media: &'a [RecallMediaSeed<'a>],
    pub phonetic_codes: &'a [&'a str],
    /// Unix seconds the query's time words resolve against (`yesterday`
    /// is the day before it), and the clock recency ages from. `None` is now.
    pub as_of: Option<u64>,
    /// Receives the pack this recall answers with if its door stops waiting
    /// at the deadline during the scope census: the assembled items, marked
    /// partial. The door itself published the empty pack it answers with
    /// before then ([`crate::task_verb::sdk::RecallDoor`]).
    pub on_cut: Option<&'a (dyn Fn(crate::memory::MemoryPack) + Sync)>,
    /// That empty pack. Its door answers with it, or with a later one
    /// `on_cut` received, once the deadline comes; past the deadline the
    /// recall stops at its next check and returns it.
    pub door_fallback: Option<&'a crate::memory::MemoryPack>,
    /// The host serves no reranker: high, xhigh and max run their expansion
    /// without the rerank stage and need no lease, and their door says so in
    /// the pack ([`crate::memory::RecallRerank::Unavailable`]).
    pub rerank_unavailable: bool,
}
