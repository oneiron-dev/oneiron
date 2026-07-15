//! Tick sources: what wakes the supervisor (ONE-1684).
//!
//! The driver is a pure EVENT CONSUMER (ARCH-0026 / CROSS-ARCH-0022 /
//! ARCH-0046): there is no periodic heartbeat or poll timer anywhere in
//! this module. Every wakeup traces to exactly one of two causes —
//!
//! * a **commitment deadline read from the job queue** ([`TimerTick`]
//!   sleeps until the concrete next deadline, re-read once per cycle), or
//! * an **authenticated push** ([`PushTick`], a bounded coalescing mailbox
//!   whose producer handles are TYPED by role: a [`HintPusher`] is
//!   structurally unable to inject a wake-class tick — H-S4).
//!
//! [`HybridTick`] selects over both with deadline priority: when a deadline
//! and a push are ready in the same poll, the deadline wins. Push bursts
//! coalesce (capacity 1 per signal class) into one follow-up pass, while a
//! missed deadline can never be dropped — deadlines are never buffered
//! here, they are re-read from the job queue on every cycle, so a deadline
//! that lost one race simply re-surfaces on the next call.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::job_queue::{JobQueue, JobState};
use oneiron::{
    DREAMER_CONSOLIDATION_MACRO_JOB_KIND, DREAMER_CONSOLIDATION_MESO_JOB_KIND,
    DREAMER_CONSOLIDATION_MICRO_JOB_KIND, DreamerConsolidationScope, DreamerRunnerStore, Vault,
    WakeTrigger,
};
use tokio::sync::Notify;

/// Millisecond wall-clock read, injectable for tests.
pub type NowMillis = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One wakeup for the supervisor. Every tick names its concrete cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// A commitment deadline read from the job queue came due.
    Deadline(CommitmentDeadline),
    /// An authenticated wake-class push: carries pass-shaping authority.
    Wake(WakeSignal),
    /// An authenticated hint-class push. Hints carry NO pass-shaping
    /// authority — the supervisor maps every hint to the least-privileged
    /// pass shape (H-S4).
    Hint(HintSignal),
}

/// A commitment deadline surfaced from the durable job queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentDeadline {
    /// When the commitment comes due (unix epoch, milliseconds).
    pub due_at_ms: u64,
    /// Which consolidation lane the due job belongs to.
    pub scope: DreamerConsolidationScope,
}

/// Wake-class push payload: names the trigger and the consolidation lane
/// the resulting pass should drain. Only a [`WakePusher`] can inject one
/// into a [`PushTick`] channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeSignal {
    pub trigger: WakeTrigger,
    pub scope: DreamerConsolidationScope,
}

/// Hint-class push payload. Deliberately carries NO scope/trigger fields:
/// a hint producer cannot shape — and in particular cannot escalate — the
/// pass its hint provokes (H-S4). The hint/wake split is enforced by the
/// type system at the channel's send surface, not by convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HintSignal {}

/// Source of wakeups for the supervisor. Signature pinned by the
/// agent-runtime design doc: `async fn next_tick(&mut self) -> Option<Tick>`.
/// `None` means the source is exhausted — nothing can ever wake the driver
/// again, so the supervisor stops.
#[allow(async_fn_in_trait)]
pub trait TickSource {
    async fn next_tick(&mut self) -> Option<Tick>;
}

// ---------------------------------------------------------------------------
// TimerTick — wake-on-next-commitment-deadline (never a poll)
// ---------------------------------------------------------------------------

/// Reads the NEXT commitment deadline from durable state. Called once per
/// wakeup cycle right before the timer arms — never on a period.
///
/// Implementations must surface only deadlines the LOCAL node could
/// actually admit: an un-admittable due deadline ticks immediately, drives
/// a pass that refuses without mutating the row, and — deadlines having
/// priority over pushes — re-surfaces on the very next read, spinning the
/// supervisor and starving the push lanes.
pub trait DeadlineSource {
    /// The earliest upcoming commitment deadline this node could admit, or
    /// `None` when no such timed work exists.
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>>;
}

/// [`DeadlineSource`] over the vault's advisory job table: the earliest due
/// queued Dreamer consolidation job THIS NODE could admit. A queued job
/// with no retry backoff is due at its enqueue stamp; a backoff-delayed job
/// is due when the backoff clears. Job stamps are stored in seconds and
/// surfaced here in milliseconds.
///
/// MACRO jobs are home-node-gated at admission (`NoHomeNode` /
/// `NotHomeNode` refusals that do not mutate the queued row), so the macro
/// lane is surfaced only while `local_node_id` matches the elected home
/// node — surfacing it elsewhere would busy-spin the supervisor on the same
/// overdue deadline. The election is re-read on every cycle, so macro work
/// re-surfaces the moment this node becomes home.
pub struct JobQueueDeadlines<'v> {
    vault: &'v Vault,
    local_node_id: u64,
}

impl<'v> JobQueueDeadlines<'v> {
    /// `local_node_id` is the same node identity the host passes to
    /// admission (`WakeSupervisorConfig::local_node_id`).
    #[must_use]
    pub fn new(vault: &'v Vault, local_node_id: u64) -> Self {
        Self {
            vault,
            local_node_id,
        }
    }
}

impl DeadlineSource for JobQueueDeadlines<'_> {
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        let queue = JobQueue::new(self.vault);
        let macro_admissible = DreamerRunnerStore::new(self.vault)
            .home_node_designation()?
            .is_some_and(|designation| designation.node_id == self.local_node_id);
        let mut next: Option<CommitmentDeadline> = None;
        for job in queue.list()? {
            if job.state != JobState::Queued {
                continue;
            }
            let Some(scope) = scope_for_job_kind(&job.kind) else {
                continue;
            };
            if scope == DreamerConsolidationScope::Macro && !macro_admissible {
                continue;
            }
            let due_secs = job.backoff_until.unwrap_or(job.created_at);
            let due_at_ms = due_secs.saturating_mul(1_000);
            if next.is_none_or(|current| due_at_ms < current.due_at_ms) {
                next = Some(CommitmentDeadline { due_at_ms, scope });
            }
        }
        Ok(next)
    }
}

fn scope_for_job_kind(kind: &str) -> Option<DreamerConsolidationScope> {
    if kind == DREAMER_CONSOLIDATION_MICRO_JOB_KIND {
        Some(DreamerConsolidationScope::Micro)
    } else if kind == DREAMER_CONSOLIDATION_MESO_JOB_KIND {
        Some(DreamerConsolidationScope::Meso)
    } else if kind == DREAMER_CONSOLIDATION_MACRO_JOB_KIND {
        Some(DreamerConsolidationScope::Macro)
    } else {
        None
    }
}

/// Wake-on-deadline timer LANE: reads the next commitment deadline from
/// its [`DeadlineSource`] and sleeps until exactly that instant. There is
/// no interval and no heartbeat — with no timed work (or on a deadline
/// read error) the lane goes quiet instead of polling.
///
/// Deliberately NOT a [`TickSource`]: a quiet timer lane is not source
/// exhaustion — timed work can appear later, and under the no-poll
/// architecture (ARCH-0026) the lane has no way to learn of it on its own.
/// Wired bare into the supervisor it would either stop the loop permanently
/// (`None` on an empty queue) or have to poll; both are wrong, so that
/// wiring is unrepresentable. Compose it into a [`HybridTick`], whose push
/// lane both carries the "new work arrived" notification and owns the one
/// true exhaustion signal (every producer handle dropped).
pub struct TimerTick<D> {
    source: D,
    now_ms: NowMillis,
}

impl<D: DeadlineSource> TimerTick<D> {
    /// Timer over the system wall clock.
    #[must_use]
    pub fn new(source: D) -> Self {
        Self::with_clock(source, Arc::new(system_now_ms))
    }

    /// Timer over an injected clock (tests).
    #[must_use]
    pub fn with_clock(source: D, now_ms: NowMillis) -> Self {
        Self { source, now_ms }
    }

    /// One deadline read. A read error is logged and treated as "no timed
    /// work": the lane goes quiet (fail-stop) instead of spinning against a
    /// broken store.
    fn read_deadline(&mut self) -> Option<CommitmentDeadline> {
        match self.source.next_deadline() {
            Ok(deadline) => deadline,
            Err(error) => {
                tracing::error!(?error, "commitment-deadline read failed; timer lane quiet");
                None
            }
        }
    }

    fn now(&self) -> u64 {
        (self.now_ms)()
    }
}

/// Sleeps until `due_at_ms` on the given clock; returns immediately for a
/// deadline already in the past (a missed deadline fires, never drops).
async fn sleep_until_due(now_ms: &NowMillis, due_at_ms: u64) {
    let now = (*now_ms)();
    if due_at_ms > now {
        tokio::time::sleep(Duration::from_millis(due_at_ms - now)).await;
    }
}

// ---------------------------------------------------------------------------
// PushTick — bounded, role-typed, coalescing push mailbox (H-S4)
// ---------------------------------------------------------------------------

/// Scope lanes for wake coalescing: signals coalesce ONLY within one lane
/// (identical/overlapping signals); wakes for distinct consolidation lanes
/// are distinct commitments and are never collapsed into each other.
const SCOPE_LANES: usize = 3;

fn scope_lane(scope: DreamerConsolidationScope) -> usize {
    match scope {
        DreamerConsolidationScope::Micro => 0,
        DreamerConsolidationScope::Meso => 1,
        // `DreamerConsolidationScope` is non_exhaustive: a future scope
        // rides the macro lane until it gets a lane of its own.
        _ => 2,
    }
}

#[derive(Debug, Default)]
struct PushState {
    wake: [Option<WakeSignal>; SCOPE_LANES],
    hint: Option<HintSignal>,
}

#[derive(Debug)]
struct PushShared {
    state: Mutex<PushState>,
    notify: Notify,
    pushers: AtomicUsize,
    receiver_alive: AtomicBool,
}

impl PushShared {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, PushState> {
        self.state.lock().expect("push mailbox lock poisoned")
    }
}

/// Rejected push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickPushError {
    /// The receiving supervisor is gone; the signal can never be consumed.
    Closed,
}

impl fmt::Display for TickPushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "push tick channel closed"),
        }
    }
}

impl std::error::Error for TickPushError {}

/// Receiving half of the push channel: ONE bounded coalescing mailbox
/// (capacity 1 per signal class — one hint slot plus one wake slot per
/// consolidation lane), drained wake-first. Bursts therefore collapse into
/// one follow-up pass per class while distinct signals are never dropped.
pub struct PushTick {
    shared: Arc<PushShared>,
}

impl PushTick {
    /// Builds a push channel: the receiver plus one producer handle per
    /// role. The role split is the H-S4 fence — mint the [`WakePusher`] for
    /// wake-authorized hosts only, and hand app-hint integrations a
    /// [`HintPusher`] (or an attenuated clone via
    /// [`WakePusher::to_hint_pusher`]). There is no other way to write into
    /// the channel.
    #[must_use]
    pub fn channel() -> (Self, WakePusher, HintPusher) {
        let shared = Arc::new(PushShared {
            state: Mutex::new(PushState::default()),
            notify: Notify::new(),
            pushers: AtomicUsize::new(2),
            receiver_alive: AtomicBool::new(true),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            WakePusher {
                shared: Arc::clone(&shared),
            },
            HintPusher { shared },
        )
    }

    /// Drains the highest-priority pending signal: wake lanes first
    /// (micro, meso, macro), then the hint slot.
    fn take_pending(&self) -> Option<Tick> {
        let mut state = self.shared.lock_state();
        for lane in &mut state.wake {
            if let Some(signal) = lane.take() {
                return Some(Tick::Wake(signal));
            }
        }
        state.hint.take().map(Tick::Hint)
    }

    /// Waits for the next pushed signal. The mailbox is level-triggered:
    /// pending state is re-checked before every wait, so a notification
    /// lost to `select!` cancellation can never lose a signal. Returns
    /// `None` once every producer handle is dropped and the mailbox is
    /// drained.
    async fn recv(&mut self) -> Option<Tick> {
        loop {
            if let Some(tick) = self.take_pending() {
                return Some(tick);
            }
            if self.shared.pushers.load(Ordering::Acquire) == 0 {
                return None;
            }
            self.shared.notify.notified().await;
        }
    }
}

impl Drop for PushTick {
    fn drop(&mut self) {
        self.shared.receiver_alive.store(false, Ordering::Release);
    }
}

impl TickSource for PushTick {
    async fn next_tick(&mut self) -> Option<Tick> {
        self.recv().await
    }
}

/// Wake-class producer handle: the ONLY send surface that can inject a
/// wake-class tick into a [`PushTick`] channel. A host holding only a
/// [`HintPusher`] is structurally unable to reach this type — the hint/wake
/// authority split is carried by the type system, not convention (H-S4).
#[derive(Debug)]
pub struct WakePusher {
    shared: Arc<PushShared>,
}

impl WakePusher {
    /// Pushes a wake-class signal. Same-lane signals coalesce (the pending
    /// pass covers both — the earlier trigger is kept); signals for
    /// distinct consolidation lanes never collapse into each other.
    pub fn push_wake(
        &self,
        trigger: WakeTrigger,
        scope: DreamerConsolidationScope,
    ) -> Result<(), TickPushError> {
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(TickPushError::Closed);
        }
        {
            let mut state = self.shared.lock_state();
            let lane = &mut state.wake[scope_lane(scope)];
            if lane.is_none() {
                *lane = Some(WakeSignal { trigger, scope });
            }
        }
        self.shared.notify.notify_one();
        Ok(())
    }

    /// Attenuates wake authority down to hint authority. Attenuation is the
    /// only direction that exists: nothing turns a [`HintPusher`] back into
    /// a [`WakePusher`].
    #[must_use]
    pub fn to_hint_pusher(&self) -> HintPusher {
        self.shared.pushers.fetch_add(1, Ordering::AcqRel);
        HintPusher {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Clone for WakePusher {
    fn clone(&self) -> Self {
        self.shared.pushers.fetch_add(1, Ordering::AcqRel);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for WakePusher {
    fn drop(&mut self) {
        if self.shared.pushers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.notify.notify_one();
        }
    }
}

/// Hint-class producer handle: its ONE send method takes no payload with
/// pass-shaping authority, so an app-hint integration cannot forge a
/// wake-class tick or escalate a pass — the fence H-S4 requires.
#[derive(Debug)]
pub struct HintPusher {
    shared: Arc<PushShared>,
}

impl HintPusher {
    /// Pushes an advisory hint. Hints coalesce into one pending slot: a
    /// burst of hints provokes at most one follow-up pass.
    pub fn push_hint(&self) -> Result<(), TickPushError> {
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(TickPushError::Closed);
        }
        {
            let mut state = self.shared.lock_state();
            if state.hint.is_none() {
                state.hint = Some(HintSignal {});
            }
        }
        self.shared.notify.notify_one();
        Ok(())
    }
}

impl Clone for HintPusher {
    fn clone(&self) -> Self {
        self.shared.pushers.fetch_add(1, Ordering::AcqRel);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for HintPusher {
    fn drop(&mut self) {
        if self.shared.pushers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.notify.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------
// HybridTick — biased select over timer + push, deadline priority
// ---------------------------------------------------------------------------

/// Selects over a [`TimerTick`] and a [`PushTick`] with deadline priority:
/// an already-due deadline short-circuits before the push lane is even
/// looked at, and when both lanes become ready in the same poll the biased
/// select picks the deadline branch. Nothing is buffered on the timer side
/// — the next deadline is re-read from the job queue on every cycle, so a
/// deadline that lost one race re-surfaces on the next call and can never
/// be dropped by push coalescing (H-S4).
pub struct HybridTick<D> {
    timer: TimerTick<D>,
    push: PushTick,
}

impl<D: DeadlineSource> HybridTick<D> {
    #[must_use]
    pub fn new(timer: TimerTick<D>, push: PushTick) -> Self {
        Self { timer, push }
    }
}

impl<D: DeadlineSource> TickSource for HybridTick<D> {
    async fn next_tick(&mut self) -> Option<Tick> {
        match self.timer.read_deadline() {
            // A deadline that is already due beats any pending push.
            Some(deadline) if deadline.due_at_ms <= self.timer.now() => {
                Some(Tick::Deadline(deadline))
            }
            Some(deadline) => {
                let clock = Arc::clone(&self.timer.now_ms);
                let winner = tokio::select! {
                    biased;
                    () = sleep_until_due(&clock, deadline.due_at_ms) => None,
                    push = self.push.recv() => Some(push),
                };
                match winner {
                    // The deadline came due first.
                    None => Some(Tick::Deadline(deadline)),
                    // A push won; the un-consumed deadline re-surfaces on
                    // the next cycle's fresh read.
                    Some(Some(tick)) => Some(tick),
                    // Push lane closed while a deadline is armed: wait the
                    // deadline out on the timer lane alone.
                    Some(None) => {
                        sleep_until_due(&clock, deadline.due_at_ms).await;
                        Some(Tick::Deadline(deadline))
                    }
                }
            }
            // No timed work: only a push can wake us. `None` from the push
            // lane means no producers remain either — the source is
            // exhausted.
            None => self.push.recv().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;

    use oneiron::{DreamerHomeNodeCandidate, EnqueueDreamerConsolidationJob, VaultConfig};

    use super::*;

    struct ScriptedDeadlines {
        deadlines: Vec<Option<CommitmentDeadline>>,
    }

    impl ScriptedDeadlines {
        fn new(mut deadlines: Vec<Option<CommitmentDeadline>>) -> Self {
            deadlines.reverse();
            Self { deadlines }
        }
    }

    impl DeadlineSource for ScriptedDeadlines {
        fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
            Ok(self.deadlines.pop().flatten())
        }
    }

    fn frozen_clock(now: u64) -> NowMillis {
        Arc::new(move || now)
    }

    #[test]
    fn push_coalesces_same_lane_wakes() {
        let (receiver, wake, _hint) = PushTick::channel();
        for _ in 0..3 {
            wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
                .expect("open channel");
        }
        assert_eq!(
            receiver.take_pending(),
            Some(Tick::Wake(WakeSignal {
                trigger: WakeTrigger::Compaction,
                scope: DreamerConsolidationScope::Micro,
            }))
        );
        assert_eq!(receiver.take_pending(), None, "burst coalesced to one");
    }

    #[test]
    fn distinct_lane_wakes_never_collapse() {
        let (receiver, wake, _hint) = PushTick::channel();
        wake.push_wake(WakeTrigger::Timer, DreamerConsolidationScope::Macro)
            .expect("open channel");
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        let first = receiver.take_pending().expect("first wake");
        let second = receiver.take_pending().expect("second wake");
        assert!(matches!(
            first,
            Tick::Wake(WakeSignal {
                scope: DreamerConsolidationScope::Micro,
                ..
            })
        ));
        assert!(matches!(
            second,
            Tick::Wake(WakeSignal {
                scope: DreamerConsolidationScope::Macro,
                ..
            })
        ));
        assert_eq!(receiver.take_pending(), None);
    }

    #[test]
    fn wake_drains_before_hint() {
        let (receiver, wake, hint) = PushTick::channel();
        hint.push_hint().expect("open channel");
        hint.push_hint().expect("open channel");
        wake.push_wake(WakeTrigger::SessionEnd, DreamerConsolidationScope::Meso)
            .expect("open channel");
        assert!(matches!(
            receiver.take_pending(),
            Some(Tick::Wake(WakeSignal {
                scope: DreamerConsolidationScope::Meso,
                ..
            }))
        ));
        assert_eq!(
            receiver.take_pending(),
            Some(Tick::Hint(HintSignal {})),
            "hint burst coalesced to one, delivered after the wake"
        );
        assert_eq!(receiver.take_pending(), None);
    }

    #[tokio::test]
    async fn push_recv_ends_when_producers_drop() {
        let (mut receiver, wake, hint) = PushTick::channel();
        wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);
        assert!(matches!(receiver.recv().await, Some(Tick::Wake(_))));
        assert_eq!(receiver.recv().await, None, "drained + no producers");
    }

    #[test]
    fn push_after_receiver_drop_is_rejected() {
        let (receiver, wake, hint) = PushTick::channel();
        drop(receiver);
        assert_eq!(
            wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro),
            Err(TickPushError::Closed)
        );
        assert_eq!(hint.push_hint(), Err(TickPushError::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn hybrid_timer_lane_fires_at_the_read_deadline_then_goes_quiet() {
        let deadline = CommitmentDeadline {
            due_at_ms: 5_000,
            scope: DreamerConsolidationScope::Micro,
        };
        let timer = TimerTick::with_clock(
            ScriptedDeadlines::new(vec![Some(deadline), None]),
            frozen_clock(0),
        );
        let (push, wake, hint) = PushTick::channel();
        drop(wake);
        drop(hint);
        let mut hybrid = HybridTick::new(timer, push);
        assert_eq!(hybrid.next_tick().await, Some(Tick::Deadline(deadline)));
        // Quiet timer lane AND no producers left: the one true exhaustion.
        assert_eq!(hybrid.next_tick().await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn hybrid_with_no_timed_work_waits_for_push_instead_of_exhausting() {
        // A quiet timer lane (no upcoming deadline) is NOT tick-source
        // exhaustion while push producers remain: the supervisor must keep
        // waiting for a push, not stop permanently. Bare TimerTick is no
        // longer a TickSource precisely because it cannot express this.
        let timer = TimerTick::with_clock(ScriptedDeadlines::new(vec![None]), frozen_clock(0));
        let (push, wake, _hint) = PushTick::channel();
        let mut hybrid = HybridTick::new(timer, push);

        let mut next = pin!(hybrid.next_tick());
        assert!(
            tokio::time::timeout(Duration::from_secs(3_600), next.as_mut())
                .await
                .is_err(),
            "no timed work + live producers must idle, not exhaust"
        );
        wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro)
            .expect("open channel");
        assert!(matches!(next.await, Some(Tick::Wake(_))));
    }

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        (dir, vault)
    }

    fn enqueue(vault: &Vault, scope: DreamerConsolidationScope, tag: &str, now: u64) {
        DreamerRunnerStore::new(vault)
            .enqueue_consolidation(EnqueueDreamerConsolidationJob {
                scope,
                input: rmpv::Value::from(tag),
                parent_job: None,
                dedupe_key: Some(tag.to_owned()),
                run_id: None,
                now,
            })
            .expect("enqueue");
    }

    fn elect_home(vault: &Vault, node_id: u64, now: u64) {
        DreamerRunnerStore::new(vault)
            .elect_home_node(
                &[DreamerHomeNodeCandidate {
                    node_id,
                    cloud: true,
                    attached: true,
                    always_on_local: false,
                    primary_device: false,
                }],
                now,
            )
            .expect("elect home node");
    }

    #[test]
    fn job_queue_deadlines_hide_macro_until_local_home_election() {
        let (_dir, vault) = open_vault();
        enqueue(&vault, DreamerConsolidationScope::Macro, "macro-job", 10);

        // No home node elected: macro admission would refuse (NoHomeNode)
        // without mutating the row, so the overdue deadline must not
        // surface and re-tick forever.
        let mut source = JobQueueDeadlines::new(&vault, 7);
        assert_eq!(source.next_deadline().expect("read"), None);

        // Local node elected home: the same row surfaces on the very next
        // re-read.
        elect_home(&vault, 7, 15);
        assert_eq!(
            source.next_deadline().expect("read"),
            Some(CommitmentDeadline {
                due_at_ms: 10_000,
                scope: DreamerConsolidationScope::Macro,
            })
        );
    }

    #[test]
    fn job_queue_deadlines_on_foreign_home_skip_macro_but_keep_other_lanes() {
        let (_dir, vault) = open_vault();
        enqueue(&vault, DreamerConsolidationScope::Macro, "macro-job", 10);
        enqueue(&vault, DreamerConsolidationScope::Micro, "micro-job", 20);
        elect_home(&vault, 9, 25);

        // Node 7 is not the elected home: the earlier macro deadline is
        // filtered (admission would refuse NotHomeNode without progress)
        // while the micro lane keeps flowing — no spin, no starvation.
        let mut source = JobQueueDeadlines::new(&vault, 7);
        assert_eq!(
            source.next_deadline().expect("read"),
            Some(CommitmentDeadline {
                due_at_ms: 20_000,
                scope: DreamerConsolidationScope::Micro,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hybrid_due_deadline_beats_pending_push() {
        let deadline = CommitmentDeadline {
            due_at_ms: 1_000,
            scope: DreamerConsolidationScope::Meso,
        };
        let timer = TimerTick::with_clock(
            ScriptedDeadlines::new(vec![Some(deadline)]),
            frozen_clock(1_000),
        );
        let (push, wake, _hint) = PushTick::channel();
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        let mut hybrid = HybridTick::new(timer, push);
        assert_eq!(
            hybrid.next_tick().await,
            Some(Tick::Deadline(deadline)),
            "an already-due deadline wins over a ready push"
        );
        // The push was NOT consumed by the deadline win: it surfaces next.
        assert!(matches!(hybrid.next_tick().await, Some(Tick::Wake(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn hybrid_push_wakes_while_deadline_is_far() {
        let deadline = CommitmentDeadline {
            due_at_ms: 60_000,
            scope: DreamerConsolidationScope::Micro,
        };
        let timer = TimerTick::with_clock(
            ScriptedDeadlines::new(vec![Some(deadline), Some(deadline)]),
            frozen_clock(0),
        );
        let (push, wake, _hint) = PushTick::channel();
        wake.push_wake(WakeTrigger::SessionEnd, DreamerConsolidationScope::Meso)
            .expect("open channel");
        let mut hybrid = HybridTick::new(timer, push);
        assert!(
            matches!(hybrid.next_tick().await, Some(Tick::Wake(_))),
            "a ready push beats a far deadline"
        );
        // The far deadline was not dropped: the next cycle re-reads and
        // waits it out (paused time auto-advances).
        assert_eq!(hybrid.next_tick().await, Some(Tick::Deadline(deadline)));
    }

    #[tokio::test]
    async fn hybrid_ends_when_no_deadline_and_no_producers() {
        let timer = TimerTick::with_clock(ScriptedDeadlines::new(vec![None]), frozen_clock(0));
        let (push, wake, hint) = PushTick::channel();
        drop(wake);
        drop(hint);
        let mut hybrid = HybridTick::new(timer, push);
        assert_eq!(hybrid.next_tick().await, None);
    }
}
