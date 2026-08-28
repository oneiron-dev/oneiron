//! Tick sources: what wakes the supervisor (ONE-1684).
//!
//! The driver is a pure EVENT CONSUMER (ARCH-0026 / CROSS-ARCH-0022 /
//! ARCH-0046): there is no periodic heartbeat or poll timer anywhere in
//! this module. Every wakeup traces to exactly one of two causes —
//!
//! * a **commitment deadline read from the attempt queue** ([`TimerTick`]
//!   sleeps until the concrete next deadline, re-read once per cycle), or
//! * an **authenticated push** ([`PushTick`], a bounded coalescing mailbox
//!   whose producer handles are TYPED by role: a [`HintPusher`] is
//!   structurally unable to inject a wake-class tick — H-S4).
//!
//! [`HybridTick`] selects over both with deadline priority: when a deadline
//! and a push are ready in the same poll, the deadline wins. Push bursts
//! coalesce (capacity 1 per wake lane and plain-hint slot; session hints
//! ride a bounded ORDERED queue that coalesces only adjacent Activity hints
//! arriving within the configured idle floor — lifecycle causality is never
//! reordered) into follow-up passes,
//! while a missed deadline can never be dropped — deadlines are never
//! buffered here, they are re-read from the attempt queue on every cycle, so
//! a deadline that lost one race simply re-surfaces on the next call.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::commitment_schedule;
use oneiron::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore, Vault,
    WakeTrigger,
};
use tokio::sync::Notify;

use crate::session::SessionHint;

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
    /// A commitment deadline read from the attempt queue came due.
    Deadline(CommitmentDeadline),
    /// An authenticated wake-class push: carries pass-shaping authority.
    Wake(WakeSignal),
    /// An authenticated hint-class push. Hints carry NO pass-shaping
    /// authority — the supervisor maps every hint to the least-privileged
    /// pass shape (H-S4).
    Hint(HintSignal),
}

/// A commitment deadline surfaced from the durable attempt queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentDeadline {
    /// When the commitment comes due (unix epoch, milliseconds).
    pub due_at_ms: u64,
    /// Which consolidation lane the due attempt belongs to.
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
///
/// The optional session-lifecycle fact (ONE-1685) is NOT pass-shaping
/// authority: the supervisor still maps every hint to the least-privileged
/// pass shape, and lifecycle consequences (including a session close's
/// Meso consolidation) are decided by DRIVER policy in
/// [`SessionTicks`](crate::SessionTicks), never by the producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HintSignal {
    /// Session-lifecycle fact, if this hint carries one. `None` is the
    /// plain advisory hint ("something may have happened, check micro").
    pub session: Option<SessionHint>,
}

/// One raw producer/channel timestamp pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionHintStamp {
    pub(crate) claimed_ms: Option<u64>,
    pub(crate) arrival_ms: u64,
}

/// Internal carrier consumed by [`SessionTicks`](crate::SessionTicks) before
/// the inert public [`HintSignal`] is surfaced. Boundary hints are points;
/// adjacent Activity hints aggregate into a period whose endpoints and count
/// survive queueing and awaited delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHintCarrier {
    pub(crate) hint: SessionHint,
    pub(crate) first: SessionHintStamp,
    pub(crate) last: SessionHintStamp,
    pub(crate) count: u64,
}

impl SessionHintCarrier {
    pub(crate) fn point(hint: SessionHint, claimed_ms: Option<u64>, arrival_ms: u64) -> Self {
        let stamp = SessionHintStamp {
            claimed_ms,
            arrival_ms,
        };
        Self {
            hint,
            first: stamp,
            last: stamp,
            count: 1,
        }
    }

    fn aggregate_activity(&mut self, claimed_ms: Option<u64>, arrival_ms: u64) {
        debug_assert_eq!(self.hint, SessionHint::Activity);
        self.last = SessionHintStamp {
            claimed_ms,
            arrival_ms,
        };
        self.count = self.count.saturating_add(1);
    }
}

/// Source of wakeups for the supervisor. Signature pinned by the
/// agent-runtime design doc: `async fn next_tick(&mut self) -> Option<Tick>`.
/// `None` means the source is exhausted — nothing can ever wake the driver
/// again, so the supervisor stops.
#[allow(async_fn_in_trait)]
pub trait TickSource {
    async fn next_tick(&mut self) -> Option<Tick>;

    /// Pops the OLDEST buffered session-lifecycle hint and its push-time
    /// arrival stamp without waiting, if this source buffers any. The
    /// session decorator ([`SessionTicks`](crate::SessionTicks)) drains these BEFORE trusting
    /// durable expiry state, so an activity hint that arrived ahead of a
    /// close deadline is applied before the close decision reads the clock
    /// it bumps (ONE-1685). Sources without a hint buffer keep the default:
    /// no buffered hints, ever.
    fn take_buffered_session_hint(&mut self) -> Option<(SessionHint, Option<u64>, u64)> {
        None
    }

    /// Full period-aware form used by the session decorator. The default
    /// adapts the required point triple for sources that do not aggregate.
    fn take_buffered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.take_buffered_session_hint()
            .map(|(hint, claimed_ms, arrival_ms)| {
                SessionHintCarrier::point(hint, claimed_ms, arrival_ms)
            })
    }

    /// Retrieves the carrier associated with the session hint most recently
    /// returned by `next_tick`. PushTick uses this sidecar so the public inert
    /// HintSignal shape and the level-triggered pop contract both stay intact.
    fn take_delivered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        None
    }
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

/// [`DeadlineSource`] over the vault's advisory attempt table: the earliest due
/// queued Dreamer consolidation attempt THIS NODE could admit. A queued attempt
/// with no retry backoff is due at its enqueue stamp; a backoff-delayed attempt
/// is due when the backoff clears. Attempt stamps are stored in seconds and
/// surfaced here in milliseconds.
///
/// MACRO attempts are gated at admission by the full local-admissibility
/// predicate (`admit_next_consolidation`): `local_node_id` must match both
/// the vault's stable client identity (`load_or_mint_client_id` via
/// [`DreamerRunnerStore::local_home_node_candidate`]) and the elected home
/// designation. Surfacing a due macro when either check would refuse leaves
/// the queued row unmutated and — deadlines having priority over pushes —
/// busy-spins the supervisor on the same overdue deadline, starving push
/// lanes. Both checks are re-read every cycle; an unreadable vault identity
/// is treated as not-admissible (macro suppressed, other lanes still flow).
pub struct AttemptQueueDeadlines<'v> {
    vault: &'v Vault,
    local_node_id: u64,
    commitment_now: Option<NowMillis>,
}

impl<'v> AttemptQueueDeadlines<'v> {
    /// `local_node_id` is the same node identity the host passes to
    /// admission (`WakeSupervisorConfig::local_node_id`).
    #[must_use]
    pub fn new(vault: &'v Vault, local_node_id: u64) -> Self {
        Self {
            vault,
            local_node_id,
            commitment_now: None,
        }
    }

    /// [`Self::new`] with an injected clock for the commitment-due lane.
    ///
    /// Only the commitment lane reads a clock: the attempt lane's stamps are
    /// durable and need none. Tests that must place "now" relative to a stored
    /// due instant use this instead of sleeping.
    #[must_use]
    pub fn with_commitment_clock(vault: &'v Vault, local_node_id: u64, now: NowMillis) -> Self {
        Self {
            vault,
            local_node_id,
            commitment_now: Some(now),
        }
    }

    /// Mirrors macro admission: home designation AND vault client identity
    /// both equal `local_node_id`. Designation read errors propagate (timer
    /// goes quiet). Identity read errors suppress macro only — same fail-
    /// closed stance as "not admissible", without starving micro/meso.
    fn macro_locally_admissible(&self) -> oneiron::Result<bool> {
        let store = DreamerRunnerStore::new(self.vault);
        let Some(designation) = store.home_node_designation()? else {
            return Ok(false);
        };
        if designation.node_id != self.local_node_id {
            return Ok(false);
        }
        // Same stable client id admission loads via load_or_mint_client_id
        // (exposed here through local_home_node_candidate).
        let vault_node_id = match store.local_home_node_candidate(false, false, false) {
            Ok(candidate) => candidate.node_id,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "vault client identity unreadable; suppressing macro deadlines"
                );
                return Ok(false);
            }
        };
        Ok(vault_node_id == self.local_node_id)
    }
}

impl DeadlineSource for AttemptQueueDeadlines<'_> {
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        let queue = AttemptQueue::new(self.vault);
        let macro_admissible = self.macro_locally_admissible()?;
        let mut next: Option<CommitmentDeadline> = None;
        for attempt in queue.list()? {
            if attempt.state != AttemptState::Queued {
                continue;
            }
            let Some(scope) = scope_for_attempt_kind(&attempt.kind) else {
                continue;
            };
            if scope == DreamerConsolidationScope::Macro && !macro_admissible {
                continue;
            }
            let due_secs = attempt.backoff_until.unwrap_or(attempt.created_at);
            let due_at_ms = due_secs.saturating_mul(1_000);
            if next.is_none_or(|current| due_at_ms < current.due_at_ms) {
                next = Some(CommitmentDeadline { due_at_ms, scope });
            }
        }
        // The two lanes are independent durable sources; the earlier one arms
        // the timer. A TIE keeps the attempt deadline, so wiring the commitment
        // lane in can never displace a deadline this source already surfaced.
        let commitment = match &self.commitment_now {
            Some(clock) => CommitmentDueDeadlines::with_clock(self.vault, Arc::clone(clock)),
            None => CommitmentDueDeadlines::new(self.vault),
        }
        .next_deadline()?;
        Ok(match (next, commitment) {
            (Some(attempt), Some(due)) if due.due_at_ms < attempt.due_at_ms => Some(due),
            (Some(attempt), _) => Some(attempt),
            (None, commitment) => commitment,
        })
    }
}

/// [`DeadlineSource`] over the commitment due index (CMT-2, ONE-1539).
///
/// Reads ONE phase — [`CommitmentDuePhase::Project`](commitment_schedule::CommitmentDuePhase) —
/// and nothing else. `Lead` and `Due` belong to the surfaces, and `LifecycleDue`
/// is a lapse marker: an unmet obligation is a fact to notice on the next pass,
/// never a reason to wake the machine, so it structurally cannot reach the
/// timer feed from here.
///
/// This is also the SOLE production caller of
/// [`Vault::reconcile_commitment_schedule`]. Projection runs inside the
/// deadline read — the one moment the driver is already awake and about to arm
/// a timer — rather than on a period, which is what keeps ARCH-0026's no-poll
/// rule intact with no scheduler anywhere.
///
/// A read or projection failure propagates as `Err`. Mapping it to `Ok(None)`
/// would tell the supervisor "no obligations exist" on a corrupt index, which
/// is the one answer a commitment engine must never give.
pub struct CommitmentDueDeadlines<'v> {
    vault: &'v Vault,
    now: NowMillis,
}

impl<'v> CommitmentDueDeadlines<'v> {
    /// Reads wall-clock time from the system.
    #[must_use]
    pub fn new(vault: &'v Vault) -> Self {
        Self::with_clock(vault, Arc::new(system_now_ms))
    }

    /// [`Self::new`] with an injected millisecond clock.
    #[must_use]
    pub fn with_clock(vault: &'v Vault, now: NowMillis) -> Self {
        Self { vault, now }
    }
}

impl DeadlineSource for CommitmentDueDeadlines<'_> {
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        let now_ms = (self.now)();
        // The index stores seconds; the tick lane speaks milliseconds.
        let now_secs = now_ms / 1_000;
        let project = [commitment_schedule::CommitmentDuePhase::Project];
        let snapshot = self.vault.commitment_due_index_snapshot()?;
        let snapshot = match snapshot.next_timer_at(&project) {
            // A Project row that has come due is work to DO, not a deadline to
            // arm on: materialize it first, then re-read, so the timer arms on
            // what the projection left behind instead of on the row it just
            // consumed.
            Some(at) if at <= now_secs => {
                self.vault.reconcile_commitment_schedule(now_secs)?;
                self.vault.commitment_due_index_snapshot()?
            }
            _ => snapshot,
        };
        Ok(snapshot
            .next_timer_at(&project)
            .map(|due_secs| CommitmentDeadline {
                due_at_ms: due_secs.saturating_mul(1_000),
                scope: DreamerConsolidationScope::Micro,
            }))
    }
}

fn scope_for_attempt_kind(kind: &str) -> Option<DreamerConsolidationScope> {
    if kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND {
        Some(DreamerConsolidationScope::Micro)
    } else if kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND {
        Some(DreamerConsolidationScope::Meso)
    } else if kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND {
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
pub(crate) async fn sleep_until_due(now_ms: &NowMillis, due_at_ms: u64) {
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

/// Bound of the ordered SESSION-hint queue. Arrival order IS lifecycle
/// causality (end-then-open is a reopen; open-end-open is two sittings), so
/// session hints are queued in order and NEVER reordered; only ADJACENT
/// Activity hints inside the idle floor coalesce (a typing burst is one
/// endpoint-preserving period).
/// Boundary hints never coalesce or evict: overflow sheds only Activity, and
/// reports [`TickPushError::QueueFull`] when a full all-boundary queue receives
/// another boundary.
const SESSION_HINT_QUEUE_CAP: usize = 8;

#[derive(Debug, Default)]
struct PushState {
    wake: [Option<WakeSignal>; SCOPE_LANES],
    /// Plain advisory hints: one coalescing slot (unchanged wave-1 shape).
    plain_hint: Option<HintSignal>,
    /// Session-lifecycle hints in ARRIVAL order (see
    /// [`SESSION_HINT_QUEUE_CAP`]).
    session_hints: std::collections::VecDeque<SessionHintCarrier>,
}

struct PushShared {
    state: Mutex<PushState>,
    notify: Notify,
    pushers: AtomicUsize,
    receiver_alive: AtomicBool,
    now_ms: NowMillis,
    coalesce_floor_ms: u64,
}

impl fmt::Debug for PushShared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PushShared").finish_non_exhaustive()
    }
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
    /// A full all-boundary session queue cannot durably accept another
    /// AppOpen/ExplicitEnd point. The producer may retry.
    QueueFull,
}

impl fmt::Display for TickPushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "push tick channel closed"),
            Self::QueueFull => write!(f, "session hint queue full"),
        }
    }
}

impl std::error::Error for TickPushError {}

/// Receiving half of the push channel: ONE bounded coalescing mailbox —
/// one wake slot per consolidation lane (drained first with a rotating scan
/// start so a lane that refills every pass cannot starve older buffered
/// wakes), an ORDERED bounded session-hint queue (arrival order preserved;
/// only adjacent Activity hints inside the idle floor coalesce — lifecycle
/// causality is never rewritten), and one coalescing slot for the plain advisory hint. Bursts
/// therefore collapse while distinct signals keep their order.
pub struct PushTick {
    shared: Arc<PushShared>,
    /// Next wake-lane index to try first (round-robin). Advances after each
    /// returned wake so every occupied lane drains within [`SCOPE_LANES`]
    /// takes even when a lower index refills between drains.
    wake_scan_start: usize,
    /// Timestamp sidecar for the session hint most recently surfaced by
    /// `next_tick`; consumed by the SessionTicks decorator before surfacing.
    delivered_session_hint: Option<SessionHintCarrier>,
}

impl PushTick {
    /// Builds a push channel: the receiver plus one producer handle per
    /// role. The role split is the H-S4 fence — mint the [`WakePusher`] for
    /// wake-authorized hosts only, and hand app-hint integrations a
    /// [`HintPusher`] (or an attenuated clone via
    /// [`WakePusher::to_hint_pusher`]). There is no other way to write into
    /// the channel.
    #[must_use]
    pub fn channel(coalesce_floor_ms: u64) -> (Self, WakePusher, HintPusher) {
        Self::channel_with_clock(Arc::new(system_now_ms), coalesce_floor_ms)
    }

    /// Builds a push channel over an injected arrival clock and idle-floor
    /// coalescing bound.
    #[must_use]
    pub fn channel_with_clock(
        now_ms: NowMillis,
        coalesce_floor_ms: u64,
    ) -> (Self, WakePusher, HintPusher) {
        let shared = Arc::new(PushShared {
            state: Mutex::new(PushState::default()),
            notify: Notify::new(),
            pushers: AtomicUsize::new(2),
            receiver_alive: AtomicBool::new(true),
            now_ms,
            coalesce_floor_ms,
        });
        (
            Self {
                shared: Arc::clone(&shared),
                wake_scan_start: 0,
                delivered_session_hint: None,
            },
            WakePusher {
                shared: Arc::clone(&shared),
            },
            HintPusher { shared },
        )
    }

    /// Drains one pending signal: wake lanes first (round-robin start so
    /// micro/meso/macro each get a turn), then the hint slot.
    ///
    /// Rotation rule: on each returned wake, the scan cursor advances to
    /// the lane after the one just drained (`(lane + 1) % SCOPE_LANES`).
    /// Empty lanes are skipped without advancing past the full cycle; a
    /// hint drain does not move the wake cursor. Deterministic and
    /// per-instance (not shared across receivers).
    fn take_pending(&mut self) -> Option<Tick> {
        self.delivered_session_hint = None;
        let mut state = self.shared.lock_state();
        let start = self.wake_scan_start % SCOPE_LANES;
        for offset in 0..SCOPE_LANES {
            let lane = (start + offset) % SCOPE_LANES;
            if let Some(signal) = state.wake[lane].take() {
                self.wake_scan_start = (lane + 1) % SCOPE_LANES;
                return Some(Tick::Wake(signal));
            }
        }
        // Session hints drain in ARRIVAL order: reordering lifecycle facts
        // rewrites causality (an end-then-open burst is a reopen, not an
        // open that ends itself). The plain advisory slot drains last.
        if let Some(carrier) = state.session_hints.pop_front() {
            self.delivered_session_hint = Some(carrier);
            return Some(Tick::Hint(HintSignal {
                session: Some(carrier.hint),
            }));
        }
        state.plain_hint.take().map(Tick::Hint)
    }

    /// Waits for the next pushed signal. The mailbox is level-triggered:
    /// pending state is re-checked before every wait, so a notification
    /// lost to `select!` cancellation can never lose a signal. Returns
    /// `None` once every producer handle is dropped and the mailbox is
    /// drained.
    ///
    /// Producer drop ordering: `WakePusher` / `HintPusher` store the signal
    /// under the mailbox mutex **before** `notify_one`, and decrement
    /// `pushers` only in `Drop` (after the store). A race remains if a
    /// producer pushes then drops between an empty `take_pending` and the
    /// `pushers == 0` check: `recv` would otherwise return `None` with a
    /// buffered wake. The final `take_pending` re-check on the exhaustion
    /// path closes that window regardless of store-before-decrement order.
    async fn recv(&mut self) -> Option<Tick> {
        loop {
            if let Some(tick) = self.take_pending() {
                return Some(tick);
            }
            if self.shared.pushers.load(Ordering::Acquire) == 0 {
                // Final re-check: a producer may have push_wake/push_hint
                // then Drop between the empty take above and the zero
                // pusher count (store-before-decrement still loses if we
                // only check the counter). Drain any last buffered signal
                // before declaring the source exhausted.
                return self.take_pending();
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

    fn take_buffered_session_hint(&mut self) -> Option<(SessionHint, Option<u64>, u64)> {
        self.shared
            .lock_state()
            .session_hints
            .pop_front()
            .map(|carrier| {
                (
                    carrier.hint,
                    carrier.first.claimed_ms,
                    carrier.first.arrival_ms,
                )
            })
    }

    fn take_buffered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.shared.lock_state().session_hints.pop_front()
    }

    fn take_delivered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.delivered_session_hint.take()
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
    /// Pushes a plain advisory hint. Plain hints coalesce into one pending
    /// slot: a burst provokes at most one follow-up pass.
    pub fn push_hint(&self) -> Result<(), TickPushError> {
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(TickPushError::Closed);
        }
        {
            let mut state = self.shared.lock_state();
            if state.plain_hint.is_none() {
                state.plain_hint = Some(HintSignal::default());
            }
        }
        self.shared.notify.notify_one();
        Ok(())
    }

    /// Pushes a session-lifecycle hint (ONE-1685) onto the bounded ORDERED
    /// queue. Arrival order is preserved end-to-end — lifecycle causality
    /// (open → end → open is two sittings) is never rewritten by
    /// coalescing; only ADJACENT Activity hints whose arrivals are separated
    /// by less than the channel's idle floor aggregate (with both endpoint
    /// stamps and a count). On overflow only Activity is loss-tolerant;
    /// boundaries are never evicted. Carrying a lifecycle fact grants NO pass-shaping
    /// authority — the driver's session policy decides what, if anything,
    /// results (H-S4).
    pub fn push_session_hint(
        &self,
        hint: SessionHint,
        claimed_ms: Option<u64>,
    ) -> Result<(), TickPushError> {
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(TickPushError::Closed);
        }
        let arrival_ms = (self.shared.now_ms)();
        {
            let mut state = self.shared.lock_state();
            if hint == SessionHint::Activity
                && let Some(last) = state.session_hints.back_mut()
                && last.hint == SessionHint::Activity
                && arrival_ms.saturating_sub(last.last.arrival_ms) < self.shared.coalesce_floor_ms
            {
                last.aggregate_activity(claimed_ms, arrival_ms);
            } else {
                if state.session_hints.len() == SESSION_HINT_QUEUE_CAP {
                    let oldest_activity = state
                        .session_hints
                        .iter()
                        .position(|queued| queued.hint == SessionHint::Activity);
                    match (hint, oldest_activity) {
                        (SessionHint::AppOpen | SessionHint::ExplicitEnd, None) => {
                            return Err(TickPushError::QueueFull);
                        }
                        (SessionHint::Activity, None) => {
                            tracing::warn!(
                                ?claimed_ms,
                                arrival_ms,
                                "session hint queue overflow; dropped incoming activity"
                            );
                            return Ok(());
                        }
                        (_, Some(index)) => {
                            let dropped = state.session_hints.remove(index);
                            tracing::warn!(
                                ?dropped,
                                "session hint queue overflow; dropped oldest activity period"
                            );
                        }
                    }
                }
                state
                    .session_hints
                    .push_back(SessionHintCarrier::point(hint, claimed_ms, arrival_ms));
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
/// — the next deadline is re-read from the attempt queue on every cycle, so a
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

    fn take_buffered_session_hint(&mut self) -> Option<(SessionHint, Option<u64>, u64)> {
        self.push.take_buffered_session_hint()
    }

    fn take_buffered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.push.take_buffered_session_hint_carrier()
    }

    fn take_delivered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.push.take_delivered_session_hint_carrier()
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::sync::atomic::AtomicU64;

    use oneiron::{DreamerHomeNodeCandidate, EnqueueDreamerConsolidationAttempt, VaultConfig};

    use super::*;

    const COALESCE_FLOOR_MS: u64 =
        crate::session::DEFAULT_SESSION_IDLE_FLOOR_SECS.saturating_mul(1_000);

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
        let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
        let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
        let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
            Some(Tick::Hint(HintSignal::default())),
            "hint burst coalesced to one, delivered after the wake"
        );
        assert_eq!(receiver.take_pending(), None);
    }

    #[test]
    fn session_hints_preserve_arrival_order_and_coalesce_only_adjacent_same_kind() {
        let (mut receiver, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
        // Arrival sequence: open, a typing burst (adjacent → ONE bump),
        // end, REOPEN, plain advisory. The second AppOpen is same-kind but
        // NOT adjacent to the first — collapsing them would erase a whole
        // sitting (the C4/G1 causality bug).
        hint.push_session_hint(SessionHint::AppOpen, None)
            .expect("open channel");
        for _ in 0..3 {
            hint.push_session_hint(SessionHint::Activity, None)
                .expect("open channel");
        }
        hint.push_session_hint(SessionHint::ExplicitEnd, None)
            .expect("open channel");
        hint.push_session_hint(SessionHint::AppOpen, None)
            .expect("open channel");
        hint.push_hint().expect("open channel");

        let mut drained = Vec::new();
        while let Some(tick) = receiver.take_pending() {
            let Tick::Hint(signal) = tick else {
                panic!("only hints were pushed, got {tick:?}");
            };
            drained.push(signal.session);
        }
        assert_eq!(
            drained,
            vec![
                Some(SessionHint::AppOpen),
                Some(SessionHint::Activity),
                Some(SessionHint::ExplicitEnd),
                Some(SessionHint::AppOpen),
                None,
            ],
            "arrival order preserved; only the adjacent typing burst coalesced"
        );
    }

    #[test]
    fn adjacent_session_hint_coalescing_retains_the_activity_period() {
        const COALESCE_FLOOR_MS: u64 = 100;

        let now = Arc::new(AtomicU64::new(10));
        let clock_now = Arc::clone(&now);
        let clock: NowMillis = Arc::new(move || clock_now.load(Ordering::Acquire));
        let (mut receiver, _wake, hint) = PushTick::channel_with_clock(clock, COALESCE_FLOOR_MS);

        hint.push_session_hint(SessionHint::Activity, None)
            .expect("open channel");
        now.store(20, Ordering::Release);
        hint.push_session_hint(SessionHint::Activity, None)
            .expect("coalesced activity");
        hint.push_session_hint(SessionHint::ExplicitEnd, None)
            .expect("distinct hint");

        let activity = receiver
            .take_buffered_session_hint_carrier()
            .expect("activity period");
        assert_eq!(activity.hint, SessionHint::Activity);
        assert_eq!(activity.first.claimed_ms, None);
        assert_eq!(activity.first.arrival_ms, 10);
        assert_eq!(activity.last.claimed_ms, None);
        assert_eq!(activity.last.arrival_ms, 20);
        assert_eq!(activity.count, 2);
        assert_eq!(
            receiver.take_buffered_session_hint(),
            Some((SessionHint::ExplicitEnd, None, 20))
        );
        assert_eq!(receiver.take_buffered_session_hint(), None);
    }

    #[test]
    fn adjacent_activity_hints_across_the_idle_floor_remain_two_carriers() {
        const COALESCE_FLOOR_MS: u64 = 100;
        const FIRST_ARRIVAL_MS: u64 = 10;
        const WITHIN_FLOOR_ARRIVAL_MS: u64 = FIRST_ARRIVAL_MS + COALESCE_FLOOR_MS - 1;
        const ACROSS_FLOOR_ARRIVAL_MS: u64 = WITHIN_FLOOR_ARRIVAL_MS + COALESCE_FLOOR_MS + 25;

        let now = Arc::new(AtomicU64::new(FIRST_ARRIVAL_MS));
        let clock_now = Arc::clone(&now);
        let clock: NowMillis = Arc::new(move || clock_now.load(Ordering::Acquire));
        let (mut receiver, _wake, hint) = PushTick::channel_with_clock(clock, COALESCE_FLOOR_MS);

        hint.push_session_hint(SessionHint::Activity, Some(1))
            .expect("first activity");
        now.store(WITHIN_FLOOR_ARRIVAL_MS, Ordering::Release);
        hint.push_session_hint(SessionHint::Activity, Some(2))
            .expect("within-floor activity");
        now.store(ACROSS_FLOOR_ARRIVAL_MS, Ordering::Release);
        hint.push_session_hint(SessionHint::Activity, Some(3))
            .expect("across-floor activity");

        let first = receiver
            .take_buffered_session_hint_carrier()
            .expect("first carrier");
        let second = receiver
            .take_buffered_session_hint_carrier()
            .expect("second carrier");
        assert_eq!(first.hint, SessionHint::Activity);
        assert_eq!(first.first.claimed_ms, Some(1));
        assert_eq!(first.first.arrival_ms, FIRST_ARRIVAL_MS);
        assert_eq!(first.last.claimed_ms, Some(2));
        assert_eq!(first.last.arrival_ms, WITHIN_FLOOR_ARRIVAL_MS);
        assert_eq!(first.count, 2);
        assert_eq!(second.hint, SessionHint::Activity);
        assert_eq!(second.first, second.last);
        assert_eq!(second.first.claimed_ms, Some(3));
        assert_eq!(second.first.arrival_ms, ACROSS_FLOOR_ARRIVAL_MS);
        assert_eq!(second.count, 1);
        assert_eq!(receiver.take_buffered_session_hint_carrier(), None);
    }

    #[test]
    fn session_hint_queue_overflow_preserves_boundaries_and_evicts_only_activity() {
        let (mut receiver, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
        // A full all-boundary queue rejects another boundary for producer
        // retry; all eight durable points remain present and ordered.
        for index in 0..SESSION_HINT_QUEUE_CAP {
            let kind = if index % 2 == 0 {
                SessionHint::AppOpen
            } else {
                SessionHint::ExplicitEnd
            };
            hint.push_session_hint(kind, None).expect("open channel");
        }
        assert_eq!(
            hint.push_session_hint(SessionHint::AppOpen, None),
            Err(TickPushError::QueueFull)
        );

        let mut drained = Vec::new();
        while let Some(tick) = receiver.take_pending() {
            let Tick::Hint(signal) = tick else {
                panic!("only hints were pushed, got {tick:?}");
            };
            drained.push(signal.session.expect("session hints only"));
        }
        assert_eq!(drained.len(), SESSION_HINT_QUEUE_CAP);
        let expected: Vec<SessionHint> = (0..SESSION_HINT_QUEUE_CAP)
            .map(|index| {
                if index % 2 == 0 {
                    SessionHint::AppOpen
                } else {
                    SessionHint::ExplicitEnd
                }
            })
            .collect();
        assert_eq!(drained, expected, "QueueFull lost no boundary point");

        // With a mixed full queue, accepting a new boundary removes the
        // oldest Activity period and no boundary.
        let (mut mixed, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
        let initial = [
            SessionHint::AppOpen,
            SessionHint::Activity,
            SessionHint::ExplicitEnd,
            SessionHint::Activity,
            SessionHint::AppOpen,
            SessionHint::ExplicitEnd,
            SessionHint::AppOpen,
            SessionHint::ExplicitEnd,
        ];
        for (index, kind) in initial.into_iter().enumerate() {
            hint.push_session_hint(kind, Some(index as u64))
                .expect("fill mixed queue");
        }
        hint.push_session_hint(SessionHint::ExplicitEnd, Some(8))
            .expect("boundary evicts activity");

        let mut mixed_drained = Vec::new();
        while let Some(carrier) = mixed.take_buffered_session_hint_carrier() {
            mixed_drained.push(carrier);
        }
        assert_eq!(mixed_drained.len(), SESSION_HINT_QUEUE_CAP);
        assert_eq!(
            mixed_drained
                .iter()
                .filter(|carrier| carrier.hint == SessionHint::Activity)
                .count(),
            1,
            "exactly the later Activity period survives"
        );
        assert_eq!(
            mixed_drained
                .iter()
                .filter(|carrier| carrier.first.claimed_ms == Some(1))
                .count(),
            0,
            "the oldest Activity period was the sole eviction"
        );
        assert_eq!(
            mixed_drained
                .iter()
                .filter(|carrier| carrier.hint != SessionHint::Activity)
                .count(),
            7,
            "all six original boundaries plus the incoming boundary survive"
        );
    }

    #[test]
    fn wake_lane_round_robin_does_not_starve_buffered_macro_under_micro_refill() {
        // P2 (codex r4): fixed micro→meso→macro scan always drained a
        // refilled micro slot first, so a buffered macro/meso wake never
        // returned under continuous micro push. Rotating scan start after
        // each returned wake drains every occupied lane within N=3 takes.
        let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        wake.push_wake(WakeTrigger::Timer, DreamerConsolidationScope::Macro)
            .expect("open channel");

        let mut scopes = Vec::new();
        for _ in 0..3 {
            let Some(Tick::Wake(signal)) = receiver.take_pending() else {
                panic!("expected a wake within the 3-take fairness window");
            };
            scopes.push(signal.scope);
            // Refill micro after every take — the starvation pattern under
            // a fixed scan that always preferred lane 0.
            wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
                .expect("open channel");
        }

        assert_eq!(
            scopes,
            [
                DreamerConsolidationScope::Micro,
                DreamerConsolidationScope::Macro,
                DreamerConsolidationScope::Micro,
            ],
            "cursor advances past drained lane: micro, then macro (skip empty meso), then micro"
        );
        assert_eq!(
            receiver.wake_scan_start, 1,
            "after micro→macro→micro drains, next scan starts at meso (1)"
        );
    }

    #[tokio::test]
    async fn push_recv_ends_when_producers_drop() {
        let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
        wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);
        assert!(matches!(receiver.recv().await, Some(Tick::Wake(_))));
        assert_eq!(receiver.recv().await, None, "drained + no producers");
    }

    #[tokio::test]
    async fn push_recv_delivers_final_wake_when_producer_drops_immediately() {
        // P2 (codex r6 / 3585850157): between empty take_pending and the
        // pushers==0 check a producer can push then Drop. Without a final
        // take_pending re-check, recv returns None while a wake is buffered.
        // Producer order: store under mutex, notify_one, Drop decrements
        // pushers (store-before-decrement). The re-check closes the window
        // either way. Concurrent push+drop while recv is waiting (and the
        // sequential push-then-drop case) both deliver exactly one signal.
        let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
        // Drop the unused hint first so the last producer can race alone.
        drop(hint);

        let producer = tokio::spawn(async move {
            // Let recv park on notified() after an empty take_pending.
            tokio::task::yield_now().await;
            wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
                .expect("open channel");
            drop(wake);
        });

        let first = receiver.recv().await;
        producer.await.expect("producer task");
        assert!(
            matches!(
                first,
                Some(Tick::Wake(WakeSignal {
                    trigger: WakeTrigger::Compaction,
                    scope: DreamerConsolidationScope::Micro,
                }))
            ),
            "exactly one buffered wake must be delivered, got {first:?}"
        );
        assert_eq!(
            receiver.recv().await,
            None,
            "second recv must exhaust (count: exactly 1 signal)"
        );
    }

    #[test]
    fn push_after_receiver_drop_is_rejected() {
        let (receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
        let (push, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
        let (push, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
            .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
                scope,
                input: rmpv::Value::from(tag),
                parent_attempt: None,
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

    /// Vault stable client identity — the same id macro admission compares
    /// via `load_or_mint_client_id` / `local_home_node_candidate`.
    fn vault_client_node_id(vault: &Vault) -> u64 {
        DreamerRunnerStore::new(vault)
            .local_home_node_candidate(false, false, false)
            .expect("vault client identity")
            .node_id
    }

    #[test]
    fn attempt_queue_deadlines_hide_macro_until_local_home_election() {
        let (_dir, vault) = open_vault();
        let local = vault_client_node_id(&vault);
        enqueue(
            &vault,
            DreamerConsolidationScope::Macro,
            "macro-attempt",
            10,
        );

        // No home node elected: macro admission would refuse (NoHomeNode)
        // without mutating the row, so the overdue deadline must not
        // surface and re-tick forever.
        let mut source = AttemptQueueDeadlines::new(&vault, local);
        assert_eq!(source.next_deadline().expect("read"), None);

        // Local vault identity elected home: both admission checks pass and
        // the same row surfaces on the very next re-read.
        elect_home(&vault, local, 15);
        assert_eq!(
            source.next_deadline().expect("read"),
            Some(CommitmentDeadline {
                due_at_ms: 10_000,
                scope: DreamerConsolidationScope::Macro,
            })
        );
    }

    #[test]
    fn attempt_queue_deadlines_on_foreign_home_skip_macro_but_keep_other_lanes() {
        let (_dir, vault) = open_vault();
        let local = vault_client_node_id(&vault);
        let foreign = local.wrapping_add(1).max(1);
        enqueue(
            &vault,
            DreamerConsolidationScope::Macro,
            "macro-attempt",
            10,
        );
        enqueue(
            &vault,
            DreamerConsolidationScope::Micro,
            "micro-attempt",
            20,
        );
        elect_home(&vault, foreign, 25);

        // Local node is not the elected home: the earlier macro deadline is
        // filtered (admission would refuse NotHomeNode without progress)
        // while the micro lane keeps flowing — no spin, no starvation.
        let mut source = AttemptQueueDeadlines::new(&vault, local);
        assert_eq!(
            source.next_deadline().expect("read"),
            Some(CommitmentDeadline {
                due_at_ms: 20_000,
                scope: DreamerConsolidationScope::Micro,
            })
        );
    }

    #[test]
    fn attempt_queue_deadlines_skip_macro_when_designation_matches_but_vault_identity_differs() {
        // P2 (codex r4): a host can pass local_node_id equal to a (stale/
        // copied) home designation that is NOT this vault's stable client
        // id. Admission errors with identity-mismatch without mutating the
        // row; the deadline filter must suppress that macro too.
        let (_dir, vault) = open_vault();
        let vault_id = vault_client_node_id(&vault);
        let spoofed = vault_id.wrapping_add(99).max(1);
        assert_ne!(spoofed, vault_id);
        enqueue(&vault, DreamerConsolidationScope::Macro, "macro-spoof", 10);
        enqueue(&vault, DreamerConsolidationScope::Micro, "micro-ok", 30);
        // Designation equals the spoofed local_node_id, not vault identity.
        elect_home(&vault, spoofed, 20);

        let mut source = AttemptQueueDeadlines::new(&vault, spoofed);
        assert_eq!(
            source.next_deadline().expect("read"),
            Some(CommitmentDeadline {
                due_at_ms: 30_000,
                scope: DreamerConsolidationScope::Micro,
            }),
            "macro must stay suppressed when vault identity ≠ local_node_id"
        );

        // Both match (honest local = vault id = designation): macro surfaces.
        elect_home(&vault, vault_id, 40);
        let mut honest = AttemptQueueDeadlines::new(&vault, vault_id);
        assert_eq!(
            honest.next_deadline().expect("read"),
            Some(CommitmentDeadline {
                due_at_ms: 10_000,
                scope: DreamerConsolidationScope::Macro,
            }),
            "macro surfaces when designation AND vault identity both match"
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
        let (push, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
        let (push, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
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
        let (push, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
        drop(wake);
        drop(hint);
        let mut hybrid = HybridTick::new(timer, push);
        assert_eq!(hybrid.next_tick().await, None);
    }
}
