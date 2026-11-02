//! Push lane: coalescing mailbox state, push error, receiver, and role-typed producer handles.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use oneiron::session_lifecycle::SessionKey;
use oneiron::{DreamerConsolidationScope, WakeTrigger};
use tokio::sync::Notify;

use super::queue::SessionHintQueue;
use super::{
    ArmedLane, HintSignal, NowMillis, SessionHintCarrier, Tick, TickSource, WakeSignal,
    system_now_ms,
};
use crate::session::SessionHint;

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

/// The first re-check of a producer waiting for room, doubling to
/// [`PRESSURE_RECHECK_MAX`]. Pacing only, never a limit: memory can free up
/// with nothing drained, so the head of the line looks again, and it stays
/// in line until its fact is kept, the receiver is gone or its own deadline
/// passes.
const PRESSURE_RECHECK_FIRST: Duration = Duration::from_millis(1);
const PRESSURE_RECHECK_MAX: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct PushState {
    wake: [Option<WakeSignal>; SCOPE_LANES],
    /// Plain advisory hints: one coalescing slot (unchanged wave-1 shape).
    plain_hint: Option<HintSignal>,
    /// Session-lifecycle hints in ARRIVAL order, uncapped (FIX 8602).
    session_hints: SessionHintQueue,
    /// What each timer lane of the receiving stack is armed for.
    armed: ArmedWakes,
}

/// Timer lanes [`ArmedLane`] names.
const ARMED_LANES: usize = 3;

fn armed_lane(lane: ArmedLane) -> usize {
    match lane {
        ArmedLane::Queue => 0,
        ArmedLane::Policy => 1,
        ArmedLane::Session => 2,
    }
}

/// The instant (unix milliseconds) each timer lane is armed for, and the
/// earliest of them, published to [`HintPusher::next_wake`] subscribers.
/// A record, never a timer: the lanes sleep on their own.
#[derive(Debug)]
struct ArmedWakes {
    lanes: [Option<u64>; ARMED_LANES],
    next: tokio::sync::watch::Sender<Option<u64>>,
}

impl Default for ArmedWakes {
    fn default() -> Self {
        Self {
            lanes: [None; ARMED_LANES],
            next: tokio::sync::watch::Sender::new(None),
        }
    }
}

impl ArmedWakes {
    fn record(&mut self, lane: ArmedLane, at_ms: Option<u64>) {
        self.lanes[armed_lane(lane)] = at_ms;
        let next = self.lanes.iter().flatten().min().copied();
        self.next.send_if_modified(|published| {
            let changed = *published != next;
            *published = next;
            changed
        });
    }
}

struct PushShared {
    state: Mutex<PushState>,
    notify: Notify,
    /// Wakes producers waiting for session-hint room: each drain, and the
    /// receiver going away.
    drained: Condvar,
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

    /// Pops the oldest session hint; a producer waiting for room is woken.
    fn pop_session_hint(&self) -> Option<SessionHintCarrier> {
        let mut state = self.lock_state();
        let carrier = state.session_hints.pop_front();
        let waiting = !state.session_hints.line_empty();
        drop(state);
        if carrier.is_some() && waiting {
            self.drained.notify_all();
        }
        carrier
    }
}

/// Rejected push. A rejected session hint was not queued: nothing reports
/// a fact kept that was not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickPushError {
    /// The receiving supervisor is gone; the signal can never be consumed.
    Closed,
    /// The allocator has no room for the session hint, or earlier hints
    /// wait for room ahead of it. [`HintPusher::push_session_hint_waiting`]
    /// waits its turn instead.
    MemoryPressure,
    /// The caller's own deadline passed while its session hint waited for
    /// room.
    DeadlinePassed,
}

impl fmt::Display for TickPushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "push tick channel closed"),
            Self::MemoryPressure => write!(f, "no room for the session hint"),
            Self::DeadlinePassed => write!(f, "deadline passed while the session hint waited"),
        }
    }
}

impl std::error::Error for TickPushError {}

/// Receiving half of the push channel: ONE bounded coalescing mailbox —
/// one wake slot per consolidation lane (drained first with a rotating scan
/// start so a lane that refills every pass cannot starve older buffered
/// wakes), an ORDERED uncapped session-hint queue (arrival order preserved;
/// only adjacent Activity hints inside the idle floor coalesce — lifecycle
/// causality is never rewritten), and one coalescing slot for the plain advisory hint. Bursts
/// therefore collapse while distinct signals keep their order.
pub struct PushTick {
    shared: Arc<PushShared>,
    /// Next wake-lane index to try first (round-robin). Advances after each
    /// returned wake so every occupied lane drains within [`SCOPE_LANES`]
    /// takes even when a lower index refills between drains.
    pub(super) wake_scan_start: usize,
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
            drained: Condvar::new(),
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
    pub(super) fn take_pending(&mut self) -> Option<Tick> {
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
        let carrier = state.session_hints.pop_front();
        let waiting = carrier.is_some() && !state.session_hints.line_empty();
        let tick = match carrier {
            Some(carrier) => {
                self.delivered_session_hint = Some(carrier);
                Some(Tick::Hint(HintSignal {
                    session: Some(carrier.hint),
                }))
            }
            None => state.plain_hint.take().map(Tick::Hint),
        };
        drop(state);
        // A drain makes room: a producer waiting for it looks now.
        if waiting {
            self.shared.drained.notify_all();
        }
        tick
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
    pub(super) async fn recv(&mut self) -> Option<Tick> {
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

    /// Records `lane`'s armed instant in the shared mailbox, for
    /// [`HintPusher::next_wake`] (see [`TickSource::note_armed`]).
    pub(super) fn record_armed(&self, lane: ArmedLane, at_ms: Option<u64>) {
        self.shared.lock_state().armed.record(lane, at_ms);
    }
}

impl Drop for PushTick {
    fn drop(&mut self) {
        // Under the mailbox lock, so a producer waiting for room cannot miss
        // the wake between its check and its wait.
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.shared.receiver_alive.store(false, Ordering::Release);
        drop(state);
        self.shared.drained.notify_all();
    }
}

impl TickSource for PushTick {
    async fn next_tick(&mut self) -> Option<Tick> {
        self.recv().await
    }

    fn take_buffered_session_hint(
        &mut self,
    ) -> Option<(SessionKey, SessionHint, Option<u64>, u64)> {
        self.shared.pop_session_hint().map(|carrier| {
            (
                carrier.key,
                carrier.hint,
                carrier.first.claimed_ms,
                carrier.first.arrival_ms,
            )
        })
    }

    fn take_buffered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.shared.pop_session_hint()
    }

    fn take_delivered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.delivered_session_hint.take()
    }

    fn note_armed(&mut self, lane: ArmedLane, at_ms: Option<u64>) {
        self.record_armed(lane, at_ms);
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

    /// The earliest instant (unix milliseconds) any timer lane of the
    /// receiving stack is armed for, `None` while none is, updated as the
    /// lanes re-arm. A host that may suspend this process arms its own timer
    /// for it and, when that fires, wakes the stack with [`Self::push_hint`]:
    /// each lane then re-reads what is due on the wall clock.
    #[must_use]
    pub fn next_wake(&self) -> tokio::sync::watch::Receiver<Option<u64>> {
        self.shared.lock_state().armed.next.subscribe()
    }

    /// Pushes a session-lifecycle hint (ONE-1685) onto the ORDERED queue
    /// (FIX 8602). Arrival order is preserved end-to-end — lifecycle
    /// causality (open → end → open is two sittings) is never rewritten by
    /// coalescing; only ADJACENT Activity hints whose arrivals are separated
    /// by less than the channel's idle floor aggregate (with both endpoint
    /// stamps and a count). Nothing is evicted or dropped: when the allocator
    /// has no room, or earlier hints already wait for room, this refuses with
    /// [`TickPushError::MemoryPressure`] and keeps nothing, and
    /// [`Self::push_session_hint_waiting`] waits its turn instead. Carrying a
    /// lifecycle fact grants NO pass-shaping authority — the driver's session
    /// policy decides what, if anything, results (H-S4).
    pub fn push_session_hint(
        &self,
        key: SessionKey,
        hint: SessionHint,
        claimed_ms: Option<u64>,
    ) -> Result<(), TickPushError> {
        let mut state = self.shared.lock_state();
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(TickPushError::Closed);
        }
        let carrier = SessionHintCarrier::point(key, hint, claimed_ms, (self.shared.now_ms)());
        if !state.session_hints.line_empty()
            || !state
                .session_hints
                .keep(carrier, self.shared.coalesce_floor_ms)
        {
            return Err(TickPushError::MemoryPressure);
        }
        drop(state);
        self.shared.notify.notify_one();
        Ok(())
    }

    /// [`Self::push_session_hint`] that waits its turn under real memory
    /// pressure instead of refusing. Producers that wait are served in
    /// arrival order, each fact with the arrival stamp it came with, and a
    /// later fact never passes one still waiting. Each drain wakes the line,
    /// and its head also looks again on a doubling pace, since memory can
    /// free up with nothing drained. `deadline` is the caller's own: `None`
    /// waits until the fact is kept or the receiver is gone. Blocks the
    /// calling thread; an async caller runs it where blocking is allowed.
    pub fn push_session_hint_waiting(
        &self,
        key: SessionKey,
        hint: SessionHint,
        claimed_ms: Option<u64>,
        deadline: Option<Instant>,
    ) -> Result<(), TickPushError> {
        let floor = self.shared.coalesce_floor_ms;
        let mut state = self.shared.lock_state();
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(TickPushError::Closed);
        }
        let carrier = SessionHintCarrier::point(key, hint, claimed_ms, (self.shared.now_ms)());
        if state.session_hints.line_empty() && state.session_hints.keep(carrier, floor) {
            drop(state);
            self.shared.notify.notify_one();
            return Ok(());
        }
        let ticket = state.session_hints.join_line();
        tracing::warn!(?hint, "session hint waits for room in arrival order");
        let mut recheck = PRESSURE_RECHECK_FIRST;
        let outcome = loop {
            if !self.shared.receiver_alive.load(Ordering::Acquire) {
                break Err(TickPushError::Closed);
            }
            if state.session_hints.is_turn(ticket) && state.session_hints.keep(carrier, floor) {
                break Ok(());
            }
            let wait = match deadline {
                Some(at) => match at.checked_duration_since(Instant::now()) {
                    Some(left) if !left.is_zero() => left.min(recheck),
                    _ => break Err(TickPushError::DeadlinePassed),
                },
                None => recheck,
            };
            state = self
                .shared
                .drained
                .wait_timeout(state, wait)
                .expect("push mailbox lock poisoned")
                .0;
            recheck = recheck.saturating_mul(2).min(PRESSURE_RECHECK_MAX);
        };
        state.session_hints.leave_line(ticket);
        drop(state);
        // The turn moved on: the next producer in line looks now.
        self.shared.drained.notify_all();
        if outcome.is_ok() {
            self.shared.notify.notify_one();
        } else {
            tracing::warn!(?hint, ?outcome, "session hint left the line unkept");
        }
        outcome
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
