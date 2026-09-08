//! Push lane: coalescing mailbox state, push error, receiver, and role-typed producer handles.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::{DreamerConsolidationScope, WakeTrigger};
use tokio::sync::Notify;

use super::{
    HintSignal, NowMillis, SessionHintCarrier, Tick, TickSource, WakeSignal, system_now_ms,
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

/// Bound of the ordered SESSION-hint queue. Arrival order IS lifecycle
/// causality (end-then-open is a reopen; open-end-open is two sittings), so
/// session hints are queued in order and NEVER reordered; only ADJACENT
/// Activity hints inside the idle floor coalesce (a typing burst is one
/// endpoint-preserving period).
/// Boundary hints never coalesce or evict: overflow sheds only Activity, and
/// reports [`TickPushError::QueueFull`] when a full all-boundary queue receives
/// another boundary.
pub(super) const SESSION_HINT_QUEUE_CAP: usize = 8;

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
