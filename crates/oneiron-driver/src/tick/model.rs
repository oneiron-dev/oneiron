//! Public tick vocabulary: tick enum, deadline and signal types, session-hint carrier, and the tick and deadline source traits.

use oneiron::{DreamerConsolidationScope, WakeTrigger};

use crate::session::SessionHint;

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

    pub(super) fn aggregate_activity(&mut self, claimed_ms: Option<u64>, arrival_ms: u64) {
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
