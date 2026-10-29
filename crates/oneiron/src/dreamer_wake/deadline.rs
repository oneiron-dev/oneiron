//! Monotonic wake-pass clock and cooperative cancellation flag.

use std::fmt;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::observation::{WakeBinding, WakeRef};

/// Wake-pass wall-clock ceiling: the REAL ceiling (1184-D4-C), monotonic.
pub const DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS: u64 = 180_000;

/// Bounded graceful-wrap window before the hard cut (1184-D4-E):
/// finalize window = `[165_000, 180_000)` under the default ceiling.
pub const DREAMER_GRACEFUL_WRAP_WINDOW_MS: u64 = 15_000;

/// Wrap-up-soon notice threshold (1184-D4-D): counter OR clock percent.
pub const DREAMER_WRAP_UP_NOTICE_PERCENT: u64 = 80;

type NowMsFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Monotonic wake-pass deadline (immune to wall-time jumps).
///
/// ONE-1288 ships the type + reads; the pinned 180s ceiling constant and
/// finalize-window behavior are ONE-1305. The wall-clock origin is recorded
/// beside the monotonic one, for the wake observation only (DOOR-144): the
/// ceiling is enforced on the monotonic clock alone.
#[derive(Clone)]
pub struct WakePassDeadline {
    ceiling_ms: u64,
    elapsed_ms: NowMsFn,
    origin_unix_ms: Option<u64>,
    /// The wake observation this pass's root committed, carried to clones.
    wake: Option<WakeBinding>,
}

impl WakePassDeadline {
    /// Starts a deadline NOW over a monotonic [`Instant`] clock, and reads
    /// the wall clock at the same origin.
    #[must_use]
    pub fn new(ceiling_ms: u64) -> Self {
        let origin = Instant::now();
        let origin_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_millis()).ok());
        Self {
            ceiling_ms,
            elapsed_ms: Arc::new(move || {
                u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
            origin_unix_ms,
            wake: None,
        }
    }

    /// Test constructor with an injected elapsed-ms clock (no wall clock in
    /// logic — chain test pin). It has no wall origin to report.
    ///
    /// A wake pass reads `elapsed_ms` inside the vault's write transaction,
    /// which may be one group commit shared with other writes. It must only
    /// read time: it must not call into the vault or wait on anything a vault
    /// caller can hold while it writes, or the vault's writer deadlocks.
    #[must_use]
    pub fn with_clock(ceiling_ms: u64, elapsed_ms: NowMsFn) -> Self {
        Self {
            ceiling_ms,
            elapsed_ms,
            origin_unix_ms: None,
            wake: None,
        }
    }

    fn elapsed(&self) -> u64 {
        (self.elapsed_ms)()
    }

    /// Milliseconds since the origin, on the monotonic clock.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed()
    }

    /// The hard ceiling in milliseconds after the origin.
    #[must_use]
    pub const fn ceiling_ms(&self) -> u64 {
        self.ceiling_ms
    }

    /// Unix milliseconds the wall clock read at the origin; `None` under an
    /// injected clock.
    #[must_use]
    pub const fn origin_unix_ms(&self) -> Option<u64> {
        self.origin_unix_ms
    }

    /// The ceiling anchored to the wall origin: a projection fixed at the
    /// origin, which a later wall-clock jump never moves.
    #[must_use]
    pub fn ceiling_unix_ms(&self) -> Option<u64> {
        self.origin_unix_ms?.checked_add(self.ceiling_ms)
    }

    /// The wake observation this pass's root committed; `None` outside an
    /// observed pass.
    #[must_use]
    pub fn wake_ref(&self) -> Option<WakeRef> {
        self.wake.as_ref().map(WakeBinding::wake)
    }

    pub(super) fn wake_binding(&self) -> Option<&WakeBinding> {
        self.wake.as_ref()
    }

    /// Binds the root's committed wake, or clears it once the pass ends.
    pub(super) fn bind_wake(&mut self, wake: Option<WakeBinding>) {
        self.wake = wake;
    }

    /// The same clock with no wake bound: the live registry's copy, which
    /// holds no pass alive.
    pub(super) fn unbound(&self) -> Self {
        Self {
            ceiling_ms: self.ceiling_ms,
            elapsed_ms: Arc::clone(&self.elapsed_ms),
            origin_unix_ms: self.origin_unix_ms,
            wake: None,
        }
    }

    /// Milliseconds left before the hard ceiling.
    #[must_use]
    pub fn remaining_ms(&self) -> u64 {
        self.ceiling_ms.saturating_sub(self.elapsed())
    }

    /// Elapsed share of the ceiling in percent, saturating at 100.
    #[must_use]
    pub fn elapsed_percent(&self) -> u64 {
        if self.ceiling_ms == 0 {
            return 100;
        }
        let numerator = u128::from(self.elapsed()).saturating_mul(100);
        (numerator / u128::from(self.ceiling_ms)).min(100) as u64
    }

    /// True once the hard ceiling has passed.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.elapsed() >= self.ceiling_ms
    }

    /// True inside the bounded graceful-wrap window before the hard cut:
    /// `elapsed >= ceiling - DREAMER_GRACEFUL_WRAP_WINDOW_MS` (ONE-1305).
    #[must_use]
    pub fn in_finalize_window(&self) -> bool {
        self.elapsed()
            >= self
                .ceiling_ms
                .saturating_sub(DREAMER_GRACEFUL_WRAP_WINDOW_MS)
    }

    /// True once even a finished partition must checkpoint rather than land
    /// (FIX 11570): past the ceiling by more than the graceful-wrap window,
    /// which a partition that finished its model steps borrows for its
    /// landing write.
    #[must_use]
    pub fn landing_closed(&self) -> bool {
        self.elapsed()
            >= self
                .ceiling_ms
                .saturating_add(DREAMER_GRACEFUL_WRAP_WINDOW_MS)
    }
}

impl fmt::Debug for WakePassDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakePassDeadline")
            .field("ceiling_ms", &self.ceiling_ms)
            .field("elapsed_ms", &self.elapsed())
            .field("origin_unix_ms", &self.origin_unix_ms)
            .field("wake", &self.wake_ref())
            .finish()
    }
}

/// Cooperative wake-pass cancellation token (ONE-1683, H-S5/R2).
///
/// A supervisor raises the flag with [`cancel`](Self::cancel); the running
/// pass observes it ONLY at its attempt-boundary checkpoints (loop top and the
/// pre-dispatch point after admission) — the same places the deadline stops
/// admission. Cancellation is never honored mid-await inside the executor or
/// between a gated write's start and its settle: aborting a pass mid-write
/// would reopen the S3 off-record fence leak. A cancel that lands after a
/// attempt was admitted parks that attempt and refunds its budget reservation
/// through the ordinary Park bookkeeping before the pass reports
/// [`WakePassStop::Cancelled`](crate::WakePassStop::Cancelled).
///
/// Clones share the flag; the token holds no waker — it is a level, not an
/// edge, and the pass polls it synchronously as it reaches each checkpoint.
/// The flag also records which request raised it first: a stop
/// ([`cancel`](Self::cancel)) or the host's pause ([`pause`](Self::pause)).
#[derive(Debug, Clone, Default)]
pub struct WakeCancellation {
    /// `LIVE`, `STOPPED` or `PAUSED`.
    raised: Arc<std::sync::atomic::AtomicU8>,
}

/// No cancellation requested.
const LIVE: u8 = 0;
/// Cancelled by a stop.
const STOPPED: u8 = 1;
/// Cancelled by the host's pause (FIX 6909).
const PAUSED: u8 = 2;

impl WakeCancellation {
    /// A fresh, un-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cooperative preemption. Idempotent; never blocks.
    pub fn cancel(&self) {
        self.raise(STOPPED);
    }

    /// Requests cooperative preemption for the host's pause (FIX 6909): as
    /// [`Self::cancel`], except that an attempt it stops before dispatch
    /// parks [`DreamerParkCause::Paused`](crate::DreamerParkCause::Paused),
    /// which a later pass resumes. Once a stop raised the flag, it stays a
    /// stop.
    pub fn pause(&self) {
        self.raise(PAUSED);
    }

    fn raise(&self, cause: u8) {
        let _ = self.raised.compare_exchange(
            LIVE,
            cause,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    /// True once cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.raised.load(std::sync::atomic::Ordering::Acquire) != LIVE
    }

    /// True when the host's pause, not a stop, raised the flag.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.raised.load(std::sync::atomic::Ordering::Acquire) == PAUSED
    }
}
