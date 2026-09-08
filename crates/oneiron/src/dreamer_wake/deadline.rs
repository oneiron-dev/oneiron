//! Monotonic wake-pass clock and cooperative cancellation flag.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

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
/// finalize-window behavior are ONE-1305.
pub struct WakePassDeadline {
    ceiling_ms: u64,
    elapsed_ms: NowMsFn,
}

impl WakePassDeadline {
    /// Starts a deadline NOW over a monotonic [`Instant`] clock.
    #[must_use]
    pub fn new(ceiling_ms: u64) -> Self {
        let origin = Instant::now();
        Self {
            ceiling_ms,
            elapsed_ms: Arc::new(move || {
                u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
        }
    }

    /// Test constructor with an injected elapsed-ms clock (no wall clock in
    /// logic — chain test pin).
    #[must_use]
    pub fn with_clock(ceiling_ms: u64, elapsed_ms: NowMsFn) -> Self {
        Self {
            ceiling_ms,
            elapsed_ms,
        }
    }

    fn elapsed(&self) -> u64 {
        (self.elapsed_ms)()
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
}

impl fmt::Debug for WakePassDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakePassDeadline")
            .field("ceiling_ms", &self.ceiling_ms)
            .field("elapsed_ms", &self.elapsed())
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
/// [`WakePassStop::Cancelled`].
///
/// Clones share the flag; the token holds no waker — it is a level, not an
/// edge, and the pass polls it synchronously as it reaches each checkpoint.
#[derive(Debug, Clone, Default)]
pub struct WakeCancellation {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl WakeCancellation {
    /// A fresh, un-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cooperative preemption. Idempotent; never blocks.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// True once cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
}
