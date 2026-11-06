//! A scoped child's live cutoff at its port calls and reads (FIX 8233).
//!
//! The runner bounds each entry of a scoped child by its job's cutoff and
//! by its parent's live clock. A port call and a read of a lent input are
//! synchronous: once admitted, the entry's timeout cannot stop them. This
//! control takes the same bound into them. It holds the child's monotonic
//! deadline, when its parent's host lent a live clock, and its job's frozen
//! wall cutoff. A port's wait and a read check it at each of their steps,
//! stop there, and answer `reader_task_settled`; the runner then ends the
//! entry at its cutoff.
//!
//! The stop is cooperative. A syscall already entered is not preempted, and
//! an admitted durable model step is not cancelled: its parent finishes it
//! and settles its spend (ARCH-0026, ARCH-0036). The control lives in memory
//! only: no job row, loan or replay record holds it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// What a scoped child's port call or read answers once its job settled,
/// was claimed again since, or reached its cutoff, its live cutoff included.
pub const READER_TASK_SETTLED: &str = "reader_task_settled";

/// The live cutoff of one scoped child's run (FIX 8233): the monotonic
/// deadline its runner derived from its parent's live clock, less the fold
/// reserve its first spawn froze, and its job's frozen wall cutoff. Its
/// runner binds it with the child's dispatcher and keeps a copy; every copy
/// shares one latch, so a cut a port call or a read sees is the runner's to
/// read once the entry returns.
#[derive(Debug, Clone)]
pub struct ScopedCallControl {
    deadline: Option<Instant>,
    cutoff_unix_ms: u64,
    cut: Arc<AtomicBool>,
}

impl ScopedCallControl {
    /// The control of a child due at `deadline` on the monotonic clock, when
    /// its parent's host lent a live clock, and at `cutoff_unix_ms`, its
    /// job's frozen cutoff, on the wall clock. No time is added to either.
    #[must_use]
    pub fn new(deadline: Option<Instant>, cutoff_unix_ms: u64) -> Self {
        Self {
            deadline,
            cutoff_unix_ms,
            cut: Arc::new(AtomicBool::new(false)),
        }
    }

    /// What is left at `now` before the earlier of its two bounds; zero once
    /// either is reached, and from then on. The wall clock is read after
    /// `now`. Without a monotonic deadline the wall cutoff alone bounds it,
    /// as the stored cutoff did; a wall clock set back never widens a
    /// monotonic deadline it holds.
    #[must_use]
    pub fn left(&self, now: Instant) -> Duration {
        self.left_before(now, u64::MAX)
    }

    /// [`Self::left`], bounded as well by `cutoff_unix_ms`, a wall cutoff
    /// its caller holds of its own (a port's stored cutoff): a cut by that
    /// cutoff is the child's cut too, and latches as one.
    #[must_use]
    pub fn left_before(&self, now: Instant, cutoff_unix_ms: u64) -> Duration {
        if self.is_cut() {
            return Duration::ZERO;
        }
        let cutoff_unix_ms = self.cutoff_unix_ms.min(cutoff_unix_ms);
        let wall = Duration::from_millis(cutoff_unix_ms.saturating_sub(crate::unix_millis_now()));
        let left = self.deadline.map_or(wall, |deadline| {
            wall.min(deadline.saturating_duration_since(now))
        });
        if left.is_zero() {
            self.cut.store(true, Ordering::Relaxed);
        }
        left
    }

    /// Whether the child's live cutoff is reached at `now`, by either
    /// bound ([`Self::left`]). A cutoff it reports reached stays reached.
    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        self.left(now).is_zero()
    }

    /// Whether a check of this control, or of a copy of it, found the
    /// cutoff reached: the runner ends the child's entry at its cutoff then.
    #[must_use]
    pub fn is_cut(&self) -> bool {
        self.cut.load(Ordering::Relaxed)
    }
}
