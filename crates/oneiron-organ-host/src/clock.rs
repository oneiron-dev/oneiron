//! A call's time, which stops while the call waits for budget room (Engine
//! ruling, 10-20; FIX 6196, 8020). Its deadline moves on by every such
//! wait, so waiting for room is never charged as the call's run time: the
//! reader's waits for its frames, and the call's own for its answers, its
//! fetched bodies and its outputs. Nothing else moves it. A real read, a
//! connect or a hop runs on the clock, and a cancel or a revocation still
//! ends the call at once.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Waits for room, as a clock that runs only while one lasts. Waits that
/// overlap on one clock count once.
#[derive(Debug, Default)]
pub(crate) struct WaitClock(Mutex<Waits>);

#[derive(Debug, Default)]
struct Waits {
    waited: Duration,
    /// Waits in progress.
    open: u32,
    /// When the first wait in progress began.
    since: Option<Instant>,
}

impl WaitClock {
    fn lock(&self) -> MutexGuard<'_, Waits> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every wait so far, those in progress included.
    pub(crate) fn waited(&self) -> Duration {
        let waits = self.lock();
        waits.waited + waits.since.map_or(Duration::ZERO, |since| since.elapsed())
    }

    /// Runs `wait` on the clock: its whole time, however it ends, is a wait
    /// for room.
    pub(crate) fn timing<T>(&self, wait: impl FnOnce() -> T) -> T {
        {
            let mut waits = self.lock();
            if waits.open == 0 {
                waits.since = Some(Instant::now());
            }
            waits.open += 1;
        }
        let _over = Over(self);
        wait()
    }

    fn stop(&self) {
        let mut waits = self.lock();
        waits.open = waits.open.saturating_sub(1);
        if waits.open == 0
            && let Some(since) = waits.since.take()
        {
            waits.waited += since.elapsed();
        }
    }
}

/// Ends one wait on its clock, a panic included.
struct Over<'a>(&'a WaitClock);

impl Drop for Over<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Where one clock stood when a deadline was set on it.
#[derive(Debug, Clone, Copy, Default)]
struct Mark<'a> {
    clock: Option<&'a WaitClock>,
    from: Duration,
}

impl<'a> Mark<'a> {
    fn at(clock: &'a WaitClock) -> Self {
        Self {
            clock: Some(clock),
            from: clock.waited(),
        }
    }

    fn again(self) -> Self {
        self.clock.map_or(self, Self::at)
    }

    /// The waits on the clock since the mark.
    fn since(self) -> Duration {
        self.clock.map_or(Duration::ZERO, |clock| {
            clock.waited().saturating_sub(self.from)
        })
    }
}

/// One deadline, moved on by the waits for room since it was set: the
/// reader's (frames) and the call's own (answers, bodies, outputs). The two
/// are apart: a reader and a call that wait at the same moment move it by
/// both, which can only leave the call more of its own time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Clock<'a> {
    set: Instant,
    reader: Mark<'a>,
    room: Mark<'a>,
}

impl<'a> Clock<'a> {
    /// `deadline`, which no wait moves: a node that holds no room for the
    /// call.
    pub(crate) fn fixed(deadline: Instant) -> Self {
        Self {
            set: deadline,
            reader: Mark::default(),
            room: Mark::default(),
        }
    }

    /// `deadline`, moved on by every wait `room` times from now.
    pub(crate) fn new(deadline: Instant, room: &'a WaitClock) -> Self {
        Self {
            room: Mark::at(room),
            ..Self::fixed(deadline)
        }
    }

    /// This clock, moved on also by every wait `reader` times from now.
    pub(crate) fn with_reader(self, reader: &'a WaitClock) -> Self {
        Self {
            reader: Mark::at(reader),
            ..self
        }
    }

    /// The deadline, as the waits so far have moved it.
    pub(crate) fn deadline(&self) -> Instant {
        let moved = self.reader.since().saturating_add(self.room.since());
        self.set.checked_add(moved).unwrap_or(self.set)
    }

    /// Whether the moved deadline has passed.
    pub(crate) fn passed(&self) -> bool {
        Instant::now() >= self.deadline()
    }

    /// The time left before the moved deadline.
    pub(crate) fn left(&self) -> Duration {
        self.deadline().saturating_duration_since(Instant::now())
    }

    /// This clock with its deadline no later than `timeout` from now, as a
    /// fetch's own timeout: the same waits move both.
    pub(crate) fn within(self, timeout: Duration) -> Self {
        let now = Instant::now();
        let own = now.checked_add(timeout).unwrap_or_else(|| self.deadline());
        Self {
            set: self.deadline().min(own),
            reader: self.reader.again(),
            room: self.room.again(),
        }
    }
}
