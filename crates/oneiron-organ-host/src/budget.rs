//! One admission budget for every organ: threads, memory, in-flight calls.
//!
//! It decides whether a call may start now, never when work runs (canon
//! pins "no second scheduler"). Classes wait in priority order; background
//! work may hold at most half the threads; one core stays free of organs.
//! A call that books more memory than the whole budget is never refused on
//! size (Rule 5): it runs alone, once the budget has drained.
//!
//! A live call grows (FIX 5284): its answers and outputs, and the frames
//! that carry them, take room as they come, past what it booked. Growth
//! waits for room while other live calls can give some back, and new calls
//! wait behind it. When every live call is waiting to grow, none could give
//! room back, so one of them goes on past the budget: the soft-target
//! exception (Engine ruling A, 10-20). Its overcommit is fully accounted,
//! and on its receipt; the budget stays the target, and drains before any
//! new call starts. Time spent waiting for room is the call's own, never
//! counted against its deadline, and only a cancel or a revocation ends it.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::error::HostError;
use crate::spec::CallClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetConfig {
    pub threads: u32,
    pub memory_bytes: u64,
    pub max_inflight: u32,
}

impl BudgetConfig {
    /// Every core but one, 2 GiB, 64 calls in flight.
    #[must_use]
    pub fn for_this_machine() -> Self {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
        Self {
            threads: u32::try_from(cores.saturating_sub(1).max(1)).unwrap_or(1),
            memory_bytes: 2 * 1024 * 1024 * 1024,
            max_inflight: 64,
        }
    }
}

#[derive(Debug, Default)]
struct Used {
    threads: u32,
    memory: u64,
    inflight: u32,
    waiting: [u32; 3],
    /// Of those waiting, the calls bigger than the whole budget. While one
    /// waits, its class admits nothing new, so the budget drains for it.
    whole: [u32; 3],
    /// Live calls and frames waiting for room to grow. While any waits, no
    /// new call is admitted, so the budget drains for them.
    growing: u32,
}

/// How long a wait for room sleeps before it asks again whether its call
/// still wants the room.
const RECHECK: Duration = Duration::from_millis(20);

/// What one growth took.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Grown {
    /// Of the growth, the bytes past the budget: the soft-target exception.
    pub(crate) overcommit: u64,
    /// The memory the budget held once it grew.
    pub(crate) peak: u64,
    /// How long it waited for room.
    pub(crate) waited: Duration,
}

#[derive(Debug)]
pub(crate) struct Budget {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    config: BudgetConfig,
    used: Mutex<Used>,
    freed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Used> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn give_back(&self, memory: u64) {
        let mut used = self.lock();
        used.memory -= memory;
        drop(used);
        self.freed.notify_all();
    }

    /// Takes `delta` more memory for a live holder: at once when it fits the
    /// budget; else once others give room back; else, when every live call
    /// is itself waiting to grow, past the budget. No deadline ends the
    /// wait; `stopped` does, polled while it waits, and then nothing is
    /// taken.
    fn grow(&self, delta: u64, stopped: &dyn Fn() -> bool) -> Option<Grown> {
        let target = self.config.memory_bytes;
        let began = Instant::now();
        let mut used = self.lock();
        used.growing += 1;
        loop {
            let after = used.memory.saturating_add(delta);
            // Every live call waits to grow: none can give room back, so
            // this one goes on past the budget, and the others wait for it.
            if after <= target || used.growing >= used.inflight {
                used.growing -= 1;
                used.memory = after;
                drop(used);
                self.freed.notify_all();
                return Some(Grown {
                    overcommit: after.saturating_sub(target).min(delta),
                    peak: after,
                    waited: began.elapsed(),
                });
            }
            if stopped() {
                used.growing -= 1;
                drop(used);
                self.freed.notify_all();
                return None;
            }
            used = self
                .freed
                .wait_timeout(used, RECHECK)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// What ends a wait for room: the call's grant revoked, or its process
/// gone. Polled while the wait lasts; no deadline ends it.
#[derive(Clone, Copy)]
pub(crate) struct Stop<'a>(pub(crate) &'a dyn Fn() -> bool);

impl std::fmt::Debug for Stop<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Stop")
    }
}

impl Stop<'static> {
    /// Never stops: a wait only room ends.
    pub(crate) const NEVER: Self = Stop(&never);
}

fn never() -> bool {
    false
}

/// The budget, as a frame reader holds it: room for each frame's body
/// before it is read.
#[derive(Debug, Clone)]
pub(crate) struct Room {
    shared: Arc<Shared>,
}

/// Memory one frame holds while its bytes live, given back on drop.
#[derive(Debug)]
pub(crate) struct Lease {
    shared: Arc<Shared>,
    memory: u64,
    grown: Grown,
}

impl Room {
    /// Room for `bytes` of a frame, as a live call grows: `None` once
    /// `stopped` says the frame is no longer wanted.
    pub(crate) fn lease(&self, bytes: u64, stopped: &dyn Fn() -> bool) -> Option<Lease> {
        let grown = self.shared.grow(bytes, stopped)?;
        Some(Lease {
            shared: Arc::clone(&self.shared),
            memory: bytes,
            grown,
        })
    }
}

impl Lease {
    /// The frame's bytes this lease holds room for.
    pub(crate) fn bytes(&self) -> u64 {
        self.memory
    }

    /// What taking the room took: past the budget, and the wait for it.
    pub(crate) fn grown(&self) -> Grown {
        self.grown
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.shared.give_back(self.memory);
    }
}

/// A booked share of the budget, returned on drop.
#[derive(Debug)]
pub(crate) struct Permit {
    shared: Arc<Shared>,
    threads: u32,
    memory: u64,
}

/// Memory a call's outputs keep after the call returns, out of its permit;
/// given back when the outputs drop.
#[derive(Debug)]
pub(crate) struct Kept {
    shared: Arc<Shared>,
    memory: u64,
}

/// One live call's room: what its permit booked, grown as its answers and
/// outputs need, and how much of it they hold.
#[derive(Debug)]
pub(crate) struct CallRoom {
    state: Mutex<RoomState>,
}

#[derive(Debug)]
struct RoomState {
    permit: Permit,
    /// Of the permit's memory, what answers lent and outputs kept hold.
    held: u64,
    overcommit: u64,
    peak: u64,
    waited: Duration,
}

impl CallRoom {
    pub(crate) fn new(permit: Permit) -> Self {
        Self {
            state: Mutex::new(RoomState {
                permit,
                held: 0,
                overcommit: 0,
                peak: 0,
                waited: Duration::ZERO,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, RoomState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds `bytes` more of the call's room, its booking grown first when
    /// they pass it. `false` once `stopped` ends a wait for room: nothing
    /// more is held.
    pub(crate) fn hold(&self, bytes: u64, stopped: &dyn Fn() -> bool) -> bool {
        let mut state = self.lock();
        let need = state.held.saturating_add(bytes);
        if need > state.permit.memory {
            let delta = need - state.permit.memory;
            let shared = Arc::clone(&state.permit.shared);
            let Some(grown) = shared.grow(delta, stopped) else {
                return false;
            };
            state.permit.memory += delta;
            state.overcommit = state.overcommit.saturating_add(grown.overcommit);
            state.peak = state.peak.max(grown.peak);
            state.waited += grown.waited;
        }
        state.held = need;
        true
    }

    /// Gives back `bytes` held for an answer the organ was never sent. The
    /// booking keeps its size.
    pub(crate) fn release(&self, bytes: u64) {
        let mut state = self.lock();
        state.held = state.held.saturating_sub(bytes);
    }

    /// Moves `bytes` already held to an output that outlives the call.
    pub(crate) fn keep(&self, bytes: u64) -> Kept {
        let mut state = self.lock();
        state.held -= bytes;
        state.permit.memory -= bytes;
        Kept {
            shared: Arc::clone(&state.permit.shared),
            memory: bytes,
        }
    }

    /// What answers lent and outputs kept hold of the call's room.
    pub(crate) fn held(&self) -> u64 {
        self.lock().held
    }

    /// What the call's growth took past the budget, the budget's peak with
    /// it, and how long it waited for room.
    pub(crate) fn grown(&self) -> Grown {
        let state = self.lock();
        Grown {
            overcommit: state.overcommit,
            peak: state.peak,
            waited: state.waited,
        }
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        self.shared.give_back(self.memory);
    }
}

fn rank(class: CallClass) -> usize {
    match class {
        CallClass::Interactive => 0,
        CallClass::Agent => 1,
        CallClass::Background => 2,
    }
}

impl Budget {
    pub(crate) fn new(config: BudgetConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                used: Mutex::new(Used::default()),
                freed: Condvar::new(),
            }),
        }
    }

    /// The budget as a frame reader holds it.
    pub(crate) fn room(&self) -> Room {
        Room {
            shared: Arc::clone(&self.shared),
        }
    }

    /// The budget's memory: the target growth may pass only under the
    /// soft-target exception.
    pub(crate) fn memory_bytes(&self) -> u64 {
        self.shared.config.memory_bytes
    }

    /// Books `threads` and `memory` for one call, waiting in class order
    /// until they fit or `deadline` passes. Memory past the whole budget
    /// fits once nothing else holds any; threads past the class's share
    /// are booked as all of it, so the call runs alone in its class. While
    /// a live call waits to grow, nothing new is admitted.
    pub(crate) fn admit(
        &self,
        class: CallClass,
        threads: u32,
        memory: u64,
        deadline: Instant,
    ) -> Result<Permit, HostError> {
        let shared = &self.shared;
        let config = shared.config;
        let whole = memory > config.memory_bytes;
        let rank = rank(class);
        let thread_cap = if class == CallClass::Background {
            (config.threads / 2).max(1)
        } else {
            config.threads
        };
        let threads = threads.min(thread_cap);
        let mut used = shared.lock();
        used.waiting[rank] += 1;
        used.whole[rank] += u32::from(whole);
        loop {
            let ahead = used.waiting[..rank].iter().any(|count| *count > 0);
            // A smaller call of the same class waits behind a whole-budget
            // one, which would otherwise never see the budget drain.
            let held = (!whole && used.whole[rank] > 0) || used.growing > 0;
            let room = if whole {
                used.memory == 0
            } else {
                used.memory.saturating_add(memory) <= config.memory_bytes
            };
            let fits =
                used.threads + threads <= thread_cap && room && used.inflight < config.max_inflight;
            if !ahead && !held && fits {
                used.waiting[rank] -= 1;
                used.whole[rank] -= u32::from(whole);
                used.threads += threads;
                used.memory += memory;
                used.inflight += 1;
                return Ok(Permit {
                    shared: Arc::clone(shared),
                    threads,
                    memory,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                used.waiting[rank] -= 1;
                used.whole[rank] -= u32::from(whole);
                drop(used);
                shared.freed.notify_all();
                return Err(HostError::BudgetTimeout);
            }
            used = shared
                .freed
                .wait_timeout(used, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut used = self.shared.lock();
        used.threads -= self.threads;
        used.memory -= self.memory;
        used.inflight -= 1;
        drop(used);
        self.shared.freed.notify_all();
    }
}
