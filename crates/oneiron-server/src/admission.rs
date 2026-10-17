//! Admission for work a remote caller can start.
//!
//! The rule every remotely reachable piece of work follows: it takes a permit
//! before it begins, and the permit travels with the work itself (the
//! connection, the child process, the upload spool, the worker thread), never
//! only with the handler that started it. A caller who hangs up therefore
//! frees nothing the work still holds.
//!
//! Past the bound, work waits; it is never refused for count (the owner's
//! rate law, ARCH-0044 C5). Waiters are served round-robin across keys (a
//! principal, a credential) and in arrival order within one key, so a fleet
//! that shares one credential takes one turn in each round, as every other
//! credential does, and no key needs a cap of its own. Each wait has a
//! deadline, sized as a request timeout rather than as a limit. The host's
//! own background work waits behind every caller.
//!
//! Each bound is a `[limits]` row set far above fleet scale. When work has to
//! wait and nobody waited before it, the row is crossed: it raises its typed
//! "is everything okay" question (OF-520, see [`LimitQuestions`]), which
//! counts every crossing.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// A wait that reached its deadline before a permit came free. Nothing was
/// started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitTimedOut;

/// A bound over one kind of work, and the queue of work waiting for it.
pub(crate) struct Admission<K> {
    pool: Arc<Pool<K>>,
}

/// A clone shares the pool: one bound, one queue.
impl<K> Clone for Admission<K> {
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
        }
    }
}

struct Pool<K> {
    queue: Mutex<Queue<K>>,
    bound: usize,
    wait: Duration,
    /// The row this bound is, and where its crossing is asked; `None` for a
    /// turn that is exclusive by nature rather than a threshold.
    row: Option<(LimitRow, Arc<LimitQuestions>)>,
}

struct Queue<K> {
    held: usize,
    /// Each key's waiters, oldest first.
    waiting: HashMap<K, VecDeque<Arc<Waiter>>>,
    /// The keys with a waiter, in the order their turns come.
    turns: VecDeque<K>,
    /// The host's own work, served only when no caller waits.
    background: VecDeque<Arc<Waiter>>,
    /// Whether the crossing in progress has asked its question.
    asked: bool,
}

/// One queued piece of work. A permit is handed over by setting `granted`
/// under the queue lock, so a waiter that gives up under the same lock either
/// finds its permit or is no longer in line.
#[derive(Default)]
struct Waiter {
    granted: Mutex<bool>,
    woken: Notify,
    woken_blocking: Condvar,
}

/// One admitted piece of work. Dropping it hands the permit to the next
/// waiter, or returns it to the pool.
#[must_use = "work runs only as long as its permit is held"]
pub(crate) struct Permit {
    pool: Arc<dyn Release>,
}

trait Release: Send + Sync {
    fn release(&self);
}

impl<K: Eq + Hash + Clone + Send + 'static> Admission<K> {
    /// A pool of `bound` permits whose waits end at `wait`, crossing `row`.
    pub(crate) fn new(
        row: LimitRow,
        questions: Arc<LimitQuestions>,
        bound: usize,
        wait: Duration,
    ) -> Self {
        Self::build(Some((row, questions)), bound, wait)
    }

    /// One turn at a time: an exclusive resource's queue, which is not a
    /// threshold and asks no question when it is busy.
    pub(crate) fn exclusive(wait: Duration) -> Self {
        Self::build(None, 1, wait)
    }

    fn build(row: Option<(LimitRow, Arc<LimitQuestions>)>, bound: usize, wait: Duration) -> Self {
        Self {
            pool: Arc::new(Pool {
                queue: Mutex::new(Queue {
                    held: 0,
                    waiting: HashMap::new(),
                    turns: VecDeque::new(),
                    background: VecDeque::new(),
                    asked: false,
                }),
                bound: bound.max(1),
                wait,
                row,
            }),
        }
    }

    /// Whether no work holds a permit or waits for one.
    pub(crate) fn is_idle(&self) -> bool {
        let queue = lock(&self.pool.queue);
        queue.held == 0 && queue.waiters() == 0
    }

    /// How many pieces of work wait for a permit.
    pub(crate) fn waiting(&self) -> usize {
        lock(&self.pool.queue).waiters()
    }

    /// A permit for `key`'s work, now or at its turn.
    pub(crate) async fn admit(&self, key: K) -> Result<Permit, WaitTimedOut> {
        self.admit_in_line(key).await
    }

    /// [`Self::admit`], in line from this call on: the returned future only
    /// waits, so work spawned in order keeps its order, and waiting holds no
    /// thread.
    pub(crate) fn admit_in_line(
        &self,
        key: K,
    ) -> impl Future<Output = Result<Permit, WaitTimedOut>> + Send + 'static {
        let entry = self.enter(Some(key));
        let wait = self.pool.wait;
        async move {
            let mut place = match entry {
                Entry::Admitted(permit) => return Ok(permit),
                Entry::Queued(place) => place,
            };
            let waiter = Arc::clone(&place.waiter);
            let _ = tokio::time::timeout(wait, waiter.granted()).await;
            place.settle().ok_or(WaitTimedOut)
        }
    }

    /// A permit for the host's own work, given only when no caller waits.
    pub(crate) fn admit_background_blocking(&self) -> Result<Permit, WaitTimedOut> {
        self.wait_blocking(None)
    }

    /// A free permit for the host's own work, or `None` with nothing put in
    /// line: the work waits for a later look rather than for a turn.
    pub(crate) fn try_admit_background(&self) -> Option<Permit> {
        let mut queue = lock(&self.pool.queue);
        // A free permit means nobody waits, as in `enter`.
        if queue.held >= self.pool.bound {
            return None;
        }
        queue.held += 1;
        drop(queue);
        Some(self.permit())
    }

    fn wait_blocking(&self, key: Option<K>) -> Result<Permit, WaitTimedOut> {
        let mut place = match self.enter(key) {
            Entry::Admitted(permit) => return Ok(permit),
            Entry::Queued(place) => place,
        };
        let deadline = Instant::now() + self.pool.wait;
        let waiter = Arc::clone(&place.waiter);
        let mut granted = lock(&waiter.granted);
        while !*granted {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            granted = waiter
                .woken_blocking
                .wait_timeout(granted, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        drop(granted);
        place.settle().ok_or(WaitTimedOut)
    }

    /// Takes a free permit, or puts the work in line. `None` is the host's
    /// own work.
    fn enter(&self, key: Option<K>) -> Entry<K> {
        let mut queue = lock(&self.pool.queue);
        // Waiters exist only while every permit is held, so a free permit
        // means nobody is ahead.
        if queue.held < self.pool.bound {
            queue.held += 1;
            return Entry::Admitted(self.permit());
        }
        let waiter = Arc::new(Waiter::default());
        match &key {
            Some(key) => {
                let line = queue.waiting.entry(key.clone()).or_default();
                let first_in_line = line.is_empty();
                line.push_back(Arc::clone(&waiter));
                if first_in_line {
                    queue.turns.push_back(key.clone());
                }
            }
            None => queue.background.push_back(Arc::clone(&waiter)),
        }
        let first = !queue.asked;
        queue.asked = true;
        let observed = queue.held + queue.waiters();
        drop(queue);
        if first && let Some((row, questions)) = &self.pool.row {
            questions.ask(*row, self.pool.bound as u64, observed as u64);
        }
        Entry::Queued(Place {
            pool: Arc::clone(&self.pool),
            waiter,
            key,
            settled: false,
        })
    }

    fn permit(&self) -> Permit {
        Permit {
            pool: Arc::clone(&self.pool) as Arc<dyn Release>,
        }
    }
}

enum Entry<K: Eq + Hash + Clone + Send + 'static> {
    Admitted(Permit),
    Queued(Place<K>),
}

/// A place in line. Settling it (or dropping it, when the caller went away)
/// takes the permit if one was handed over, or leaves the line if not.
struct Place<K: Eq + Hash + Clone + Send + 'static> {
    pool: Arc<Pool<K>>,
    waiter: Arc<Waiter>,
    key: Option<K>,
    settled: bool,
}

impl<K: Eq + Hash + Clone + Send + 'static> Place<K> {
    fn settle(&mut self) -> Option<Permit> {
        if self.settled {
            return None;
        }
        self.settled = true;
        let mut queue = lock(&self.pool.queue);
        if *lock(&self.waiter.granted) {
            return Some(Permit {
                pool: Arc::clone(&self.pool) as Arc<dyn Release>,
            });
        }
        let waiter = &self.waiter;
        match &self.key {
            Some(key) => {
                if let Some(line) = queue.waiting.get_mut(key) {
                    line.retain(|queued| !Arc::ptr_eq(queued, waiter));
                    if line.is_empty() {
                        queue.waiting.remove(key);
                        queue.turns.retain(|turn| turn != key);
                    }
                }
            }
            None => queue
                .background
                .retain(|queued| !Arc::ptr_eq(queued, waiter)),
        }
        if queue.waiters() == 0 {
            queue.asked = false;
        }
        None
    }
}

impl<K: Eq + Hash + Clone + Send + 'static> Drop for Place<K> {
    fn drop(&mut self) {
        // A permit handed over to a caller who has gone goes straight on.
        drop(self.settle());
    }
}

impl<K: Eq + Hash + Clone> Queue<K> {
    fn waiters(&self) -> usize {
        self.waiting.values().map(VecDeque::len).sum::<usize>() + self.background.len()
    }

    /// The next waiter whose turn it is: the oldest of the next key in the
    /// round, then the host's own work.
    fn next(&mut self) -> Option<Arc<Waiter>> {
        if let Some(key) = self.turns.pop_front() {
            let line = self.waiting.get_mut(&key)?;
            let waiter = line.pop_front();
            if line.is_empty() {
                self.waiting.remove(&key);
            } else {
                self.turns.push_back(key);
            }
            return waiter;
        }
        self.background.pop_front()
    }
}

impl<K: Eq + Hash + Clone + Send + 'static> Release for Pool<K> {
    fn release(&self) {
        let mut queue = lock(&self.queue);
        match queue.next() {
            // The permit passes on as it is: `held` does not change. Once
            // nobody waits, the crossing is over; the next wait is a new one.
            Some(waiter) => {
                *lock(&waiter.granted) = true;
                waiter.woken.notify_one();
                waiter.woken_blocking.notify_all();
                if queue.waiters() == 0 {
                    queue.asked = false;
                }
            }
            None => {
                queue.held = queue.held.saturating_sub(1);
                queue.asked = false;
            }
        }
    }
}

impl Waiter {
    async fn granted(&self) {
        loop {
            let woken = self.woken.notified();
            if *lock(&self.granted) {
                return;
            }
            woken.await;
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.pool.release();
    }
}

/// Every lock here guards plain counts and lines changed in one step each,
/// so a holder that panicked left them whole: a poisoned lock is still true.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What crossing one `[limits]` row with a burst came to: how many callers
/// were turned away, and whether the row asked. Rule five holds at the row
/// when nobody was and it did.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Crossing {
    pub(crate) refused: usize,
    pub(crate) asked: bool,
}

#[cfg(test)]
mod tests;
