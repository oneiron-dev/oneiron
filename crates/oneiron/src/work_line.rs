//! A fair line for work that waits its turn: the vault's task-work line, and
//! each bound a host holds over work a remote caller can start.
//!
//! The rule every such piece of work follows: it takes a permit before it
//! begins, and the permit travels with the work itself (the connection, the
//! child process, the upload spool, the worker thread), never only with the
//! handler that started it. A caller who hangs up therefore frees nothing the
//! work still holds.
//!
//! Past the bound, work waits; it is never refused for count (the owner's
//! rate law, ARCH-0044 C5). Waiters are served round-robin across keys (a
//! principal, a credential) and in arrival order within one key, so a fleet
//! that shares one credential takes one turn in each round, as every other
//! credential does, and no key needs a cap of its own. Each wait has a
//! deadline, sized as a request timeout rather than as a limit. The host's
//! own background work waits behind every caller.
//!
//! When work has to wait and nobody waited before it, the line is crossed:
//! its [`LineCrossing`] hears it once per crossing (a host's OF-520 "is
//! everything okay" question).
//!
//! Task work (`can`, `ask`, `wait`, `tasks.answer`; Rule 5) takes its turn
//! from one line per vault ([`Vault::admit_task_work`]), whichever door it
//! came in by: a served route, the embedded SDK, a code run's own ask and
//! wait, or a pumped agent.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::{EntityId, Vault};

/// Where a line says it was crossed: work had to wait, and nobody waited
/// before it. Called outside the line's lock; it must not wait on the work.
pub trait LineCrossing: Send + Sync {
    /// `observed` pieces of work hold or wait for the line's `bound` permits.
    fn crossed(&self, bound: u64, observed: u64);
}

/// A wait that reached its deadline before a permit came free. Nothing was
/// started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitTimedOut;

/// A bound over one kind of work, and the line of work waiting for it.
pub struct WorkLine<K> {
    pool: Arc<Pool<K>>,
}

/// A clone shares the pool: one bound, one line.
impl<K> Clone for WorkLine<K> {
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
        }
    }
}

struct Pool<K> {
    queue: Mutex<Queue<K>>,
    bound: AtomicUsize,
    wait: Mutex<Duration>,
    /// Where the line's crossing is said; `None` for a turn that is
    /// exclusive by nature rather than a threshold.
    crossing: RwLock<Option<Arc<dyn LineCrossing>>>,
}

struct Queue<K> {
    held: usize,
    /// Each key's waiters, oldest first.
    waiting: HashMap<K, VecDeque<Arc<Waiter>>>,
    /// The keys with a waiter, in the order their turns come.
    turns: VecDeque<K>,
    /// The host's own work, served only when no caller waits.
    background: VecDeque<Arc<Waiter>>,
    /// Whether the crossing in progress was said.
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
pub struct LinePermit {
    pool: Arc<dyn Release>,
}

trait Release: Send + Sync {
    fn release(&self);
}

impl<K: Eq + Hash + Clone + Send + 'static> WorkLine<K> {
    /// A line of `bound` permits whose waits end at `wait`, its crossings
    /// said to `crossing`.
    pub fn new(crossing: Option<Arc<dyn LineCrossing>>, bound: usize, wait: Duration) -> Self {
        Self {
            pool: Arc::new(Pool {
                queue: Mutex::new(Queue {
                    held: 0,
                    waiting: HashMap::new(),
                    turns: VecDeque::new(),
                    background: VecDeque::new(),
                    asked: false,
                }),
                bound: AtomicUsize::new(bound.max(1)),
                wait: Mutex::new(wait),
                crossing: RwLock::new(crossing),
            }),
        }
    }

    /// One turn at a time: an exclusive resource's line, which is not a
    /// threshold and says no crossing when it is busy.
    pub fn exclusive(wait: Duration) -> Self {
        Self::new(None, 1, wait)
    }

    /// Sets the bound, the wait and where crossings are said, on the same
    /// line: work in line keeps its place. A raised bound lets waiters in at
    /// once; a lowered one takes hold as held work ends.
    pub fn configure(&self, bound: usize, wait: Duration, crossing: Option<Arc<dyn LineCrossing>>) {
        *lock(&self.pool.wait) = wait;
        *self
            .pool
            .crossing
            .write()
            .unwrap_or_else(PoisonError::into_inner) = crossing;
        let bound = bound.max(1);
        let mut queue = lock(&self.pool.queue);
        self.pool.bound.store(bound, Ordering::Relaxed);
        while queue.held < bound {
            let Some(waiter) = queue.next() else {
                break;
            };
            queue.held += 1;
            grant(&waiter);
        }
        if queue.waiters() == 0 {
            queue.asked = false;
        }
    }

    /// Whether no work holds a permit or waits for one.
    pub fn is_idle(&self) -> bool {
        let queue = lock(&self.pool.queue);
        queue.held == 0 && queue.waiters() == 0
    }

    /// How many pieces of work wait for a permit.
    pub fn waiting(&self) -> usize {
        lock(&self.pool.queue).waiters()
    }

    /// A permit for `key`'s work, now or at its turn.
    pub async fn admit(&self, key: K) -> Result<LinePermit, WaitTimedOut> {
        self.admit_in_line(key).await
    }

    /// [`Self::admit`], in line from this call on: the returned future only
    /// waits, so work spawned in order keeps its order, and waiting holds no
    /// thread.
    pub fn admit_in_line(
        &self,
        key: K,
    ) -> impl Future<Output = Result<LinePermit, WaitTimedOut>> + Send + 'static {
        let entry = self.enter(Some(key));
        let wait = *lock(&self.pool.wait);
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

    /// [`Self::admit`] on this thread, for work that runs on its own thread
    /// rather than on a runtime.
    pub fn admit_blocking(&self, key: K) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking(Some(key))
    }

    /// A permit for the host's own work, given only when no caller waits.
    pub fn admit_background_blocking(&self) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking(None)
    }

    /// A free permit for the host's own work, or `None` with nothing put in
    /// line: the work waits for a later look rather than for a turn.
    pub fn try_admit_background(&self) -> Option<LinePermit> {
        let mut queue = lock(&self.pool.queue);
        // A free permit means nobody waits, as in `enter`.
        if queue.held >= self.pool.bound.load(Ordering::Relaxed) {
            return None;
        }
        queue.held += 1;
        drop(queue);
        Some(self.permit())
    }

    fn wait_blocking(&self, key: Option<K>) -> Result<LinePermit, WaitTimedOut> {
        let mut place = match self.enter(key) {
            Entry::Admitted(permit) => return Ok(permit),
            Entry::Queued(place) => place,
        };
        let deadline = Instant::now() + *lock(&self.pool.wait);
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
        let bound = self.pool.bound.load(Ordering::Relaxed);
        // Waiters exist only while every permit is held, so a free permit
        // means nobody is ahead.
        if queue.held < bound {
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
        if first {
            let crossing = self
                .pool
                .crossing
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(crossing) = crossing {
                crossing.crossed(bound as u64, observed as u64);
            }
        }
        Entry::Queued(Place {
            pool: Arc::clone(&self.pool),
            waiter,
            key,
            settled: false,
        })
    }

    fn permit(&self) -> LinePermit {
        LinePermit {
            pool: Arc::clone(&self.pool) as Arc<dyn Release>,
        }
    }
}

enum Entry<K: Eq + Hash + Clone + Send + 'static> {
    Admitted(LinePermit),
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
    fn settle(&mut self) -> Option<LinePermit> {
        if self.settled {
            return None;
        }
        self.settled = true;
        let mut queue = lock(&self.pool.queue);
        if *lock(&self.waiter.granted) {
            return Some(LinePermit {
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
        // Over a lowered bound, the permit goes back rather than on.
        if queue.held > self.bound.load(Ordering::Relaxed) {
            queue.held -= 1;
            return;
        }
        match queue.next() {
            // The permit passes on as it is: `held` does not change. Once
            // nobody waits, the crossing is over; the next wait is a new one.
            Some(waiter) => {
                grant(&waiter);
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

/// Hands `waiter` its permit, under the queue lock.
fn grant(waiter: &Waiter) {
    *lock(&waiter.granted) = true;
    waiter.woken.notify_one();
    waiter.woken_blocking.notify_all();
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

impl Drop for LinePermit {
    fn drop(&mut self) {
        self.pool.release();
    }
}

/// Every lock here guards plain counts and lines changed in one step each,
/// so a holder that panicked left them whole: a poisoned lock is still true.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Task work a vault runs at once before more waits its turn, until a host
/// sets its own (`limits.task_work`): past ten times a fleet's 200 agents.
pub const TASK_WORK_BOUND: usize = 2_048;

/// How long task work waits for its turn before it runs anyway, until a host
/// sets its own (`limits.queue_wait_timeout_ms`).
pub const TASK_WORK_WAIT: Duration = Duration::from_secs(300);

/// One piece of task work's turn on a vault ([`Vault::admit_task_work`]):
/// dropping it hands the turn to the next caller in line. Work that waited
/// out its turn holds none.
#[must_use = "task work keeps its turn only while it is held"]
pub struct TaskWorkTurn {
    _permit: Option<LinePermit>,
}

impl TaskWorkTurn {
    fn after(caller: EntityId, admitted: Result<LinePermit, WaitTimedOut>) -> Self {
        match admitted {
            Ok(permit) => Self {
                _permit: Some(permit),
            },
            Err(WaitTimedOut) => {
                tracing::info!(
                    caller = %caller.to_hex(),
                    "task work waited out its turn; it runs past the task-work bound"
                );
                Self { _permit: None }
            }
        }
    }
}

impl Vault {
    /// Sets this vault's task-work line: `bound` pieces at once, waits that
    /// end at `wait`, its crossings said to `crossing`. A host sets it once
    /// it holds the vault; the line and the work in it stay.
    pub fn set_task_work(
        &self,
        bound: usize,
        wait: Duration,
        crossing: Option<Arc<dyn LineCrossing>>,
    ) {
        self.task_work.configure(bound, wait, crossing);
    }

    /// `caller`'s turn to run one piece of task work on this vault (`can`,
    /// `ask`, `wait`, `tasks.answer`; Rule 5): at once while fewer than the
    /// bound run, else in a fair line, one caller's work after another's,
    /// each caller's oldest first. Work is never refused: past the wait it
    /// runs without a turn. Hold the turn until the work ends; take it
    /// before the engine opens a transaction, and only where no turn is held
    /// for the same work already.
    pub fn admit_task_work(
        &self,
        caller: EntityId,
    ) -> impl Future<Output = TaskWorkTurn> + Send + 'static {
        let admitted = self.task_work.admit_in_line(caller);
        async move { TaskWorkTurn::after(caller, admitted.await) }
    }

    /// [`Self::admit_task_work`] on this thread: for the embedded SDK, a
    /// code run's own calls and other work off the runtime.
    pub fn admit_task_work_blocking(&self, caller: EntityId) -> TaskWorkTurn {
        TaskWorkTurn::after(caller, self.task_work.admit_blocking(caller))
    }
}
