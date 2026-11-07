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
//! deadline, sized as a request timeout rather than as a limit; task work's
//! is its own request's deadline, and without one it waits for its turn
//! however long the line. The host's own background work waits behind every
//! caller.
//!
//! When work has to wait and nobody waited before it, the line is crossed:
//! its [`LineCrossing`] hears it once per crossing (a host's OF-520 "is
//! everything okay" question), and again when the last waiter leaves. A
//! bundle of the host's own work that finds too little room crosses the line
//! as a waiter does, and its crossing lasts until room for it comes back
//! ([`WorkLine::try_admit_background_bundle`], FIX 6304).
//!
//! Task work (`can`, `ask`, `wait`, `tasks.answer`; Rule 5) takes its turn
//! from one line per vault ([`Vault::admit_task_work`]), whichever door it
//! came in by: a served route, the embedded SDK, a code run's own ask and
//! wait, or a pumped agent. It never runs without its turn (FIX 10015).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Where a line says it was crossed: work had to wait, and nobody waited
/// before it. Called outside the line's lock; it must not wait on the work.
pub trait LineCrossing: Send + Sync {
    /// Crossing `epoch` ([`WorkLine::crossing_epoch`]) began: `observed`
    /// pieces of work hold, wait for or asked for the line's `bound` permits.
    fn crossed(&self, epoch: u64, bound: u64, observed: u64);

    /// The crossing `epoch` names ([`WorkLine::crossing_epoch`]) is over:
    /// its last waiter left the line, given its permit, gone or out of time.
    fn drained(&self, epoch: u64) {
        let _ = epoch;
    }
}

/// Observation of one caller's place in an existing line. It grants no
/// permit and never changes the line's bound, order or deadline. Called
/// outside the line's lock, before waiting and after the permit arrives.
pub trait LineObserver: Send + Sync {
    fn queued(&self);
    fn held(&self);
}

/// A wait that reached its deadline before a permit came free. Nothing was
/// started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitTimedOut;

/// A bundle of the host's own work that found too little room: `free`
/// permits were free when it asked. Nothing was taken or put in line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineShortage {
    pub free: usize,
}

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
    /// The largest bundle of the host's own work that found too little room
    /// since room for it last came back: while one is unmet, the crossing it
    /// began stays open, so trying again is not crossing again.
    unmet: usize,
    /// Which crossing is the latest: each new one counts the next.
    epoch: u64,
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
                    unmet: 0,
                    epoch: 0,
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
        queue.room_returned(bound);
        let drained = queue.end_settled_crossing();
        drop(queue);
        self.pool.say_drained(drained);
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

    /// The crossing in progress while work waits in line or a bundle's
    /// shortage is unmet: its epoch, which every later crossing's is greater
    /// than. `None` while neither is.
    pub fn crossing_epoch(&self) -> Option<u64> {
        let queue = lock(&self.pool.queue);
        queue.asked.then_some(queue.epoch)
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
        self.admit_in_line_observed(key, None)
    }

    /// The same permit and fair line as [`Self::admit_in_line`], with an
    /// observation of this caller's queued/held transition.
    pub fn admit_in_line_observed(
        &self,
        key: K,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> impl Future<Output = Result<LinePermit, WaitTimedOut>> + Send + 'static {
        let entry = self.enter(Some(key));
        if let Some(observer) = &observer {
            match &entry {
                Entry::Admitted(_) => observer.held(),
                Entry::Queued(_) => observer.queued(),
            }
        }
        let wait = *lock(&self.pool.wait);
        async move {
            let mut place = match entry {
                Entry::Admitted(permit) => return Ok(permit),
                Entry::Queued(place) => place,
            };
            let waiter = Arc::clone(&place.waiter);
            let _ = tokio::time::timeout(wait, waiter.granted()).await;
            let permit = place.settle().ok_or(WaitTimedOut)?;
            if let Some(observer) = observer {
                observer.held();
            }
            Ok(permit)
        }
    }

    /// [`Self::admit_in_line`] whose wait ends at `wait` rather than at the
    /// line's own (FIX 9110): the same line, order and permit as
    /// [`Self::admit_blocking_for`], awaited instead of holding a thread. The
    /// line's own wait is left as it is for every other caller.
    pub fn admit_in_line_for(
        &self,
        key: K,
        wait: Duration,
    ) -> impl Future<Output = Result<LinePermit, WaitTimedOut>> + Send + 'static {
        let entry = self.enter(Some(key));
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
        self.wait_blocking(Some(key), None)
    }

    /// [`Self::admit_blocking`] whose wait ends at `wait` rather than at the
    /// line's own: the same line, order and permit, for work that keeps a
    /// wait of its own (a caller's shorter deadline among them).
    pub fn admit_blocking_for(&self, key: K, wait: Duration) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking(Some(key), Some(wait))
    }

    /// [`Self::admit_blocking`] with the observation
    /// [`Self::admit_in_line_observed`] makes, on this thread: this caller's
    /// queued/held transition, said to the serving call's receipt when it
    /// has one (FIX 21154).
    pub fn admit_blocking_observed(
        &self,
        key: K,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking_observed(key, None, observer)
    }

    /// [`Self::admit_blocking_for`] with the same observation.
    pub fn admit_blocking_for_observed(
        &self,
        key: K,
        wait: Duration,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking_observed(key, Some(wait), observer)
    }

    /// [`Self::admit_blocking_untimed`] with the same observation.
    pub fn admit_blocking_untimed_observed(
        &self,
        key: K,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> LinePermit {
        let entry = self.enter(Some(key));
        observe_entry(observer.as_deref(), &entry);
        let mut place = match entry {
            Entry::Admitted(permit) => return permit,
            Entry::Queued(place) => place,
        };
        place.wait_granted(None);
        let permit = place
            .settle()
            .expect("a place whose permit was handed over settles with it");
        if let Some(observer) = observer {
            observer.held();
        }
        permit
    }

    /// A caller's blocking wait at its place, observed as an awaited one is:
    /// queued or held as it enters, held once its permit comes.
    fn wait_blocking_observed(
        &self,
        key: K,
        wait: Option<Duration>,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> Result<LinePermit, WaitTimedOut> {
        let entry = self.enter(Some(key));
        observe_entry(observer.as_deref(), &entry);
        let mut place = match entry {
            Entry::Admitted(permit) => return Ok(permit),
            Entry::Queued(place) => place,
        };
        let deadline = Instant::now() + wait.unwrap_or_else(|| *lock(&self.pool.wait));
        place.wait_granted(Some(deadline));
        let permit = place.settle().ok_or(WaitTimedOut)?;
        if let Some(observer) = observer {
            observer.held();
        }
        Ok(permit)
    }

    /// A permit for the host's own work, given only when no caller waits.
    pub fn admit_background_blocking(&self) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking(None, None)
    }

    /// [`Self::admit_background_blocking`] whose wait ends at `wait`: the
    /// host's own work with a deadline of its own, still served last.
    pub fn admit_background_blocking_for(
        &self,
        wait: Duration,
    ) -> Result<LinePermit, WaitTimedOut> {
        self.wait_blocking(None, Some(wait))
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

    /// `permits` free permits at once for the host's own work, all or none,
    /// with nothing put in line (FIX 6304): a caller in line keeps every
    /// permit that comes free before it. A bundle that finds too little room
    /// crosses the line, said once as a first waiter's crossing is, and the
    /// crossing stays open until room for the bundle comes back, so a bundle
    /// tried again meanwhile is not a new crossing.
    ///
    /// # Errors
    /// Returns the [`LineShortage`] when fewer than `permits` are free.
    pub fn try_admit_background_bundle(
        &self,
        permits: usize,
    ) -> Result<Vec<LinePermit>, LineShortage> {
        let mut queue = lock(&self.pool.queue);
        let bound = self.pool.bound.load(Ordering::Relaxed);
        // A free permit means nobody waits, as in `enter`.
        let free = bound.saturating_sub(queue.held);
        if permits <= free {
            queue.held += permits;
            drop(queue);
            return Ok((0..permits).map(|_| self.permit()).collect());
        }
        queue.unmet = queue.unmet.max(permits);
        let crossing = queue.begin_crossing(permits);
        drop(queue);
        self.pool.say_crossed(crossing, bound);
        Err(LineShortage { free })
    }

    fn wait_blocking(
        &self,
        key: Option<K>,
        wait: Option<Duration>,
    ) -> Result<LinePermit, WaitTimedOut> {
        let mut place = match self.enter(key) {
            Entry::Admitted(permit) => return Ok(permit),
            Entry::Queued(place) => place,
        };
        let deadline = Instant::now() + wait.unwrap_or_else(|| *lock(&self.pool.wait));
        place.wait_granted(Some(deadline));
        place.settle().ok_or(WaitTimedOut)
    }

    /// A permit for `key`'s work at its turn, however long the line: the
    /// line's own wait never ends it. The same line, order and permit as
    /// [`Self::admit_in_line_observed`], and the same observation.
    pub fn admit_in_line_untimed(
        &self,
        key: K,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> impl Future<Output = LinePermit> + Send + 'static {
        let entry = self.enter(Some(key));
        if let Some(observer) = &observer {
            match &entry {
                Entry::Admitted(_) => observer.held(),
                Entry::Queued(_) => observer.queued(),
            }
        }
        async move {
            let mut place = match entry {
                Entry::Admitted(permit) => return permit,
                Entry::Queued(place) => place,
            };
            let waiter = Arc::clone(&place.waiter);
            waiter.granted().await;
            let permit = place
                .settle()
                .expect("a place whose permit was handed over settles with it");
            if let Some(observer) = observer {
                observer.held();
            }
            permit
        }
    }

    /// [`Self::admit_in_line_untimed`] until `deadline`: past it with no
    /// permit, the work leaves the line, and nothing was started. A deadline
    /// already past puts nothing in line, and a permit that comes at or past
    /// it goes on to the next waiter. Held is observed only with the permit
    /// the work keeps.
    pub fn admit_in_line_until(
        &self,
        key: K,
        deadline: Instant,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> impl Future<Output = Result<LinePermit, WaitTimedOut>> + Send + 'static {
        let entry = (Instant::now() < deadline).then(|| self.enter(Some(key)));
        if let (Some(observer), Some(Entry::Queued(_))) = (&observer, &entry) {
            observer.queued();
        }
        async move {
            let permit = match entry.ok_or(WaitTimedOut)? {
                Entry::Admitted(permit) => permit,
                Entry::Queued(mut place) => {
                    let waiter = Arc::clone(&place.waiter);
                    let until = tokio::time::Instant::from_std(deadline);
                    let _ = tokio::time::timeout_at(until, waiter.granted()).await;
                    place.settle().ok_or(WaitTimedOut)?
                }
            };
            let permit = before(deadline, permit)?;
            if let Some(observer) = observer {
                observer.held();
            }
            Ok(permit)
        }
    }

    /// [`Self::admit_in_line_untimed`] on this thread.
    pub fn admit_blocking_untimed(&self, key: K) -> LinePermit {
        let mut place = match self.enter(Some(key)) {
            Entry::Admitted(permit) => return permit,
            Entry::Queued(place) => place,
        };
        place.wait_granted(None);
        place
            .settle()
            .expect("a place whose permit was handed over settles with it")
    }

    /// [`Self::admit_in_line_until`] on this thread.
    pub fn admit_blocking_until(
        &self,
        key: K,
        deadline: Instant,
    ) -> Result<LinePermit, WaitTimedOut> {
        if Instant::now() >= deadline {
            return Err(WaitTimedOut);
        }
        let permit = match self.enter(Some(key)) {
            Entry::Admitted(permit) => permit,
            Entry::Queued(mut place) => {
                place.wait_granted(Some(deadline));
                place.settle().ok_or(WaitTimedOut)?
            }
        };
        before(deadline, permit)
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
        let crossing = queue.begin_crossing(0);
        drop(queue);
        self.pool.say_crossed(crossing, bound);
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
    /// Waits on this thread until the permit is handed over, or until
    /// `deadline` when there is one.
    fn wait_granted(&self, deadline: Option<Instant>) {
        let mut granted = lock(&self.waiter.granted);
        while !*granted {
            granted = match deadline {
                None => self
                    .waiter
                    .woken_blocking
                    .wait(granted)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    self.waiter
                        .woken_blocking
                        .wait_timeout(granted, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }

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
        let drained = queue.end_settled_crossing();
        drop(queue);
        self.pool.say_drained(drained);
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

    /// Begins a crossing unless one is in progress: its epoch and the work
    /// that holds, waits for or asks for the line with `asking` more, for the
    /// line's crossing to hear once the lock is let go. `None` when one is.
    fn begin_crossing(&mut self, asking: usize) -> Option<(u64, usize)> {
        if std::mem::replace(&mut self.asked, true) {
            return None;
        }
        self.epoch += 1;
        Some((self.epoch, self.held + self.waiters() + asking))
    }

    /// Ends the crossing in progress once nobody waits and no bundle's
    /// shortage is unmet: its epoch, if it was said, for the line's crossing
    /// to hear once the lock is let go.
    fn end_settled_crossing(&mut self) -> Option<u64> {
        if self.waiters() > 0 || self.unmet > 0 {
            return None;
        }
        std::mem::take(&mut self.asked).then_some(self.epoch)
    }

    /// Clears an unmet bundle's shortage once room for it is free again
    /// under `bound`, or the whole line is, for one larger than the line.
    fn room_returned(&mut self, bound: usize) {
        if bound.saturating_sub(self.held) >= self.unmet.min(bound) {
            self.unmet = 0;
        }
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

impl<K> Pool<K> {
    /// Tells the line's crossing that crossing `begun` (its epoch and the
    /// work it observed) began on a line of `bound`, if one did. Called
    /// outside the queue's lock.
    fn say_crossed(&self, begun: Option<(u64, usize)>, bound: usize) {
        if let Some((epoch, observed)) = begun
            && let Some(crossing) = self.crossing()
        {
            crossing.crossed(epoch, bound as u64, observed as u64);
        }
    }

    /// Tells the line's crossing that crossing `epoch` is over, if one
    /// ended. Called outside the queue's lock.
    fn say_drained(&self, epoch: Option<u64>) {
        if let Some(epoch) = epoch
            && let Some(crossing) = self.crossing()
        {
            crossing.drained(epoch);
        }
    }

    fn crossing(&self) -> Option<Arc<dyn LineCrossing>> {
        self.crossing
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl<K: Eq + Hash + Clone + Send + 'static> Release for Pool<K> {
    fn release(&self) {
        let mut queue = lock(&self.queue);
        let bound = self.bound.load(Ordering::Relaxed);
        // Over a lowered bound, the permit goes back rather than on.
        if queue.held > bound {
            queue.held -= 1;
            return;
        }
        // The permit passes on as it is: `held` does not change. Once nobody
        // waits and no bundle's shortage is unmet, the crossing is over; the
        // next wait is a new one.
        match queue.next() {
            Some(waiter) => grant(&waiter),
            None => {
                queue.held = queue.held.saturating_sub(1);
                queue.room_returned(bound);
            }
        }
        let drained = queue.end_settled_crossing();
        drop(queue);
        self.say_drained(drained);
    }
}

/// `permit`, unless `deadline` passed by the time it came: then it goes on
/// to the next waiter, and the work it was for never starts.
fn before(deadline: Instant, permit: LinePermit) -> Result<LinePermit, WaitTimedOut> {
    if Instant::now() < deadline {
        Ok(permit)
    } else {
        Err(WaitTimedOut)
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

/// Says `entry` to `observer`: held when it took a permit at once, queued
/// when it waits for one.
fn observe_entry<K: Eq + Hash + Clone + Send + 'static>(
    observer: Option<&dyn LineObserver>,
    entry: &Entry<K>,
) {
    if let Some(observer) = observer {
        match entry {
            Entry::Admitted(_) => observer.held(),
            Entry::Queued(_) => observer.queued(),
        }
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

/// The task-work line's own wait, until a host sets its own
/// (`limits.queue_wait_timeout_ms`): how long other work in that line that
/// names no wait of its own (a recovery's pages) waits for its turn, and
/// the wait other lines start with. Task work itself waits for its turn
/// however long the line, or until its own request deadline (FIX 10015).
pub const TASK_WORK_WAIT: Duration = Duration::from_secs(300);

/// One piece of task work's turn on a vault ([`Vault::admit_task_work`]):
/// dropping it hands the turn to the next caller in line. Task work runs
/// only while it holds its turn.
#[must_use = "task work keeps its turn only while it is held"]
pub struct TaskWorkTurn {
    pub _permit: LinePermit,
}
