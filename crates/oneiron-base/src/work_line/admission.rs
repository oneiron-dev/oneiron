//! How work enters a line: making and setting a `WorkLine`, and each way a
//! piece of work takes a permit at once, waits in line for one, or leaves
//! the line without one.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use super::{
    LineCrossing, LineObserver, LinePermit, LineShortage, Place, Pool, Queue, Release,
    WaitTimedOut, Waiter, WorkLine, grant, lock,
};

struct BlockingWaitWake(std::thread::Thread);

impl std::task::Wake for BlockingWaitWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
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

    /// The same background line and wait, also ending when `cancel` completes.
    /// Both notifications wake this blocking thread; no runtime is needed.
    /// A permit handed over while the wait ends is settled normally.
    pub fn admit_background_blocking_for_cancel(
        &self,
        wait: Duration,
        cancel: impl Future<Output = ()>,
    ) -> Result<LinePermit, WaitTimedOut> {
        let waker = std::task::Waker::from(Arc::new(BlockingWaitWake(std::thread::current())));
        let mut context = std::task::Context::from_waker(&waker);
        let mut cancel = std::pin::pin!(cancel);
        if cancel.as_mut().poll(&mut context).is_ready() {
            return Err(WaitTimedOut);
        }
        let mut place = match self.enter(None) {
            Entry::Admitted(permit) => return Ok(permit),
            Entry::Queued(place) => place,
        };
        let deadline = Instant::now() + wait;
        let waiter = Arc::clone(&place.waiter);
        let mut granted = std::pin::pin!(waiter.granted());
        loop {
            if granted.as_mut().poll(&mut context).is_ready()
                || cancel.as_mut().poll(&mut context).is_ready()
            {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::park_timeout(left);
        }
        place.settle().ok_or(WaitTimedOut)
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

/// `permit`, unless `deadline` passed by the time it came: then it goes on
/// to the next waiter, and the work it was for never starts.
fn before(deadline: Instant, permit: LinePermit) -> Result<LinePermit, WaitTimedOut> {
    if Instant::now() < deadline {
        Ok(permit)
    } else {
        Err(WaitTimedOut)
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
