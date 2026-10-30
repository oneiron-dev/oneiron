//! Group commit at the vault's single LMDB writer (ARCH-0019 storage
//! invariant, OF-536).
//!
//! Concurrent logical writes share one write transaction and one fsync. The
//! first caller to arrive opens the transaction and leads the group; callers
//! that arrive while it is open join it. Each member runs its own closure on
//! its own thread, one at a time and in arrival order, inside a nested
//! transaction of the shared one, so a member that fails discards only its own
//! rows and its thread-local state is the one it always had. The leader commits
//! once and only then settles the members: no caller hears "committed" before
//! the shared transaction is durable.
//!
//! A group takes the writes already queued, in order, until it carries its
//! size bound or meets a write that closes it (below). When its queue runs
//! empty it waits only while a write is announced as on its way, and only
//! until its window, counted from when the group opened, has passed. With
//! nothing announced it closes at once, so a lone writer never waits. The
//! window bounds that idle wait, not how long a group stays open: a group
//! whose queue never empties runs past its window until its size bound. Both
//! bounds are learned-setting rows ([`GROUP_COMMIT_WINDOW_MS`],
//! [`GROUP_COMMIT_MAX_WRITES`]) that the leader reads in the transaction it
//! opens.
//!
//! A member's answer, and whatever its calling thread holds, stay alive until
//! the group commits, so no member may wait on another's. Only engine writes
//! audited to hold nothing across the commit ([`Callback::Audited`]) share a
//! group freely. A caller's opaque callback ([`Callback::Opaque`]) runs as a
//! group of its own, as every write did before group commit: it joins no open
//! group, so it never waits on what an earlier member's caller holds, and its
//! group closes after it, so no later write waits on what its result carries.
//! A write that leaves a session-overlay segment installed also closes its
//! group: it holds that segment's permit until it commits the segment after
//! the base commit.
//!
//! A deferred-commit write (Engine ruling 10-30 23:09) is the one caller that
//! hears its answer before that: it answers once its rows are staged in the
//! group's open transaction, after every check its closure makes, and does
//! not wait for the shared commit and its data sync. Its rows keep their
//! place in arrival order, and the group's leader commits them after the
//! answer: a writer already leading, or, when the write would lead itself,
//! the store's own deferred-commit leader, a thread that opens the group for
//! it with the bounds the write read for it in a snapshot. A crash before
//! that commit loses the rows of a write whose answer already went out; the
//! store's drop waits for it. A reader that must see those rows waits until
//! the commits of the writes already answered are decided
//! ([`Store::wait_for_deferred_commits`]).
//!
//! A detached write (FIX 12023) waits for less still: it takes its place in
//! the same arrival order and returns at once, before the writer is taken, and
//! the group's leader runs its closure on its own thread when its turn comes
//! ([`detached`]).
//!
//! This is the store's existing single writer taking many rows per commit. It
//! is not a lock: correctness is still LMDB's one write transaction, and a
//! writer that opens `env.write_txn()` itself waits for the group like any
//! other writer. It is not a queue outside the store, and not a coordinator:
//! the next waiting member leads the next group itself, but for a
//! deferred-commit write, whose group the store's own leader opens.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::error::Error;
use crate::learning_setting::{
    GROUP_COMMIT_MAX_WRITES, GROUP_COMMIT_WINDOW_MS, SettingSpec, setting_value_in_txn,
};

use super::legal_hold::RefusalBatch;
use super::{Store, StoreCore, active_write_txn_depth};

mod detached;

pub(crate) use detached::{AfterCommit, DetachedWrite};
use detached::{DetachedGroup, DetachedWrites};

/// Whose closure a write runs, which decides whether its group may go on
/// after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Callback {
    /// Engine code audited to hold nothing across the shared commit: neither
    /// its answer nor its caller keeps a lock or permit that another write's
    /// closure takes. The group goes on after it.
    Audited,
    /// A caller's callback the engine cannot see into. Its answer and its
    /// caller may hold what another member waits for, and its closure may wait
    /// for what another member's caller holds, so it runs as a group of its
    /// own.
    Opaque,
}

/// What a member's closure does with the rows it staged.
pub(crate) enum Rows<T, E> {
    /// Keep the rows; answer `T` once the group is durable.
    Commit(T),
    /// Keep the rows (a refusal's own receipt); answer `E` once the group is
    /// durable.
    Refuse(E),
    /// Drop the rows: nothing of this write joins the group. The answer still
    /// waits for the group's commit, and a success becomes the commit's error
    /// if it fails, because it may rest on rows an earlier member staged.
    Discard(std::result::Result<T, E>),
}

/// When a member's answer comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnswerAt {
    /// Once the shared transaction is durable: every write but a
    /// deferred-commit one.
    Commit,
    /// Once its rows are staged in the open group: a deferred-commit write
    /// (Engine ruling 10-30 23:09).
    Stage,
}

/// This vault's group-commit counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GroupCommitStats {
    /// Shared write transactions committed.
    pub groups: u64,
    /// Logical writes whose rows those transactions carried.
    pub writes: u64,
    /// The most logical writes one transaction carried.
    pub largest_group: u64,
}

/// The counters behind [`GroupCommitStats`], recorded by the leader after each
/// commit.
#[derive(Default)]
pub(crate) struct GroupCommitCounters {
    groups: AtomicU64,
    writes: AtomicU64,
    largest_group: AtomicU64,
}

impl GroupCommitCounters {
    fn record(&self, writes: u64) {
        self.groups.fetch_add(1, Ordering::Relaxed);
        self.writes.fetch_add(writes, Ordering::Relaxed);
        self.largest_group.fetch_max(writes, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> GroupCommitStats {
        GroupCommitStats {
            groups: self.groups.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            largest_group: self.largest_group.load(Ordering::Relaxed),
        }
    }
}

/// The waiting room of one vault's writer.
#[derive(Default)]
pub(crate) struct GroupCommit {
    waiting: Mutex<Waiting>,
    /// Wakes a leader holding its group open for an announced write.
    arrival: Condvar,
    /// Writes announced as on their way and not yet queued.
    announced: AtomicUsize,
    /// Leads the group of a deferred-commit write that holds the writer.
    deferred_leader: DeferredCommitLeader,
    /// The deferred-commit writes answered, and how many of them settled.
    deferred: DeferredCommits,
    /// The detached writes queued, and how many of them settled (FIX 12023).
    detached: DetachedWrites,
    #[cfg(test)]
    pub(crate) hooks: hooks::GroupCommitHooks,
}

#[derive(Default)]
struct Waiting {
    /// A group is open or committing; arrivals queue behind it.
    leading: bool,
    queue: VecDeque<Arrival>,
    /// How many of `queue` are detached writes (FIX 12023).
    detached: usize,
}

/// One arrival at the writer, in the one arrival order every write keeps
/// (FIX 12023): a write whose thread waits for its turn, or a detached write
/// whose closure the leader runs on its own thread.
enum Arrival {
    Write(Arc<Ticket>),
    Detached(DetachedWrite),
}

impl Waiting {
    /// The first arrival, taken out of the queue.
    fn take_front(&mut self) -> Option<Arrival> {
        let front = self.queue.pop_front();
        if matches!(front, Some(Arrival::Detached(_))) {
            self.detached -= 1;
        }
        front
    }
}

/// The store's own leader for deferred-commit writes (Engine ruling 10-30
/// 23:09): a thread, started by the first such write that holds the writer
/// (it found it idle, or a group handed it on), that opens a group for that
/// write, runs the writes queued there as any leader does, commits once and
/// passes the writer on. It also leads the group of a detached write that
/// finds the writer idle, or heads the queue when a group hands the writer on
/// (FIX 12023). It holds the store's core, never a store view, and the store's
/// drop ends it after the group it leads
/// ([`GroupCommit::stop_deferred_commit_leader`]).
#[derive(Default)]
struct DeferredCommitLeader {
    requests: Mutex<LeaderRequests>,
    requested: Condvar,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct LeaderRequests {
    /// The group a deferred-commit write took the writer for, with the limits
    /// read for it. One at a time: the writer is taken again only once that
    /// group has passed it on.
    pending: Option<Limits>,
    /// The store is dropping: lead what was asked for, then end.
    stopping: bool,
}

impl DeferredCommitLeader {
    /// Asks the leader thread to lead the group a deferred-commit write just
    /// took the writer for, starting the thread on first use. False when it
    /// cannot start: that write leads its group itself.
    ///
    /// A dropping store starts none: the thread it stops leads what is asked
    /// next, since its own last group may pass the writer back to it for the
    /// detached writes queued behind (FIX 12023).
    fn request(&self, core: &Arc<StoreCore>, limits: Limits) -> bool {
        {
            let mut thread = self.thread.lock().unwrap_or_else(PoisonError::into_inner);
            let stopping = self
                .requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stopping;
            if !stopping && thread.as_ref().is_none_or(JoinHandle::is_finished) {
                let core = Arc::clone(core);
                let started = std::thread::Builder::new()
                    .name("oneiron-deferred-commit".into())
                    .spawn(move || core.lead_deferred_commit_groups());
                match started {
                    // A leader thread ends early only in a panic; a new one
                    // takes its place.
                    Ok(handle) => {
                        if let Some(ended) = thread.replace(handle) {
                            let _ = ended.join();
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "the deferred-commit leader did not start; the write leads its own group"
                        );
                        return false;
                    }
                }
            }
        }
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending = Some(limits);
        self.requested.notify_all();
        true
    }

    /// The next group asked for, or `None` once the store is dropping.
    fn next_request(&self) -> Option<Limits> {
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(limits) = requests.pending.take() {
                return Some(limits);
            }
            if requests.stopping {
                return None;
            }
            requests = self
                .requested
                .wait(requests)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Ends the leader thread once the group it leads, and each one asked of
    /// it after, is committed. The store is marked dropping first, so no
    /// request starts a thread again meanwhile.
    fn stop(&self) {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stopping = true;
        self.requested.notify_all();
        let Some(thread) = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        if thread.join().is_err() {
            tracing::warn!("the deferred-commit leader ended in a panic");
        }
    }
}

/// How many deferred-commit writes answered before their group's commit, and
/// how many of those the commits since settled, committed or lost. Groups
/// commit one at a time and such a write answers only inside its group, so
/// both count the same writes in the same order.
#[derive(Default)]
struct DeferredCommits {
    counts: Mutex<DeferredCounts>,
    settled: Condvar,
}

#[derive(Default)]
struct DeferredCounts {
    answered: u64,
    settled: u64,
}

impl DeferredCommits {
    /// Counts one write answered before its group's commit.
    fn answer(&self) {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .answered += 1;
    }

    /// The writes answered so far.
    fn answered(&self) -> u64 {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .answered
    }

    /// Every write answered up to `answered` has its group's commit decided.
    /// Returns how many that commit settled.
    fn settle_to(&self, answered: u64) -> u64 {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let settled = answered.saturating_sub(counts.settled);
        if settled > 0 {
            counts.settled = answered;
            self.settled.notify_all();
        }
        settled
    }

    /// Blocks until every write answered so far is settled.
    fn wait_settled(&self) {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let answered = counts.answered;
        drop(
            self.settled
                .wait_while(counts, |now| now.settled < answered)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

/// One queued logical write and its hand-offs with the leader.
struct Ticket {
    callback: Callback,
    turn: Mutex<Turn>,
    changed: Condvar,
}

#[derive(Default)]
enum Turn {
    #[default]
    Queued,
    /// Open and lead the next group.
    Lead,
    /// Run inside the leader's open transaction.
    Run(SharedTxn),
    /// Done with the shared transaction: whether its rows joined, and whether
    /// the group must close after it.
    Ran { kept: bool, closes: bool },
    /// The shared commit is decided: `None` committed, `Some` failed.
    Settled(Option<heed::Error>),
}

enum Assigned {
    Lead,
    Run(SharedTxn),
}

/// The leader's open transaction, lent to one member at a time.
struct SharedTxn(*mut RwTxn<'static>);

// SAFETY: LMDB keeps its write lock with the thread that began the transaction,
// and the leader both begins and commits it on its own thread. A member only
// begins, uses and ends a NESTED transaction under it, which takes no lock and
// touches no thread-local state. The leader stays blocked in `Ticket::run`
// until the member reports `Ran`, so exactly one thread uses the transaction
// at a time, and the ticket mutex orders every hand-off.
unsafe impl Send for SharedTxn {}

impl SharedTxn {
    fn lend(txn: &mut RwTxn<'_>) -> Self {
        Self(std::ptr::from_mut(txn).cast::<RwTxn<'static>>())
    }
}

/// A write on its way to the group, counted until it queues. The leader holds
/// its group open for announced writes, up to the window.
pub(crate) struct Announced<'s> {
    group: &'s GroupCommit,
}

impl Drop for Announced<'_> {
    fn drop(&mut self) {
        self.group.announced.fetch_sub(1, Ordering::AcqRel);
        // Notify under the lock so a leader between its check and its wait
        // cannot miss the change.
        let _waiting = self.group.lock();
        self.group.arrival.notify_all();
    }
}

struct Limits {
    window: Duration,
    max_writes: usize,
    /// A test holds this group open until this many writes ran in it.
    #[cfg(test)]
    hold_until: usize,
}

impl Limits {
    /// The two setting rows in force, read in the group's own transaction. A
    /// row that cannot be read leaves its seed in force: tuning never fails a
    /// write.
    fn read(store: &Store, txn: &RoTxn<'_>) -> Self {
        let value =
            |spec: &SettingSpec| setting_value_in_txn(store, txn, spec).unwrap_or(spec.seed);
        let window_ms = value(&GROUP_COMMIT_WINDOW_MS);
        Self {
            window: Duration::try_from_secs_f64(window_ms / 1000.0).unwrap_or(Duration::ZERO),
            // The row lies within the catalog's 1..=4096, so the cast is exact.
            max_writes: value(&GROUP_COMMIT_MAX_WRITES).clamp(1.0, GROUP_COMMIT_MAX_WRITES.max)
                as usize,
            #[cfg(test)]
            hold_until: store.group_commit.hooks.take_hold(),
        }
    }

    /// These bounds for the group the store's leader opens next, for the
    /// detached writes this group leaves queued (FIX 12023). A test's hold is
    /// this group's alone.
    fn again(&self) -> Self {
        Self {
            window: self.window,
            max_writes: self.max_writes,
            #[cfg(test)]
            hold_until: 0,
        }
    }
}

impl GroupCommit {
    fn lock(&self) -> MutexGuard<'_, Waiting> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts one write as on its way. Take it before the preparation a write
    /// does outside the transaction, and pass it to [`Store::group_write`].
    pub(crate) fn announce(&self) -> Announced<'_> {
        self.announced.fetch_add(1, Ordering::AcqRel);
        Announced { group: self }
    }

    /// The next member for the open group, or `None` when the group closes.
    fn next_member(&self, size: usize, limits: &Limits, opened: Instant) -> Option<Arrival> {
        if size >= limits.max_writes {
            return None;
        }
        let deadline = opened + limits.window;
        let mut waiting = self.lock();
        loop {
            match waiting.queue.front() {
                // An opaque callback joins no group: this one closes, and the
                // hand-off makes it the next leader, alone.
                Some(Arrival::Write(ticket)) if ticket.callback == Callback::Opaque => return None,
                Some(_) => {
                    let next = waiting.take_front();
                    if matches!(next, Some(Arrival::Detached(_))) {
                        self.detached.drained.notify_all();
                    }
                    return next;
                }
                None => {}
            }
            let (keep_open, deadline) = self.keep_open(size, limits, (opened, deadline));
            let now = Instant::now();
            if !keep_open || now >= deadline {
                return None;
            }
            waiting = self
                .arrival
                .wait_timeout(waiting, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Whether an empty queue still keeps the group open, and until when:
    /// while a write is announced, up to the window.
    #[cfg(not(test))]
    fn keep_open(
        &self,
        _size: usize,
        _limits: &Limits,
        (_opened, deadline): (Instant, Instant),
    ) -> (bool, Instant) {
        (self.announced.load(Ordering::Acquire) > 0, deadline)
    }

    #[cfg(test)]
    fn keep_open(
        &self,
        size: usize,
        limits: &Limits,
        (opened, deadline): (Instant, Instant),
    ) -> (bool, Instant) {
        if size < limits.hold_until {
            return (true, opened + hooks::HOLD_OPEN_LIMIT);
        }
        (self.announced.load(Ordering::Acquire) > 0, deadline)
    }

    /// Passes the writer on. A detached write the store's leader can run at
    /// the head of the queue goes to that leader, which runs the writes behind
    /// it as members (FIX 12023); else the first queued write leads, and runs
    /// first any detached write left ahead of it; with none queued, the writer
    /// stands down. `next` is the store's core and the bounds of the group
    /// that closes, for the leader's next group; `None`, after a writer did
    /// not open, asks no leader to try again.
    fn hand_off(&self, next: Option<(&Arc<StoreCore>, &Limits)>) {
        if let Some((core, limits)) = next
            && self.detached_heads_for_leader()
            && self.deferred_leader.request(core, limits.again())
        {
            return;
        }
        let mut waiting = self.lock();
        let first = waiting
            .queue
            .iter()
            .position(|arrival| matches!(arrival, Arrival::Write(_)));
        if let Some(at) = first
            && let Some(Arrival::Write(next)) = waiting.queue.remove(at)
        {
            drop(waiting);
            next.set(Turn::Lead);
            return;
        }
        // Detached writes no leader can take now stay queued for the next
        // writer, or the vault's own close; an enqueuer waiting past the
        // bound takes the writer for them.
        waiting.leading = false;
        drop(waiting);
        self.detached.drained.notify_all();
    }

    /// Puts a deferred-commit write that holds the writer back where it was
    /// queued, behind the detached writes that arrived before it, for the
    /// store's leader to run them and it first.
    fn requeue_first(&self, ticket: &Arc<Ticket>) {
        let mut waiting = self.lock();
        let at = waiting
            .queue
            .iter()
            .take_while(|arrival| matches!(arrival, Arrival::Detached(_)))
            .count();
        waiting.queue.insert(at, Arrival::Write(Arc::clone(ticket)));
    }

    /// Takes a deferred-commit write back out of the queue: the store's
    /// leader did not start, and it leads its group itself.
    fn withdraw(&self, ticket: &Arc<Ticket>) {
        self.lock().queue.retain(
            |arrival| !matches!(arrival, Arrival::Write(queued) if Arc::ptr_eq(queued, ticket)),
        );
    }

    /// Ends the store's deferred-commit leader after the group it leads, if
    /// any, has committed: the store's drop, so a clean close keeps every
    /// deferred-commit write it answered (Engine ruling 10-30 23:09).
    pub(crate) fn stop_deferred_commit_leader(&self) {
        self.deferred_leader.stop();
    }
}

impl Ticket {
    fn new(callback: Callback) -> Self {
        Self {
            callback,
            turn: Mutex::default(),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Turn> {
        self.turn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, turn: Turn) {
        *self.lock() = turn;
        self.changed.notify_all();
    }

    /// Member side: blocks until told to lead or to run.
    fn wait_for_turn(&self) -> Assigned {
        let mut turn = self.lock();
        loop {
            match std::mem::take(&mut *turn) {
                Turn::Lead => return Assigned::Lead,
                Turn::Run(shared) => return Assigned::Run(shared),
                other => *turn = other,
            }
            turn = self
                .changed
                .wait(turn)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Leader side: lends the open transaction and blocks until the member is
    /// done with it. Returns whether the member's rows joined the group, and
    /// whether the group closes after it.
    fn run(&self, shared: SharedTxn) -> (bool, bool) {
        let mut turn = self.lock();
        *turn = Turn::Run(shared);
        self.changed.notify_all();
        loop {
            if let Turn::Ran { kept, closes } = *turn {
                return (kept, closes);
            }
            turn = self
                .changed
                .wait(turn)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Member side: blocks until the shared commit is decided. Leaves every
    /// other state in place: the leader may not have read `Ran` yet.
    fn wait_settled(&self) -> Option<heed::Error> {
        let mut turn = self.lock();
        loop {
            if let Turn::Settled(lost) = &mut *turn {
                return lost.take();
            }
            turn = self
                .changed
                .wait(turn)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// How a member's write ended inside its nested transaction.
enum Staged<T, E> {
    /// Its rows joined the group; this answer stands once the group commits.
    Kept(std::result::Result<T, E>),
    /// Nothing joined; this is the final answer.
    Dropped(std::result::Result<T, E>),
    Panicked(Box<dyn std::any::Any + Send>),
}

impl Store {
    /// Runs one logical write in this vault's group commit.
    ///
    /// The write's closure gets a transaction of its own (the shared one when
    /// it leads, a nested one when it joins) and says through [`Rows`] whether
    /// its rows stay. The answer arrives only after the shared transaction
    /// committed. A panic in the closure drops its rows and resumes on the
    /// caller's thread. The write is engine code audited to hold nothing
    /// across the shared commit ([`Callback::Audited`]).
    ///
    /// A thread already inside a write transaction keeps its own, as before.
    pub(crate) fn group_write<T, E>(
        &self,
        announced: Option<Announced<'_>>,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.group_write_as(Callback::Audited, announced, write)
    }

    /// [`Self::group_write`] for a write of either kind: a
    /// [`Callback::Opaque`] write runs as a group of its own. Each write's
    /// legal-hold refusals reach their logs in its group's own transaction,
    /// kept whatever its rows did, so they are durable when it answers and no
    /// writer is taken again while its answer lives (FIX 2435); a write nested
    /// in a held writer leaves them to its outer write.
    pub(crate) fn group_write_as<T, E>(
        &self,
        callback: Callback,
        announced: Option<Announced<'_>>,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        // A keyed request's intent open here counts this write (FIX 10379).
        let write = super::idempotency_intent::counting_commits(self, write);
        if active_write_txn_depth() > 0 {
            drop(announced);
            return self.solo_write(write);
        }
        self.queue_write(callback, announced, write, None)
    }

    /// Queues `write` behind the open group, or leads one, and runs it there.
    /// `closing` is the vault whose drop this write is, for the detached
    /// writes that need it and run in this write's group (FIX 12023).
    fn queue_write<T, E>(
        &self,
        callback: Callback,
        announced: Option<Announced<'_>>,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
        closing: Option<&Vault>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let group = &self.group_commit;
        let ticket = {
            let mut waiting = group.lock();
            if waiting.leading {
                let ticket = Arc::new(Ticket::new(callback));
                waiting.queue.push_back(Arrival::Write(Arc::clone(&ticket)));
                group.arrival.notify_all();
                Some(ticket)
            } else {
                waiting.leading = true;
                None
            }
        };
        drop(announced);
        let Some(ticket) = ticket else {
            return self.lead(callback, write, closing);
        };
        match ticket.wait_for_turn() {
            Assigned::Lead => self.lead(callback, write, closing),
            Assigned::Run(shared) => self.join(&ticket, shared, write, AnswerAt::Commit),
        }
    }

    /// [`Self::group_write`] whose answer does not wait for the shared commit
    /// (Engine ruling 10-30 23:09). The write queues in arrival order as any
    /// write does, its closure runs in the group's open transaction with
    /// every check it makes, and once its rows are staged there its answer
    /// comes back. The group's leader commits them after: a writer already
    /// leading, or the store's own deferred-commit leader, which takes the
    /// writer for it when the writer is idle or is handed on to it. A crash
    /// before that commit loses rows whose answer already went out; the
    /// store's drop waits for it.
    ///
    /// It carries the legal-hold refusals queued outside any door's writer, as
    /// a leading write does. A write whose rows are dropped, or that holds
    /// what settles only at the commit (hold-log rows it wrote, a session
    /// segment it commits after the base), answers after the commit as any
    /// write does, and so does one that leads its group itself because the
    /// store's leader could not take it.
    #[allow(
        dead_code,
        reason = "the call receipt moved to the detached door (FIX 12023); this door stays for a \
                  write whose own checks must still refuse before its reply"
    )]
    pub(crate) fn group_write_deferred_commit<T, E>(
        &self,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let write = super::idempotency_intent::counting_commits(self, write);
        if active_write_txn_depth() > 0 {
            return self.solo_write(write);
        }
        let group = &self.group_commit;
        let ticket = Arc::new(Ticket::new(Callback::Audited));
        let idle = {
            let mut waiting = group.lock();
            waiting.queue.push_back(Arrival::Write(Arc::clone(&ticket)));
            group.arrival.notify_all();
            !std::mem::replace(&mut waiting.leading, true)
        };
        // Holding the writer, idle or handed on, this write asks the store's
        // leader to take its group, once.
        let mut asked = false;
        let mut holds_writer = idle;
        loop {
            if holds_writer {
                if !self.request_deferred_commit_leader() {
                    group.withdraw(&ticket);
                    return self.lead(Callback::Audited, write, None);
                }
                asked = true;
            }
            match ticket.wait_for_turn() {
                Assigned::Run(shared) => {
                    return self.join(&ticket, shared, write, AnswerAt::Stage);
                }
                // The store's leader handed the writer back: it could not
                // open the group, and this write leads it itself.
                Assigned::Lead if asked => return self.lead(Callback::Audited, write, None),
                Assigned::Lead => {
                    group.requeue_first(&ticket);
                    holds_writer = true;
                }
            }
        }
    }

    /// Asks the store's deferred-commit leader to take the group of a write
    /// that holds the writer. The group's limits are read here, in a snapshot
    /// taken while this write holds the writer, as its leader would read them
    /// in the transaction it opens. False when the leader cannot take it.
    fn request_deferred_commit_leader(&self) -> bool {
        let limits = match self.env.read_txn() {
            Ok(txn) => Limits::read(self, &txn),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the deferred-commit leader's limits did not read; the write leads its own group"
                );
                return false;
            }
        };
        self.group_commit
            .deferred_leader
            .request(&self.core, limits)
    }

    /// Blocks until the group commit of every deferred-commit write answered
    /// so far, and of every detached write queued so far (FIX 12023), is
    /// decided (Engine ruling 10-30 23:09), so a reader sees what such a write
    /// answered once it committed: a receipt a reply named. A thread inside a
    /// write, whose own group cannot commit while it waits, does not wait.
    /// Returns at once when none is in flight.
    pub(crate) fn wait_for_deferred_commits(&self) {
        if active_write_txn_depth() > 0 {
            return;
        }
        self.take_writer_for_left_detached();
        self.group_commit.deferred.wait_settled();
        self.group_commit.detached.wait_settled();
    }

    /// [`Self::group_write`] for a write whose `Ok` keeps its rows and whose
    /// `Err` drops them.
    pub(crate) fn write_in_group<T>(
        &self,
        write: impl FnOnce(&mut RwTxn<'_>) -> crate::error::Result<T>,
    ) -> crate::error::Result<T> {
        self.group_write(None, |txn| match write(txn) {
            Ok(value) => Rows::Commit(value),
            Err(err) => Rows::Discard(Err(err)),
        })
    }

    fn solo_write<T, E>(
        &self,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let mut txn = self.env.write_txn()?;
        match write(&mut txn) {
            Rows::Commit(value) => {
                txn.commit().map_err(Error::from)?;
                Ok(value)
            }
            Rows::Refuse(err) => {
                txn.commit().map_err(Error::from)?;
                Err(err)
            }
            Rows::Discard(answer) => answer,
        }
    }

    fn lead<T, E>(
        &self,
        callback: Callback,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
        closing: Option<&Vault>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let group = &self.group_commit;
        let mut shared = match self.env.write_txn() {
            Ok(txn) => txn,
            Err(err) => {
                group.hand_off(None);
                return Err(E::from(err));
            }
        };
        let opened = Instant::now();
        let limits = Limits::read(self, &shared);
        // Detached writes left ahead of this one run first, in their arrival
        // order (FIX 12023): no leader could take the writer for them.
        let mut detached = DetachedGroup::new(closing);
        self.core.run_queued_detached(&mut shared, &mut detached);
        // The leader's rows go next, in a transaction nested in the shared
        // one, so dropping them keeps the refusals logged beside them.
        let (staged, refusals) = self.stage(&mut shared, write);
        // An engine write's group also carries the refusals queued outside
        // any door's writer, as its flush did. An opaque one, which may be a
        // commit that moves no backup mark (FIX 6730), carries its own alone.
        let mut refusals = match callback {
            Callback::Audited => refusals.with_queued(),
            Callback::Opaque => refusals,
        };
        let answer = match staged {
            Staged::Kept(answer) => answer,
            Staged::Dropped(answer) => {
                // Nothing of it joined: the group closes at once, carrying
                // only those refusals and the detached writes that ran before
                // it, and drops whole when there are none.
                let logged = refusals.write_in(&mut shared);
                if detached.ran() > 0 {
                    let _ = self.core.close_group(
                        shared,
                        &limits,
                        opened,
                        (1, 0),
                        true,
                        Some(refusals),
                        detached,
                    );
                    return answer;
                }
                if logged {
                    refusals.landed(shared.commit().is_ok());
                } else {
                    drop(shared);
                }
                group.hand_off(Some((&self.core, &limits)));
                return answer;
            }
            Staged::Panicked(panic) => {
                if detached.ran() > 0 {
                    let _ = self.core.close_group(
                        shared,
                        &limits,
                        opened,
                        (1, 0),
                        true,
                        None,
                        detached,
                    );
                } else {
                    drop(shared);
                    group.hand_off(Some((&self.core, &limits)));
                }
                resume_unwind(panic);
            }
        };
        refusals.write_in(&mut shared);
        // An opaque leader runs alone (no member is ever opaque).
        let closes = callback == Callback::Opaque || holds_postcommit_permit();
        self.core
            .close_group(
                shared,
                &limits,
                opened,
                (1, 1),
                closes,
                Some(refusals),
                detached,
            )
            .map_err(|err| E::from(Error::from(err)))?;
        answer
    }

    fn join<T, E>(
        &self,
        ticket: &Ticket,
        shared: SharedTxn,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
        answer_at: AnswerAt,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let (staged, refusals, logged) = {
            // SAFETY: the leader lent its open transaction and stays blocked in
            // `Ticket::run` until this thread reports `Ran` below. This
            // reference and the nested transactions under it all end inside
            // this block, before that report.
            let parent = unsafe { &mut *shared.0 };
            let (staged, refusals) = self.stage(parent, write);
            // A deferred-commit write also carries the refusals queued
            // outside any door's writer, as the leader it stands in for
            // would: its group may have no leader write to carry them.
            let mut refusals = match answer_at {
                AnswerAt::Commit => refusals,
                AnswerAt::Stage => refusals.with_queued(),
            };
            // Its refusals join the group whatever its rows did.
            let logged = !matches!(staged, Staged::Panicked(_)) && refusals.write_in(parent);
            (staged, refusals, logged)
        };
        match staged {
            Staged::Kept(answer) => {
                let closes = holds_postcommit_permit();
                // A deferred-commit write answers once its rows are in the
                // group, unless it holds what settles only at the commit:
                // hold-log rows it wrote there, or a session segment it
                // commits after the base. It is counted before it reports, so
                // the leader settles it with this group's commit.
                let answers_staged = answer_at == AnswerAt::Stage && !logged && !closes;
                if answers_staged {
                    self.group_commit.deferred.answer();
                }
                ticket.set(Turn::Ran { kept: true, closes });
                if answers_staged {
                    return answer;
                }
                let lost = ticket.wait_settled();
                refusals.landed(lost.is_none());
                match lost {
                    None => answer,
                    Some(lost) => Err(E::from(Error::from(lost))),
                }
            }
            // No rows of its own joined, but a success read in the group may
            // rest on rows the group then failed to commit.
            Staged::Dropped(answer) => {
                ticket.set(Turn::Ran {
                    kept: false,
                    closes: false,
                });
                let lost = ticket.wait_settled();
                refusals.landed(lost.is_none());
                match (lost, answer) {
                    (Some(lost), Ok(_)) => Err(E::from(Error::from(lost))),
                    (_, answer) => answer,
                }
            }
            Staged::Panicked(panic) => {
                ticket.set(Turn::Ran {
                    kept: false,
                    closes: false,
                });
                resume_unwind(panic)
            }
        }
    }

    /// Runs `write` in a transaction nested in `parent`, keeping or dropping
    /// its rows as it says. The refusals it queues on this thread meanwhile
    /// come back as its own batch, for the caller to log in `parent`.
    fn stage<T, E>(
        &self,
        parent: &mut RwTxn<'_>,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> (Staged<T, E>, RefusalBatch<'_>)
    where
        E: From<Error>,
    {
        let attempt = self.begin_refusal_attempt();
        let staged = match self.env.nested_write_txn(parent) {
            Err(err) => Staged::Dropped(Err(E::from(Error::from(err)))),
            Ok(mut child) => match catch_unwind(AssertUnwindSafe(|| write(&mut child))) {
                Ok(Rows::Commit(value)) => match child.commit() {
                    Ok(()) => Staged::Kept(Ok(value)),
                    Err(err) => Staged::Dropped(Err(E::from(Error::from(err)))),
                },
                Ok(Rows::Refuse(refusal)) => match child.commit() {
                    Ok(()) => Staged::Kept(Err(refusal)),
                    Err(err) => Staged::Dropped(Err(E::from(Error::from(err)))),
                },
                Ok(Rows::Discard(answer)) => Staged::Dropped(answer),
                Err(panic) => Staged::Panicked(panic),
            },
        };
        (staged, attempt.finish())
    }
}

impl StoreCore {
    /// The rest of an open group after its leader's own rows: each queued
    /// write in turn until the group closes, then one commit, the leader's
    /// refusals settled, every member settled and the writer passed on. `ran`
    /// writes ran in it before the members, `kept` of them keeping rows, and
    /// `detached` holds the detached writes that ran before them (FIX 12023).
    #[allow(clippy::too_many_arguments)]
    fn close_group(
        self: &Arc<Self>,
        mut shared: RwTxn<'_>,
        limits: &Limits,
        opened: Instant,
        (ran, mut kept): (usize, usize),
        mut closes: bool,
        refusals: Option<RefusalBatch<'_>>,
        mut detached: DetachedGroup<'_>,
    ) -> heed::Result<()> {
        let group = &self.group_commit;
        let mut members = Vec::new();
        while !closes
            && let Some(next) =
                group.next_member(ran + members.len() + detached.ran(), limits, opened)
        {
            match next {
                Arrival::Write(ticket) => {
                    let (joined, closed) = ticket.run(SharedTxn::lend(&mut shared));
                    kept += usize::from(joined);
                    closes = closed;
                    members.push(ticket);
                }
                // A detached write runs on this thread. One whose vault
                // closes elsewhere goes back to the head, and the group
                // closes for that close to run it.
                Arrival::Detached(write) => {
                    if let Some(back) = self.run_detached(&mut shared, write, &mut detached) {
                        group.requeue_detached(back);
                        closes = true;
                    }
                }
            }
        }
        // Each deferred-commit write this group carries has answered by now,
        // and none of the next group can answer before this one hands off.
        let deferred = group.deferred.answered();
        // A group whose rows are only a clock floor's (FIX 11568) is noted
        // as its own writer noted it: by the txn id it took, once it
        // committed, when no other commit came between.
        let replay_only = detached
            .only_replay_rows(kept)
            .then(|| self.env.info().last_txn_id);
        #[cfg(test)]
        group
            .hooks
            .before_commit(ran + members.len() + detached.ran());
        #[cfg(not(test))]
        let committed = shared.commit();
        #[cfg(test)]
        let committed = group.hooks.commit(shared);
        let kept = kept + detached.kept();
        if committed.is_ok() && kept > 0 {
            self.diagnostics.group_commit.record(kept as u64);
        }
        if let Some(before) = replay_only
            && committed.is_ok()
            && self.env.info().last_txn_id == before + 1
        {
            self.diagnostics.replay_only_commits.note(before + 1);
        }
        detached.settle(&group.detached, &committed);
        let settled = group.deferred.settle_to(deferred);
        // The deferred-commit writes it carried answered already: a failed
        // commit loses their rows, said here as no answer can say it.
        if let Err(error) = &committed
            && settled > 0
        {
            tracing::warn!(
                %error,
                lost = settled,
                "a group commit failed after its deferred-commit writes answered; their rows are lost"
            );
        }
        if let Some(refusals) = refusals {
            refusals.landed(committed.is_ok());
        }
        // Every member waits for this, kept rows or not: an answer read in the
        // shared transaction may rest on rows an earlier member staged.
        for ticket in &members {
            ticket.set(Turn::Settled(committed.as_ref().err().map(replicate)));
        }
        group.hand_off(Some((self, limits)));
        detached.release();
        committed
    }

    /// The deferred-commit leader thread: each group asked for, until the
    /// store drops (Engine ruling 10-30 23:09).
    fn lead_deferred_commit_groups(self: &Arc<Self>) {
        while let Some(limits) = self.group_commit.deferred_leader.next_request() {
            self.lead_deferred_commit_group(&limits);
        }
    }

    /// Leads the group a deferred-commit or detached write took the writer
    /// for. It has no write of its own: the writes queued there run in arrival
    /// order, as in any group, and it commits once. Its deferred-commit
    /// members carry the legal-hold refusals queued outside any writer, which
    /// a leader with a write would carry.
    fn lead_deferred_commit_group(self: &Arc<Self>, limits: &Limits) {
        let group = &self.group_commit;
        let shared = match self.env.write_txn() {
            Ok(txn) => txn,
            Err(error) => {
                // The first queued write takes the writer and leads itself.
                // The detached writes queued have no caller to answer: their
                // writer did not open, and they are said lost.
                tracing::warn!(
                    %error,
                    "the deferred-commit leader could not open its group; the write leads its own"
                );
                group.discard_detached("the store's writer did not open for it");
                group.hand_off(None);
                return;
            }
        };
        let opened = Instant::now();
        // A failed commit reaches each member that waits for it, and the
        // group says what it lost of the writes that did not wait.
        let _ = self.close_group(
            shared,
            limits,
            opened,
            (0, 0),
            false,
            None,
            DetachedGroup::new(None),
        );
    }
}

/// Whether the write that just ran on this thread holds something it releases
/// only after its commit: an installed session-overlay segment, whose permit
/// the next write on that overlay waits for (lock order: base writer, then
/// segment permit). Its group closes after it, so that wait never sits inside
/// the same group.
fn holds_postcommit_permit() -> bool {
    crate::session_overlay::txn_segment_installed()
}

/// The shared commit's error, once per member whose rows it lost.
fn replicate(err: &heed::Error) -> heed::Error {
    match err {
        heed::Error::Mdb(code) => heed::Error::Mdb(*code),
        heed::Error::Io(io) => heed::Error::Io(io.raw_os_error().map_or_else(
            || std::io::Error::new(io.kind(), io.to_string()),
            std::io::Error::from_raw_os_error,
        )),
        other => heed::Error::Io(std::io::Error::other(other.to_string())),
    }
}

#[cfg(test)]
impl GroupCommit {
    /// Writes queued for the writer behind the open group. Each one has done
    /// everything it does before its transaction, so a test can act between
    /// a write's checks and its transaction.
    pub(crate) fn queued(&self) -> usize {
        let waiting = self.lock();
        waiting.queue.len() - waiting.detached
    }
}

#[cfg(test)]
pub(crate) mod hooks {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use heed::RwTxn;

    /// How long a test may hold a group open waiting for its members.
    pub(super) const HOLD_OPEN_LIMIT: Duration = Duration::from_secs(30);

    type BeforeCommit = Box<dyn Fn(usize) + Send + Sync>;

    /// Test seams of one vault's group commit.
    #[derive(Default)]
    pub(crate) struct GroupCommitHooks {
        /// Holds the next group open until this many writes ran in it.
        hold_until: AtomicUsize,
        /// Called with the number of writes that ran, just before a commit.
        before_commit: Mutex<Option<BeforeCommit>>,
        /// Fails the next shared commit.
        fail_commit: AtomicBool,
    }

    impl GroupCommitHooks {
        /// Holds the next group open until `writes` writes ran in it (or
        /// [`HOLD_OPEN_LIMIT`] passed), so a test knows who shares it.
        pub(crate) fn hold_next_group_until(&self, writes: usize) {
            self.hold_until.store(writes, Ordering::Release);
        }

        pub(crate) fn on_before_commit(&self, hook: impl Fn(usize) + Send + Sync + 'static) {
            *self
                .before_commit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
        }

        /// Makes the next shared commit fail the way a failed data sync does:
        /// LMDB discards the transaction and the leader gets an I/O error.
        pub(crate) fn fail_next_commit(&self) {
            self.fail_commit.store(true, Ordering::Release);
        }

        pub(super) fn commit(&self, txn: RwTxn<'_>) -> heed::Result<()> {
            if self.fail_commit.swap(false, Ordering::AcqRel) {
                drop(txn);
                return Err(heed::Error::Io(std::io::Error::other(
                    "injected: the shared commit's data sync failed",
                )));
            }
            txn.commit()
        }

        pub(super) fn take_hold(&self) -> usize {
            self.hold_until.swap(0, Ordering::AcqRel)
        }

        pub(super) fn before_commit(&self, ran: usize) {
            if let Some(hook) = self
                .before_commit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                hook(ran);
            }
        }
    }
}

#[cfg(test)]
mod tests;
