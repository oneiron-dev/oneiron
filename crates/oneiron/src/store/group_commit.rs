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
//! A group closes at its size bound, at the end of its window, or as soon as
//! no announced write is still on its way, so a lone writer never waits. Both
//! bounds are learned-setting rows ([`GROUP_COMMIT_WINDOW_MS`],
//! [`GROUP_COMMIT_MAX_WRITES`]) that the leader reads in the transaction it
//! opens.
//!
//! A write that leaves a session-overlay segment installed holds that
//! segment's permit until it commits the segment after the base commit, so the
//! group closes right after it: no later member of the same group can wait on
//! that permit.
//!
//! This is the store's existing single writer taking many rows per commit. It
//! is not a lock: correctness is still LMDB's one write transaction, and a
//! writer that opens `env.write_txn()` itself waits for the group like any
//! other writer. It is not a queue outside the store, and not a coordinator:
//! the next waiting member leads the next group itself.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use heed::{RoTxn, RwTxn};

use crate::error::Error;
use crate::learning_setting::{
    GROUP_COMMIT_MAX_WRITES, GROUP_COMMIT_WINDOW_MS, SettingSpec, setting_value_in_txn,
};

use super::{Store, active_write_txn_depth};

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
    #[cfg(test)]
    pub(crate) hooks: hooks::GroupCommitHooks,
}

#[derive(Default)]
struct Waiting {
    /// A group is open or committing; arrivals queue behind it.
    leading: bool,
    queue: VecDeque<Arc<Ticket>>,
}

/// One queued logical write and its hand-offs with the leader.
#[derive(Default)]
struct Ticket {
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
    fn next_member(&self, size: usize, limits: &Limits, opened: Instant) -> Option<Arc<Ticket>> {
        if size >= limits.max_writes {
            return None;
        }
        let deadline = opened + limits.window;
        let mut waiting = self.lock();
        loop {
            if let Some(ticket) = waiting.queue.pop_front() {
                return Some(ticket);
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

    /// Passes the writer to the first queued write, or stands down.
    fn hand_off(&self) {
        let mut waiting = self.lock();
        match waiting.queue.pop_front() {
            Some(next) => {
                drop(waiting);
                next.set(Turn::Lead);
            }
            None => waiting.leading = false,
        }
    }
}

impl Ticket {
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
    /// caller's thread.
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
        if active_write_txn_depth() > 0 {
            drop(announced);
            return self.solo_write(write);
        }
        let group = &self.group_commit;
        let ticket = {
            let mut waiting = group.lock();
            if waiting.leading {
                let ticket = Arc::new(Ticket::default());
                waiting.queue.push_back(Arc::clone(&ticket));
                group.arrival.notify_all();
                Some(ticket)
            } else {
                waiting.leading = true;
                None
            }
        };
        drop(announced);
        let Some(ticket) = ticket else {
            return self.lead(write);
        };
        match ticket.wait_for_turn() {
            Assigned::Lead => self.lead(write),
            Assigned::Run(shared) => self.join(&ticket, shared, write),
        }
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
        let mut txn = self.env.write_txn().map_err(Error::from)?;
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
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let group = &self.group_commit;
        let mut shared = match self.env.write_txn() {
            Ok(txn) => txn,
            Err(err) => {
                group.hand_off();
                return Err(E::from(Error::from(err)));
            }
        };
        let opened = Instant::now();
        let limits = Limits::read(self, &shared);
        // The leader writes straight into the shared transaction. It goes
        // first, so a failure has no neighbour to protect and drops it whole.
        let answer = match catch_unwind(AssertUnwindSafe(|| write(&mut shared))) {
            Ok(Rows::Commit(value)) => Ok(value),
            Ok(Rows::Refuse(err)) => Err(err),
            Ok(Rows::Discard(answer)) => {
                drop(shared);
                group.hand_off();
                return answer;
            }
            Err(panic) => {
                drop(shared);
                group.hand_off();
                resume_unwind(panic);
            }
        };
        let mut members = Vec::new();
        let mut kept = 1;
        let mut closes = holds_postcommit_permit();
        while !closes && let Some(ticket) = group.next_member(1 + members.len(), &limits, opened) {
            let (joined, closed) = ticket.run(SharedTxn::lend(&mut shared));
            kept += usize::from(joined);
            closes = closed;
            members.push(ticket);
        }
        #[cfg(test)]
        group.hooks.before_commit(1 + members.len());
        let committed = shared.commit();
        if committed.is_ok() {
            self.diagnostics.group_commit.record(kept as u64);
        }
        // Every member waits for this, kept rows or not: an answer read in the
        // shared transaction may rest on rows an earlier member staged.
        for ticket in &members {
            ticket.set(Turn::Settled(committed.as_ref().err().map(replicate)));
        }
        group.hand_off();
        committed.map_err(|err| E::from(Error::from(err)))?;
        answer
    }

    fn join<T, E>(
        &self,
        ticket: &Ticket,
        shared: SharedTxn,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let staged = {
            // SAFETY: the leader lent its open transaction and stays blocked in
            // `Ticket::run` until this thread reports `Ran` below. This
            // reference and the nested transaction under it both end inside
            // this block, before that report.
            let parent = unsafe { &mut *shared.0 };
            match self.env.nested_write_txn(parent) {
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
            }
        };
        match staged {
            Staged::Kept(answer) => {
                ticket.set(Turn::Ran {
                    kept: true,
                    closes: holds_postcommit_permit(),
                });
                match ticket.wait_settled() {
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
                match (ticket.wait_settled(), answer) {
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
pub(crate) mod hooks {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

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
