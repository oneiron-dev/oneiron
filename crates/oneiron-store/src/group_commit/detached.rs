//! Detached writes (FIX 12023; Engine ruling 10-30 23:09, extended to the
//! light recall's own writes).
//!
//! A detached write's caller needs none of its rows to answer: a call
//! receipt's ref, a retrieval run's id and an authorization's judged time are
//! all minted before it queues. It takes its place in the group commit's one
//! arrival order, beside the writes whose threads wait for their turn, and
//! normally returns after enqueueing, without waiting for its stage or commit.
//! Queue backpressure and the leader-start fallback below can still block the
//! calling thread. The group's leader runs its closure on its own thread, in a
//! transaction nested in the shared one, when its turn comes: a writer
//! already leading, or the store's deferred-commit leader, which takes the
//! writer for it when no group is open. A closure that fails rolls back its
//! own rows only, is said in a warn with the write's name, and fails no
//! group.
//!
//! A crash before its group commits loses rows whose caller already answered.
//! A clean close keeps them: the vault's drop and the store's drop run every
//! detached write still queued before either closes, and a reader that must
//! see their rows waits until those queued so far are decided
//! ([`Store::wait_for_deferred_commits`]). Memory stays bounded without a
//! refusal: at [`DETACHED_WRITES_WAITING_MAX`] (4096) queued while a group is
//! led, an enqueuer outside an active write waits for the drain rather than
//! dropping its write. That wait is on the caller's thread, including a call
//! receipt's or recall telemetry's reply thread: it can wait behind the writer.
//! If the deferred-commit leader cannot start, the caller leads the group
//! itself and can also wait for the writer, stage and commit.
//!
//! Most closures write over the store's core alone, which the store's own
//! leader holds ([`DetachedWrite::of_core`]). One that writes through the
//! vault's own doors (a call receipt, whose side-row wall mints custody
//! through the vault) holds the vault weakly, so a queued write never keeps a
//! vault open, and runs on a handle its leader takes while a holder keeps the
//! vault, or on the closing vault in its drop ([`DetachedWrite::of_vault`]).
//! When the handle a leader took turns out to be the last, because every
//! other holder let go while the write ran, the vault closes on a thread of
//! its own just after. Each handle a leader takes is counted on its vault's
//! open path from when it is taken until it is let go of, its close
//! included ([`LeaderHolds`]), so a reopen of that path in this process waits
//! for that close rather than finding the vault still open (FIX 12316).
//!
//! A write may carry an after-commit callback ([`DetachedWrite::after_commit`]):
//! it runs once with whether the write's rows landed, after its group's
//! commit or that commit's failure, never at the stage. A write whose closure
//! failed is told `false` once its group's commit is decided, and a write lost
//! before any group ran it is told `false` as it is said lost.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use heed::RwTxn;

use crate::active_write_txn::active_write_txn_depth;
use crate::active_write_txn::active_write_txn_guard;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// Past this many detached writes queued, an enqueuer waits for the drain
/// before it adds its own (FIX 12023): memory stays bounded, and no write is
/// refused or dropped.
pub const DETACHED_WRITES_WAITING_MAX: usize = 4096;

/// What runs once a detached write's group commit is decided, with whether
/// its rows landed: `true` only when its closure kept them and the group
/// committed. A lease is held from that commit, not from the queueing.
pub type AfterCommit = Box<dyn FnOnce(bool) + Send>;

/// How many detached writes queued, and how many of them the commits since
/// decided, committed or lost (FIX 12023). They leave the queue in order and
/// each group settles its own before it passes the writer on, so the first
/// `settled` writes queued are the decided ones.
#[derive(Default)]
pub struct DetachedWrites {
    pub counts: Mutex<DetachedCounts>,
    pub settled: Condvar,
    /// Wakes an enqueuer that waits past the bound; waited on with the
    /// queue's lock.
    pub drained: Condvar,
}

#[derive(Default)]
struct DetachedCounts {
    pub queued: u64,
    pub settled: u64,
}

impl DetachedWrites {
    pub fn counts(&self) -> MutexGuard<'_, DetachedCounts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts one write queued.
    pub fn queue_one(&self) {
        self.counts().queued += 1;
    }

    /// Counts `writes` more decided.
    pub fn settle(&self, writes: usize) {
        if writes == 0 {
            return;
        }
        self.counts().settled += writes as u64;
        self.settled.notify_all();
    }

    /// The writes decided so far.
    pub fn settled_count(&self) -> u64 {
        self.counts().settled
    }

    /// The writes queued so far.
    pub fn queued_count(&self) -> u64 {
        self.counts().queued
    }

    /// Blocks until every write queued so far is decided.
    pub fn wait_settled(&self) {
        let counts = self.counts();
        let queued = counts.queued;
        drop(
            self.settled
                .wait_while(counts, |now| now.settled < queued)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// [`Self::wait_settled`] until `deadline` at most (FIX 12023 W0):
    /// whether every write queued when it began is decided by then.
    pub fn wait_settled_until(&self, deadline: Instant) -> bool {
        let counts = self.counts();
        let queued = counts.queued;
        let timeout = deadline.saturating_duration_since(Instant::now());
        let (counts, _) = self
            .settled
            .wait_timeout_while(counts, timeout, |now| now.settled < queued)
            .unwrap_or_else(PoisonError::into_inner);
        counts.settled >= queued
    }
}

/// How often a reopen looks again while a store's leader holds the vault at
/// its path ([`LeaderHolds::wait_for_release`]).
pub const LEADER_HOLD_POLL: Duration = Duration::from_millis(10);
