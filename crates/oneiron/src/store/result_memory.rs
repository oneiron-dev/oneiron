//! The memory code-mode result bodies may hold (OF-190 B++).
//!
//! One pool bounds the bodies every run in the process keeps in memory at
//! once (`[limits] code_result_memory_bytes`); each run draws on it through a
//! share, at most `[limits] code_result_session_memory_bytes` and at most the
//! pool split between the runs open on it. The host makes one pool and
//! installs it on every vault it opens ([`crate::Vault::set_result_memory`]);
//! until it does, a vault draws on a pool of its own, sized from its rows.
//!
//! Nothing here refuses. A body that would take a run past its share or the
//! pool past its bound asks the row's OF-520 question and stays in its file,
//! where the run reads it by range.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::limit_ask::{EngineLimit, LimitWatch};

/// Result bodies held in memory by every run drawing on it.
#[derive(Debug)]
pub struct ResultMemoryPool {
    bound: u64,
    held: AtomicU64,
    runs: AtomicU64,
}

impl ResultMemoryPool {
    /// A pool of `bound` bytes.
    #[must_use]
    pub fn new(bound: u64) -> Self {
        Self {
            bound,
            held: AtomicU64::new(0),
            runs: AtomicU64::new(0),
        }
    }

    /// The bytes the pool may hold.
    #[must_use]
    pub fn bound(&self) -> u64 {
        self.bound
    }

    /// The bytes it holds now.
    #[must_use]
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    /// Opens one run's share, at most `ceiling` bytes.
    pub(crate) fn share(self: &Arc<Self>, ceiling: u64) -> ResultShare {
        self.runs.fetch_add(1, Ordering::Relaxed);
        ResultShare(Arc::new(ShareState {
            pool: Arc::clone(self),
            ceiling,
            held: AtomicU64::new(0),
        }))
    }
}

#[derive(Debug)]
struct ShareState {
    pool: Arc<ResultMemoryPool>,
    ceiling: u64,
    held: AtomicU64,
}

impl Drop for ShareState {
    fn drop(&mut self) {
        self.pool.runs.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One run's draw on the pool. Dropped with the run.
#[derive(Debug)]
pub(crate) struct ResultShare(Arc<ShareState>);

impl ResultShare {
    /// What this run may hold now: its ceiling, or its even split of the
    /// pool, whichever is less.
    pub(crate) fn bytes(&self) -> u64 {
        let runs = self.0.pool.runs.load(Ordering::Relaxed).max(1);
        self.0.ceiling.min(self.0.pool.bound / runs)
    }

    /// What this run holds now.
    pub(crate) fn held(&self) -> u64 {
        self.0.held.load(Ordering::Relaxed)
    }

    /// Holds `bytes` of body in memory, or, past the run's share or the
    /// pool's bound, asks that row's question through `watch` and holds
    /// nothing: the caller leaves the body in its file. Each add is checked
    /// as it lands, so two runs racing for the last bytes never both pass,
    /// and a pool add that does not fit gives the run's back (FIX 313).
    pub(crate) fn hold(&self, bytes: u64, watch: &LimitWatch) -> Option<ResultHold> {
        let share = self.bytes();
        if let Err(held) = add_within(&self.0.held, bytes, share) {
            let run_after = held.saturating_add(bytes);
            watch.crossed(EngineLimit::CodeResultSessionMemoryBytes, share, run_after);
            return None;
        }
        let pool = &self.0.pool;
        if let Err(held) = add_within(&pool.held, bytes, pool.bound) {
            self.0.held.fetch_sub(bytes, Ordering::Relaxed);
            let pool_after = held.saturating_add(bytes);
            watch.crossed(EngineLimit::CodeResultMemoryBytes, pool.bound, pool_after);
            return None;
        }
        Some(ResultHold {
            share: Arc::clone(&self.0),
            bytes,
        })
    }
}

/// Adds `bytes` to `held` in one step while the sum stays within `bound`;
/// else adds nothing and returns what `held` was.
fn add_within(held: &AtomicU64, bytes: u64, bound: u64) -> Result<u64, u64> {
    held.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |now| {
        now.checked_add(bytes).filter(|after| *after <= bound)
    })
}

/// Body bytes one run holds in memory, given back when dropped.
#[derive(Debug)]
pub(crate) struct ResultHold {
    share: Arc<ShareState>,
    bytes: u64,
}

impl Drop for ResultHold {
    fn drop(&mut self) {
        self.share.held.fetch_sub(self.bytes, Ordering::Relaxed);
        self.share
            .pool
            .held
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

impl crate::Vault {
    /// Installs the process's result-memory pool on this vault, in place of
    /// the one it opened with. A run already open keeps the pool it drew on.
    pub fn set_result_memory(&self, pool: Arc<ResultMemoryPool>) {
        *self
            .store
            .result_memory
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = pool;
    }

    /// Opens one run's share of the installed pool.
    pub(crate) fn result_share(&self) -> ResultShare {
        let pool = Arc::clone(
            &self
                .store
                .result_memory
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        pool.share(
            self.limit_watch()
                .bound(EngineLimit::CodeResultSessionMemoryBytes),
        )
    }
}
