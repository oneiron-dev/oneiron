//! Admission for work a remote caller can start.
//!
//! The rule every remotely reachable piece of work follows: it takes a permit
//! before it begins, and the permit travels with the work itself (the
//! connection, the child process, the upload spool, the worker thread), never
//! only with the handler that started it. A caller who hangs up therefore
//! frees nothing the work still holds.
//!
//! Past the bound, work waits; it is never refused for count (the owner's
//! rate law, ARCH-0044 C5). The line is the engine's
//! ([`oneiron::work_line`]), the same one the vault's task work waits in:
//! round-robin across keys, arrival order within one key, a deadline per
//! wait, and the host's own background work behind every caller.
//!
//! Each bound is a `[limits]` row set far above fleet scale. When work has to
//! wait and nobody waited before it, the row is crossed: it raises its typed
//! "is everything okay" question (OF-520, see [`LimitQuestions`]), which
//! counts every crossing.

use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use oneiron::work_line::{LineCrossing, WorkLine};
pub(crate) use oneiron::work_line::{LinePermit as Permit, WaitTimedOut};

use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// A bound over one kind of work, and the queue of work waiting for it.
pub(crate) struct Admission<K> {
    line: WorkLine<K>,
}

/// A clone shares the pool: one bound, one queue.
impl<K> Clone for Admission<K> {
    fn clone(&self) -> Self {
        Self {
            line: self.line.clone(),
        }
    }
}

impl<K: Eq + Hash + Clone + Send + 'static> Admission<K> {
    /// A pool of `bound` permits whose waits end at `wait`, crossing `row`.
    pub(crate) fn new(
        row: LimitRow,
        questions: Arc<LimitQuestions>,
        bound: usize,
        wait: Duration,
    ) -> Self {
        Self {
            line: WorkLine::new(Some(row_crossing(row, questions)), bound, wait),
        }
    }

    /// One turn at a time: an exclusive resource's queue, which is not a
    /// threshold and asks no question when it is busy.
    pub(crate) fn exclusive(wait: Duration) -> Self {
        Self {
            line: WorkLine::exclusive(wait),
        }
    }

    /// Whether no work holds a permit or waits for one.
    pub(crate) fn is_idle(&self) -> bool {
        self.line.is_idle()
    }

    /// How many pieces of work wait for a permit.
    pub(crate) fn waiting(&self) -> usize {
        self.line.waiting()
    }

    /// A permit for `key`'s work, now or at its turn.
    pub(crate) async fn admit(&self, key: K) -> Result<Permit, WaitTimedOut> {
        self.line.admit(key).await
    }

    /// [`Self::admit`], in line from this call on: the returned future only
    /// waits, so work spawned in order keeps its order, and waiting holds no
    /// thread.
    pub(crate) fn admit_in_line(
        &self,
        key: K,
    ) -> impl Future<Output = Result<Permit, WaitTimedOut>> + Send + 'static {
        self.line.admit_in_line(key)
    }

    /// A permit for the host's own work, given only when no caller waits.
    pub(crate) fn admit_background_blocking(&self) -> Result<Permit, WaitTimedOut> {
        self.line.admit_background_blocking()
    }

    /// A free permit for the host's own work, or `None` with nothing put in
    /// line: the work waits for a later look rather than for a turn.
    pub(crate) fn try_admit_background(&self) -> Option<Permit> {
        self.line.try_admit_background()
    }
}

/// Where a `[limits]` row's crossing is asked: its typed question.
pub(crate) fn row_crossing(row: LimitRow, questions: Arc<LimitQuestions>) -> Arc<dyn LineCrossing> {
    Arc::new(RowCrossing { row, questions })
}

struct RowCrossing {
    row: LimitRow,
    questions: Arc<LimitQuestions>,
}

impl LineCrossing for RowCrossing {
    fn crossed(&self, bound: u64, observed: u64) {
        self.questions.ask(self.row, bound, observed);
    }
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
