//! Bytes request bodies, or answers, may hold at once.
//!
//! Requests that find too few free wait in arrival order. Freed bytes are
//! handed to the oldest waiters under the budget's lock, as an admission
//! permit is ([`crate::admission`]), so the line is exactly the requests
//! still waiting: one handed its bytes has left it before its task runs
//! again. A wait that begins when nobody waits crosses the row and asks.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// Bytes request bodies may hold at once, taken before a body is read and
/// held until its request's work ends; or answers, taken before the model
/// makes one and held until it is delivered.
pub(super) struct BodyBudget {
    budget: Arc<Mutex<Budget>>,
    total: usize,
    /// The row a wait crosses.
    row: LimitRow,
}

struct Budget {
    free: usize,
    /// Requests waiting for bytes, oldest first.
    line: VecDeque<Arc<Turn>>,
}

/// One waiting request and the bytes it wants. They are handed over by
/// setting `granted` under the budget's lock, so a request that gives up
/// under the same lock either finds its bytes or is no longer in line.
struct Turn {
    bytes: usize,
    granted: AtomicBool,
    woken: Notify,
}

/// Bytes one request holds. Dropping them hands them to those waiting.
#[must_use = "a body's bytes are held only as long as this is"]
pub(super) struct BodyBytes {
    budget: Arc<Mutex<Budget>>,
    bytes: usize,
}

impl BodyBudget {
    /// A budget for request bodies.
    pub(super) fn new(total: usize) -> Self {
        Self::crossing(total, LimitRow::EmbedderBodyBytes)
    }

    /// A budget for answers.
    pub(super) fn answers(total: usize) -> Self {
        Self::crossing(total, LimitRow::EmbedderAnswerBytes)
    }

    fn crossing(total: usize, row: LimitRow) -> Self {
        Self {
            budget: Arc::new(Mutex::new(Budget {
                free: total,
                line: VecDeque::new(),
            })),
            total,
            row,
        }
    }

    /// Reserves `bytes`, at once or at its turn: requests that find the
    /// budget full wait in order, each up to `wait`, and the first to wait
    /// when none did crosses the row and asks. `None` when the wait ran out,
    /// or at once for more bytes than the whole budget: those are never
    /// held under a smaller claim. The endpoint sizes its budgets so no
    /// request asks for that: a body is at most a budget, and the answer
    /// row is checked against the model's largest answer at start.
    pub(super) async fn reserve(
        &self,
        bytes: usize,
        wait: Duration,
        questions: &LimitQuestions,
    ) -> Option<BodyBytes> {
        if bytes > self.total {
            return None;
        }
        let mut place = {
            let mut budget = lock(&self.budget);
            // A waiter holds back every later request, so free bytes with
            // nobody in line mean nobody is ahead.
            if budget.line.is_empty() && budget.free >= bytes {
                budget.free -= bytes;
                return Some(self.held(bytes));
            }
            let first = budget.line.is_empty();
            let turn = Arc::new(Turn {
                bytes,
                granted: AtomicBool::new(false),
                woken: Notify::new(),
            });
            budget.line.push_back(Arc::clone(&turn));
            let held = self.total - budget.free;
            drop(budget);
            if first {
                questions.ask(
                    self.row,
                    self.total as u64,
                    held.saturating_add(bytes) as u64,
                );
            }
            Place {
                budget: Arc::clone(&self.budget),
                turn,
                settled: false,
            }
        };
        let turn = Arc::clone(&place.turn);
        let _ = tokio::time::timeout(wait, turn.granted()).await;
        place.settle().then(|| self.held(bytes))
    }

    fn held(&self, bytes: usize) -> BodyBytes {
        BodyBytes {
            budget: Arc::clone(&self.budget),
            bytes,
        }
    }

    /// Requests waiting for bytes now.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        lock(&self.budget).line.len()
    }

    /// Bytes held now, by requests reading or holding their bodies.
    #[cfg(test)]
    pub(super) fn held_bytes(&self) -> usize {
        self.total - lock(&self.budget).free
    }
}

impl Budget {
    /// Hands free bytes to the oldest waiters while theirs fit. The oldest
    /// that does not fit holds back those behind it, so a large body is never
    /// passed over for ever by small ones.
    fn grant(&mut self) {
        while let Some(turn) = self.line.front() {
            if turn.bytes > self.free {
                return;
            }
            self.free -= turn.bytes;
            turn.granted.store(true, Ordering::SeqCst);
            turn.woken.notify_one();
            self.line.pop_front();
        }
    }
}

/// A place in line. Settling it (or dropping it, when the request went away)
/// takes the bytes if they were handed over, or leaves the line if not.
struct Place {
    budget: Arc<Mutex<Budget>>,
    turn: Arc<Turn>,
    settled: bool,
}

impl Place {
    fn settle(&mut self) -> bool {
        if self.settled {
            return false;
        }
        self.settled = true;
        let mut budget = lock(&self.budget);
        if self.turn.granted.load(Ordering::SeqCst) {
            return true;
        }
        budget
            .line
            .retain(|queued| !Arc::ptr_eq(queued, &self.turn));
        // Whoever it held back may fit now.
        budget.grant();
        false
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        // Bytes handed to a request that has gone go straight on.
        if self.settle() {
            drop(BodyBytes {
                budget: Arc::clone(&self.budget),
                bytes: self.turn.bytes,
            });
        }
    }
}

impl Turn {
    async fn granted(&self) {
        loop {
            let woken = self.woken.notified();
            if self.granted.load(Ordering::SeqCst) {
                return;
            }
            woken.await;
        }
    }
}

impl Drop for BodyBytes {
    fn drop(&mut self) {
        let mut budget = lock(&self.budget);
        budget.free += self.bytes;
        budget.grant();
    }
}

/// What an answer of `inputs` rows of `dimensions` floats may hold until it
/// is delivered: the rows as the model returns them (4 bytes a float) or as
/// base64 (under 6), and at the same time their encoding
/// ([`encoding_bytes`]).
pub(super) fn answer_bytes(inputs: usize, dimensions: usize) -> usize {
    inputs
        .saturating_mul(dimensions.saturating_mul(6))
        .saturating_add(encoding_bytes(inputs, dimensions))
}

/// The most an answer's encoding takes: 18 bytes a float as JSON (an f32's
/// shortest form, as ryu writes it, is at most 17: a sign, `0.`, five zeros
/// and nine digits; and its comma), with room for each row's own fields and
/// the answer's. The answer is encoded into a buffer of exactly this many
/// bytes, which is never grown, so what it holds is what was counted.
pub(super) fn encoding_bytes(inputs: usize, dimensions: usize) -> usize {
    inputs
        .saturating_mul(dimensions.saturating_mul(18).saturating_add(ROW_FIELDS))
        .saturating_add(ANSWER_FIELDS)
}

/// A buffer that is never grown: a write past its capacity fails, so an
/// answer holds no more than the room it took.
pub(super) struct Fixed(pub(super) Vec<u8>);

impl std::io::Write for Fixed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0.capacity() - self.0.len() {
            return Err(std::io::Error::other("the answer is past its room"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One answer row's fields past its floats, counted generously.
const ROW_FIELDS: usize = 256;

/// An answer's fields past its rows (the model, its transform, profile and
/// provenance), counted generously.
const ANSWER_FIELDS: usize = 16 * 1024;

/// The budget's counts and line change in one step each under its lock, so
/// a holder that panicked left them whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
