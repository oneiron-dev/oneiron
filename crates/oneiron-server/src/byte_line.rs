//! Bytes in memory the work under one row may hold at once: the embedder
//! endpoint's request bodies or answers, or LFS transfers' room.
//!
//! Work that finds too few free waits in arrival order. Freed bytes are
//! handed to the oldest waiters under the line's lock, as an admission
//! permit is ([`crate::admission`]), so the line is exactly the work still
//! waiting: work handed its bytes has left it before its task runs again. A
//! wait that begins when nobody waits crosses the row and asks, and so does
//! work larger than the whole line, which waits until it can run alone.
//!
//! Lock order, where a line sits beside the LFS transfer permits: a read (a
//! chunk exchange, a download, a verify) takes its bytes on the reads line,
//! then its transfer permit; an upload takes its transfer permit, then, once
//! its body is spooled, its bytes on the installs line. A read waiting for a
//! permit holds only bytes no upload waits for, and an install in progress
//! waits on no line, so neither wait closes a cycle.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// Bytes the work under one row may hold at once, each piece taking its
/// bytes before it allocates them and holding them until it ends.
pub(crate) struct ByteLine {
    line: Arc<Mutex<Line>>,
    total: usize,
    /// The row a wait crosses.
    row: LimitRow,
}

struct Line {
    free: usize,
    /// Work waiting for bytes, oldest first.
    waiting: VecDeque<Arc<Turn>>,
}

/// One piece of waiting work and the bytes it wants. They are handed over by
/// setting `granted` under the line's lock, so work that gives up under the
/// same lock either finds its bytes or is no longer in line.
struct Turn {
    bytes: usize,
    granted: AtomicBool,
    woken: Notify,
}

/// Bytes one piece of work holds. Dropping them hands them to those waiting.
#[must_use = "bytes are held only as long as this is"]
pub(crate) struct HeldBytes {
    line: Arc<Mutex<Line>>,
    bytes: usize,
}

impl ByteLine {
    /// A line of `total` bytes under `row`.
    pub(crate) fn new(row: LimitRow, total: usize) -> Self {
        Self {
            line: Arc::new(Mutex::new(Line {
                free: total,
                waiting: VecDeque::new(),
            })),
            total,
            row,
        }
    }

    /// Reserves `bytes`, at once or at its turn: work that finds the line
    /// full waits in order, each up to `wait`, and the first to wait when
    /// none did crosses the row and asks. `None` when the wait ran out, or
    /// at once for more bytes than the whole line: those are never held
    /// under a smaller claim. A caller that sizes its line so no work asks
    /// for that uses this; one that cannot uses [`Self::reserve_alone`].
    pub(crate) async fn reserve(
        &self,
        bytes: usize,
        wait: Duration,
        questions: &LimitQuestions,
    ) -> Option<HeldBytes> {
        if bytes > self.total {
            return None;
        }
        self.take(bytes, bytes, wait, questions).await
    }

    /// Reserves `bytes` as [`Self::reserve`] does, but work larger than the
    /// whole line is never refused: it takes the whole line, so it waits
    /// until it can run alone and holds back those behind it, and the row
    /// asks. `None` only when the wait ran out.
    pub(crate) async fn reserve_alone(
        &self,
        bytes: usize,
        wait: Duration,
        questions: &LimitQuestions,
    ) -> Option<HeldBytes> {
        self.take(bytes.min(self.total), bytes, wait, questions)
            .await
    }

    /// Takes `bytes` for work that wants `wanted`, which is more only when
    /// the work is larger than the line.
    async fn take(
        &self,
        bytes: usize,
        wanted: usize,
        wait: Duration,
        questions: &LimitQuestions,
    ) -> Option<HeldBytes> {
        let mut place = {
            let mut line = lock(&self.line);
            let held = self.total - line.free;
            // A waiter holds back all later work, so free bytes with
            // nobody in line mean nobody is ahead.
            if line.waiting.is_empty() && line.free >= bytes {
                line.free -= bytes;
                drop(line);
                if wanted > bytes {
                    questions.ask(
                        self.row,
                        self.total as u64,
                        held.saturating_add(wanted) as u64,
                    );
                }
                return Some(self.held(bytes));
            }
            let first = line.waiting.is_empty();
            let turn = Arc::new(Turn {
                bytes,
                granted: AtomicBool::new(false),
                woken: Notify::new(),
            });
            line.waiting.push_back(Arc::clone(&turn));
            drop(line);
            if first || wanted > bytes {
                questions.ask(
                    self.row,
                    self.total as u64,
                    held.saturating_add(wanted) as u64,
                );
            }
            Place {
                line: Arc::clone(&self.line),
                turn,
                settled: false,
            }
        };
        let turn = Arc::clone(&place.turn);
        let _ = tokio::time::timeout(wait, turn.granted()).await;
        place.settle().then(|| self.held(bytes))
    }

    fn held(&self, bytes: usize) -> HeldBytes {
        HeldBytes {
            line: Arc::clone(&self.line),
            bytes,
        }
    }

    /// Work waiting for bytes now.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        lock(&self.line).waiting.len()
    }

    /// Bytes held now.
    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> usize {
        self.total - lock(&self.line).free
    }

    /// The bytes the line holds.
    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.total
    }
}

impl Line {
    /// Hands free bytes to the oldest waiters while theirs fit. The oldest
    /// that does not fit holds back those behind it, so large work is never
    /// passed over for ever by small work.
    fn grant(&mut self) {
        while let Some(turn) = self.waiting.front() {
            if turn.bytes > self.free {
                return;
            }
            self.free -= turn.bytes;
            turn.granted.store(true, Ordering::SeqCst);
            turn.woken.notify_one();
            self.waiting.pop_front();
        }
    }
}

/// A place in line. Settling it (or dropping it, when the work went away)
/// takes the bytes if they were handed over, or leaves the line if not.
struct Place {
    line: Arc<Mutex<Line>>,
    turn: Arc<Turn>,
    settled: bool,
}

impl Place {
    fn settle(&mut self) -> bool {
        if self.settled {
            return false;
        }
        self.settled = true;
        let mut line = lock(&self.line);
        if self.turn.granted.load(Ordering::SeqCst) {
            return true;
        }
        line.waiting
            .retain(|queued| !Arc::ptr_eq(queued, &self.turn));
        // Whoever it held back may fit now.
        line.grant();
        false
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        // Bytes handed to work that has gone go straight on.
        if self.settle() {
            drop(HeldBytes {
                line: Arc::clone(&self.line),
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

impl Drop for HeldBytes {
    fn drop(&mut self) {
        let mut line = lock(&self.line);
        line.free += self.bytes;
        line.grant();
    }
}

/// The line's counts and waiters change in one step each under its lock, so
/// a holder that panicked left them whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
