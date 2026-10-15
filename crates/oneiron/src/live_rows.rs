//! Live work the engine holds open for its callers: message streams and live
//! text documents (rule 5: ARCH-0044 C5, OF-520).
//!
//! Each count is a row set far above fleet scale (ARCH-0079: 100 to 200
//! agents, many on one credential). Past its row the next opener waits its
//! turn; it is never refused for count. Waiters are served round-robin across
//! keys (an actor or a principal) and in arrival order within one key, so a
//! fleet that shares one key takes one turn a round like any other key. Each
//! wait ends at the wait row, a deadline: [`LiveWaitedOut`].
//!
//! A wait that begins when nobody waited crosses the row, and the row asks
//! the host's "is everything okay" question once for that crossing
//! ([`Vault::set_live_row_crossing`]). Every opener waits before it takes any
//! transaction, lock or lease, so a waiter holds nothing another needs.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::Vault;

/// A count of live work the engine bounds by a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveRow {
    /// Message streams open at once in one vault.
    MessageStreams,
    /// Text documents resident at once in one registry.
    LiveDocuments,
}

impl LiveRow {
    /// Every row: the list the check that none refuses for count reads.
    pub const ALL: [Self; 2] = [Self::MessageStreams, Self::LiveDocuments];

    /// The closed name the row is set and asked under.
    pub const fn key(self) -> &'static str {
        match self {
            Self::MessageStreams => "live.message_streams",
            Self::LiveDocuments => "live.documents",
        }
    }
}

/// The rows and the wait deadline in force for one vault. A host sets them
/// from its manifest ([`Vault::set_live_rows`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveRows {
    /// Message streams open at once before the next waits.
    pub message_streams: usize,
    /// Text documents resident at once before the next waits.
    pub live_documents: usize,
    /// How long one opener waits for its turn.
    pub wait: Duration,
}

impl LiveRows {
    /// Ten times ARCH-0079's 200 agents.
    pub const DEFAULT_MESSAGE_STREAMS: usize = 2_048;
    /// Ten times ARCH-0079's 200 agents.
    pub const DEFAULT_LIVE_DOCUMENTS: usize = 2_048;
    /// A request's timeout, not a limit.
    pub const DEFAULT_WAIT: Duration = Duration::from_secs(300);

    /// The bound `row` is set to.
    pub const fn bound(&self, row: LiveRow) -> usize {
        match row {
            LiveRow::MessageStreams => self.message_streams,
            LiveRow::LiveDocuments => self.live_documents,
        }
    }
}

impl Default for LiveRows {
    fn default() -> Self {
        Self {
            message_streams: Self::DEFAULT_MESSAGE_STREAMS,
            live_documents: Self::DEFAULT_LIVE_DOCUMENTS,
            wait: Self::DEFAULT_WAIT,
        }
    }
}

/// Where a crossed row asks: the row, what it is set to, and how much live
/// work held or waited when it was crossed. Nothing waits on the answer.
pub type LiveRowCrossing = Arc<dyn Fn(LiveRow, u64, u64) + Send + Sync>;

/// A wait for a turn that reached its deadline. Nothing was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("live work waited for its turn past its deadline")]
pub struct LiveWaitedOut {
    /// The row the work waited under.
    pub row: LiveRow,
}

/// One vault's rows and the host's crossing door.
#[derive(Default)]
pub(crate) struct LiveRowsCell {
    rows: RwLock<LiveRows>,
    crossing: RwLock<Option<LiveRowCrossing>>,
}

impl LiveRowsCell {
    fn rows(&self) -> LiveRows {
        *self.rows.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn ask(&self, row: LiveRow, bound: usize, observed: usize) {
        let crossing = self
            .crossing
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match crossing {
            Some(crossing) => crossing(row, bound as u64, observed as u64),
            None => tracing::warn!(
                kind = "limit_crossed",
                row = row.key(),
                bound,
                observed,
                "live work crossed its row and waits its turn; is everything okay?"
            ),
        }
    }
}

impl Vault {
    /// Sets this vault's live rows and wait deadline. Work already waiting
    /// keeps the deadline it started with; a bound takes effect at the next
    /// open and the next close.
    pub fn set_live_rows(&self, rows: LiveRows) {
        *self
            .live_rows
            .rows
            .write()
            .unwrap_or_else(PoisonError::into_inner) = rows;
    }

    /// The live rows in force.
    pub fn live_rows(&self) -> LiveRows {
        self.live_rows.rows()
    }

    /// Points this vault's row crossings at the host's question door. With
    /// none set, a crossing is logged.
    pub fn set_live_row_crossing(&self, crossing: Option<LiveRowCrossing>) {
        *self
            .live_rows
            .crossing
            .write()
            .unwrap_or_else(PoisonError::into_inner) = crossing;
    }
}

/// The fair line of one row: who holds a turn, and who waits for one.
pub(crate) struct LiveLine {
    row: LiveRow,
    queue: Arc<Mutex<Queue>>,
}

struct Queue {
    held: usize,
    /// The bound in force at the latest open.
    bound: usize,
    /// Each key's waiters, oldest first.
    waiting: HashMap<Vec<u8>, VecDeque<Arc<Waiter>>>,
    /// The keys with a waiter, in the order their turns come.
    turns: VecDeque<Vec<u8>>,
    /// Whether the crossing in progress has asked its question.
    asked: bool,
}

/// One waiting opener. A turn is handed over by setting `granted` under the
/// queue's lock, so an opener that gives up under the same lock either finds
/// its turn or is no longer in line.
#[derive(Default)]
struct Waiter {
    granted: Mutex<bool>,
    woken: Condvar,
}

/// One turn held. Dropping it hands the turn to the next waiter.
#[must_use = "live work holds its turn only as long as this is"]
pub(crate) struct LivePermit {
    queue: Arc<Mutex<Queue>>,
}

impl LiveLine {
    pub(crate) fn new(row: LiveRow) -> Self {
        Self {
            row,
            queue: Arc::new(Mutex::new(Queue {
                held: 0,
                bound: 1,
                waiting: HashMap::new(),
                turns: VecDeque::new(),
                asked: false,
            })),
        }
    }

    /// A turn for `key`'s work, now or at its turn, under `vault`'s row. The
    /// caller holds no transaction, lock or lease while this waits.
    pub(crate) fn enter(&self, vault: &Vault, key: &[u8]) -> Result<LivePermit, LiveWaitedOut> {
        let rows = vault.live_rows.rows();
        let bound = rows.bound(self.row).max(1);
        let waiter = {
            let mut queue = lock(&self.queue);
            queue.bound = bound;
            // A raised bound frees turns for those already waiting first.
            queue.grant();
            // Waiters remain only while every turn is held, so a free turn
            // means nobody is ahead.
            if queue.held < bound && queue.turns.is_empty() {
                queue.held += 1;
                return Ok(self.permit());
            }
            let waiter = Arc::new(Waiter::default());
            let line = queue.waiting.entry(key.to_vec()).or_default();
            let first_in_line = line.is_empty();
            line.push_back(Arc::clone(&waiter));
            if first_in_line {
                queue.turns.push_back(key.to_vec());
            }
            let first = !queue.asked;
            queue.asked = true;
            let observed = queue.held + queue.waiters();
            drop(queue);
            if first {
                vault.live_rows.ask(self.row, bound, observed);
            }
            waiter
        };
        let deadline = Instant::now() + rows.wait;
        let mut granted = lock(&waiter.granted);
        while !*granted {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            granted = waiter
                .woken
                .wait_timeout(granted, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        drop(granted);
        self.settle(&waiter, key)
            .then(|| self.permit())
            .ok_or(LiveWaitedOut { row: self.row })
    }

    /// Takes the turn handed to `waiter`, or leaves the line.
    fn settle(&self, waiter: &Arc<Waiter>, key: &[u8]) -> bool {
        let mut queue = lock(&self.queue);
        if *lock(&waiter.granted) {
            return true;
        }
        if let Some(line) = queue.waiting.get_mut(key) {
            line.retain(|queued| !Arc::ptr_eq(queued, waiter));
            if line.is_empty() {
                queue.waiting.remove(key);
                queue.turns.retain(|turn| turn != key);
            }
        }
        if queue.turns.is_empty() {
            queue.asked = false;
        }
        false
    }

    fn permit(&self) -> LivePermit {
        LivePermit {
            queue: Arc::clone(&self.queue),
        }
    }

    /// Openers waiting for a turn now.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        lock(&self.queue).waiters()
    }
}

impl Queue {
    fn waiters(&self) -> usize {
        self.waiting.values().map(VecDeque::len).sum()
    }

    /// The oldest waiter of the key whose turn it is.
    fn next(&mut self) -> Option<Arc<Waiter>> {
        let key = self.turns.pop_front()?;
        let line = self.waiting.get_mut(&key)?;
        let waiter = line.pop_front();
        if line.is_empty() {
            self.waiting.remove(&key);
        } else {
            self.turns.push_back(key);
        }
        waiter
    }

    /// Hands free turns to the waiters whose turn it is while the bound
    /// leaves room.
    fn grant(&mut self) {
        while self.held < self.bound
            && let Some(waiter) = self.next()
        {
            self.held += 1;
            *lock(&waiter.granted) = true;
            waiter.woken.notify_all();
        }
        if self.turns.is_empty() {
            self.asked = false;
        }
    }
}

impl Drop for LivePermit {
    fn drop(&mut self) {
        let mut queue = lock(&self.queue);
        queue.held = queue.held.saturating_sub(1);
        queue.grant();
    }
}

/// The queue's counts and lines change in one step each under its lock, so
/// a holder that panicked left them whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
