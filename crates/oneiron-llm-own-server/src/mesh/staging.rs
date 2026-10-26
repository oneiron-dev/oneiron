//! The bytes the model mesh holds for calls (FIX 8618, FIX 8619): bodies a
//! connection stages either way, replies waiting to be read, and stream
//! batches waiting for their reader. Each is booked on a [`StagingBudget`]
//! for its whole life, its map entry with it (an empty body too), before
//! its room is allocated, and the room is allocated fallibly.
//!
//! The budget is bytes, never a count. Work that finds it full waits in
//! arrival order; work larger than the whole budget waits until it runs
//! alone. Waiting only paces: nothing is dropped, no fixed timeout is
//! added, and the caller's own cancellation still ends the wait. Bytes a
//! booking grows by once it holds some are charged at once, never waited
//! for, so no holder waits on another; a budget owed past its total holds
//! back new work until it is paid. No map lock is held across a wait.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::{Carried, INLINE, PIECE, hash, lock};

/// The bytes a mesh service or transport books for its calls at once, all
/// its connections together, when its host names no other total
/// (CALLS: mesh staging default).
pub const DEFAULT_STAGING_BYTES: usize = 1 << 30;

/// The bytes one side of the model mesh may hold for its calls at once.
/// Clones share them.
#[derive(Clone)]
pub struct StagingBudget {
    inner: Arc<Budget>,
}

impl std::fmt::Debug for StagingBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingBudget")
            .field("total", &self.inner.total)
            .finish_non_exhaustive()
    }
}

impl Default for StagingBudget {
    fn default() -> Self {
        Self::new(DEFAULT_STAGING_BYTES)
    }
}

struct Budget {
    total: usize,
    state: Mutex<State>,
}

struct State {
    free: usize,
    /// Bytes charged past the free ones: freed bytes pay them first.
    owed: usize,
    /// Work waiting for bytes, oldest first.
    waiting: VecDeque<Arc<Turn>>,
}

/// One piece of waiting work and the bytes it wants, handed over by setting
/// `granted` under the state's lock.
struct Turn {
    bytes: usize,
    granted: AtomicBool,
    woken: Notify,
}

/// Bytes one piece of work holds; dropping it hands them on.
#[must_use = "bytes are booked only as long as this is held"]
pub(super) struct Booking {
    budget: Arc<Budget>,
    bytes: usize,
}

impl StagingBudget {
    /// A budget of `total` bytes (at least one).
    #[must_use]
    pub fn new(total: usize) -> Self {
        let total = total.max(1);
        Self {
            inner: Arc::new(Budget {
                total,
                state: Mutex::new(State {
                    free: total,
                    owed: 0,
                    waiting: VecDeque::new(),
                }),
            }),
        }
    }

    /// Books `bytes`, at once or at its turn: work behind a full budget
    /// waits in order, and work larger than the whole budget takes all of
    /// it, so it runs alone. Dropping the wait leaves the line.
    pub(super) async fn reserve(&self, bytes: usize) -> Booking {
        let take = bytes.min(self.inner.total);
        let turn = {
            let mut state = lock(&self.inner.state);
            if state.waiting.is_empty() && state.owed == 0 && state.free >= take {
                state.free -= take;
                return self.booking(take);
            }
            let turn = Arc::new(Turn {
                bytes: take,
                granted: AtomicBool::new(false),
                woken: Notify::new(),
            });
            state.waiting.push_back(Arc::clone(&turn));
            turn
        };
        let mut place = Place {
            budget: Arc::clone(&self.inner),
            turn: Arc::clone(&turn),
            settled: false,
        };
        loop {
            let woken = turn.woken.notified();
            if turn.granted.load(Ordering::SeqCst) {
                break;
            }
            woken.await;
        }
        place.settled = true;
        self.booking(take)
    }

    /// Books `bytes` now, whatever the budget holds: for bytes a call holds
    /// already, or grows by once it holds some.
    pub(super) fn charged(&self, bytes: usize) -> Booking {
        let mut booking = self.booking(0);
        self.charge(&mut booking, bytes);
        booking
    }

    /// Moves `booking` to `bytes` now: shrinking frees the rest, growing
    /// takes free bytes and owes the remainder, never waiting.
    pub(super) fn charge(&self, booking: &mut Booking, bytes: usize) {
        debug_assert!(Arc::ptr_eq(&booking.budget, &self.inner));
        let mut state = lock(&self.inner.state);
        if bytes <= booking.bytes {
            state.release(booking.bytes - bytes);
        } else {
            let extra = bytes - booking.bytes;
            let taken = extra.min(state.free);
            state.free -= taken;
            state.owed = state.owed.saturating_add(extra - taken);
        }
        booking.bytes = bytes;
    }

    fn booking(&self, bytes: usize) -> Booking {
        Booking {
            budget: Arc::clone(&self.inner),
            bytes,
        }
    }
}

impl State {
    /// Takes back `bytes` a holder let go: what is owed first, then free,
    /// then handed to the oldest waiters whose bytes fit.
    fn release(&mut self, bytes: usize) {
        let paid = bytes.min(self.owed);
        self.owed -= paid;
        self.free += bytes - paid;
        if self.owed > 0 {
            return;
        }
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

/// A place in line: dropped before its bytes were taken, it leaves the line,
/// or hands bytes it was granted straight on.
struct Place {
    budget: Arc<Budget>,
    turn: Arc<Turn>,
    settled: bool,
}

impl Drop for Place {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let mut state = lock(&self.budget.state);
        if self.turn.granted.load(Ordering::SeqCst) {
            state.release(self.turn.bytes);
            return;
        }
        state
            .waiting
            .retain(|queued| !Arc::ptr_eq(queued, &self.turn));
        // Whoever it held back may fit now.
        state.release(0);
    }
}

impl Drop for Booking {
    fn drop(&mut self) {
        lock(&self.budget.state).release(self.bytes);
    }
}

/// A body the mesh holds, with the bytes booked for it.
pub(super) struct BookedBody {
    pub(super) bytes: Vec<u8>,
    pub(super) booking: Booking,
}

impl BookedBody {
    /// `bytes` a call holds already (one that came inline in a message),
    /// charged for as long as it holds them.
    pub(super) fn charged(budget: &StagingBudget, bytes: Vec<u8>) -> Self {
        let booking = budget.charged(bytes.capacity());
        Self { bytes, booking }
    }

    /// Room for `len` bytes, booked first with `extra` bytes of bookkeeping
    /// beside it, then allocated fallibly.
    pub(super) async fn room(
        budget: &StagingBudget,
        len: usize,
        extra: usize,
    ) -> Result<Self, String> {
        let booking = budget.reserve(len.saturating_add(extra)).await;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| "this node has no memory for the body".to_owned())?;
        Ok(Self { bytes, booking })
    }
}

/// What one map entry holding `V` costs past its bytes: its key, its value
/// and the map's spare room for it.
const fn entry_cost<V>() -> usize {
    2 * (size_of::<[u8; 32]>() + size_of::<V>())
}

/// A body coming in, piece by piece (FIX 9323): its first piece waits its
/// turn for its own bytes and its entry, and each later piece's growth is
/// charged as it arrives, so a body never waits while it holds some and
/// never books bytes a peer only advertised. Its total, offsets and hash
/// are checked as it grows and once it is whole.
struct Incoming {
    total: u64,
    body: BookedBody,
}

/// The bodies one connection staged, each way, every one booked on the
/// side's budget until it is taken, read, or the connection goes.
pub(super) struct Staging {
    pub(super) budget: StagingBudget,
    incoming: Mutex<HashMap<[u8; 32], Incoming>>,
    outgoing: Mutex<HashMap<[u8; 32], Arc<BookedBody>>>,
}

impl Staging {
    pub(super) fn new(budget: StagingBudget) -> Self {
        Self {
            budget,
            incoming: Mutex::default(),
            outgoing: Mutex::default(),
        }
    }

    /// Takes one piece of a body a later message names. Its first piece
    /// books its own bytes and the body's entry, empty or not, waiting its
    /// turn when the budget is full; no lock is held while it waits. Each
    /// later piece grows the body by what it carries, charged at once,
    /// never waited for (FIX 9323).
    pub(super) async fn put(
        &self,
        named: [u8; 32],
        total: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        if offset == 0 && !lock(&self.incoming).contains_key(&named) {
            let body =
                BookedBody::room(&self.budget, bytes.len(), entry_cost::<Incoming>()).await?;
            let mut incoming = lock(&self.incoming);
            if incoming.contains_key(&named) {
                return Err("a staged piece out of order".into());
            }
            incoming.insert(named, Incoming { total, body });
        }
        let mut incoming = lock(&self.incoming);
        let held = incoming
            .get_mut(&named)
            .ok_or("a staged piece out of order")?;
        if held.total != total
            || held.body.bytes.len() as u64 != offset
            || offset.saturating_add(bytes.len() as u64) > total
        {
            return Err("a staged piece out of order".into());
        }
        let body = &mut held.body;
        if body.bytes.capacity() - body.bytes.len() < bytes.len() {
            body.bytes
                .try_reserve(bytes.len())
                .map_err(|_| "this node has no memory for the body".to_owned())?;
            let room = body
                .bytes
                .capacity()
                .saturating_add(entry_cost::<Incoming>());
            self.budget.charge(&mut body.booking, room);
        }
        body.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// The body a message names, its booking with it: one staged here is
    /// taken whole, one that came inline is charged as it is.
    pub(super) fn take(&self, carried: Carried) -> Result<BookedBody, String> {
        match carried {
            Carried::Inline(bytes) => Ok(BookedBody::charged(&self.budget, bytes)),
            Carried::Staged { hash: named, len } => {
                let staged = lock(&self.incoming)
                    .remove(&named)
                    .filter(|held| held.body.bytes.len() as u64 == len)
                    .ok_or("staged body missing or incomplete")?;
                if hash(&staged.body.bytes) != named {
                    return Err("staged body does not match its hash".into());
                }
                Ok(staged.body)
            }
        }
    }

    /// Offers a reply body: inline, its booking handed back for the caller
    /// to hold until the reply is sent, or staged, booked until its last
    /// piece is read or the connection goes.
    pub(super) fn offer(&self, body: BookedBody) -> (Carried, Option<Booking>) {
        if body.bytes.len() <= INLINE {
            let BookedBody { bytes, booking } = body;
            return (Carried::Inline(bytes), Some(booking));
        }
        let named = hash(&body.bytes);
        let len = body.bytes.len() as u64;
        lock(&self.outgoing).insert(named, Arc::new(body));
        (Carried::Staged { hash: named, len }, None)
    }

    /// One piece of a staged reply, charged until it is sent. The last piece
    /// takes the reply out; its booking goes once the piece is copied.
    pub(super) fn piece(&self, named: [u8; 32], offset: u64) -> Result<BookedBody, String> {
        let body = lock(&self.outgoing)
            .get(&named)
            .cloned()
            .ok_or("no such staged body")?;
        let start = usize::try_from(offset)
            .ok()
            .filter(|start| *start < body.bytes.len())
            .ok_or("a piece past the end")?;
        let end = start.saturating_add(PIECE).min(body.bytes.len());
        let mut piece = Vec::new();
        piece
            .try_reserve_exact(end - start)
            .map_err(|_| "this node has no memory for the piece".to_owned())?;
        piece.extend_from_slice(&body.bytes[start..end]);
        if end == body.bytes.len() {
            // The last piece: the asking side has it all.
            lock(&self.outgoing).remove(&named);
        }
        Ok(BookedBody::charged(&self.budget, piece))
    }
}

/// What one outgoing reply entry costs past its bytes.
pub(super) const OUTGOING_ENTRY: usize = entry_cost::<Arc<BookedBody>>() + size_of::<BookedBody>();
