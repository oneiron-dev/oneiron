//! Fair room and a bulk share (FIX 9519).
//!
//! Claims that wait for room in a class are served in turn across callers
//! and oldest first within each ([`FairClaims`]): a caller with a long
//! backlog takes one claim, then every other caller waiting takes one,
//! before it takes its next. A claim dropped while it waits, its caller
//! gone, leaves the queue at once and wakes the claims behind it. Nothing
//! waits on a clock and nothing is refused: the pending caps stay pacing
//! alone, and every waiting claim is owed its room.
//!
//! Live goes before bulk at every unit, but not for ever: after
//! [`LIVE_STREAK_CAP`] live units in a row, a worker that holds a waiting
//! bulk call takes one bulk unit before its next live one ([`next_class`]).
//! A running unit is still never pre-empted.

use std::collections::VecDeque;

use oneiron::memory::extraction::{ExtractionCaller, ExtractionWork};

/// Live units the workers take in a row while a bulk call one of them could
/// run waits; the next unit then goes to bulk.
pub(super) const LIVE_STREAK_CAP: usize = 8;

/// One claim waiting for room.
struct Ticket {
    id: u64,
    caller: ExtractionCaller,
}

/// The claims waiting for room in one class, and the callers they belong
/// to in the order their turns come round.
#[derive(Default)]
struct ClassQueue {
    tickets: VecDeque<Ticket>,
    /// Each caller with a waiting claim, once, in turn order.
    order: VecDeque<ExtractionCaller>,
}

impl ClassQueue {
    /// The claim whose turn it is: the oldest of the caller at the front.
    fn head(&self) -> Option<u64> {
        let caller = self.order.front()?;
        self.tickets
            .iter()
            .find(|ticket| ticket.caller == *caller)
            .map(|ticket| ticket.id)
    }

    /// Takes claim `id` out; whether it was waiting. Its caller's turn
    /// passes to the next caller when `served`, and leaves the order once it
    /// has no claim left.
    fn take(&mut self, id: u64, served: bool) -> bool {
        let Some(place) = self.tickets.iter().position(|ticket| ticket.id == id) else {
            return false;
        };
        let Some(ticket) = self.tickets.remove(place) else {
            return false;
        };
        let more = self
            .tickets
            .iter()
            .any(|other| other.caller == ticket.caller);
        if let Some(turn) = self
            .order
            .iter()
            .position(|caller| *caller == ticket.caller)
        {
            if !more {
                self.order.remove(turn);
            } else if served
                && turn == 0
                && let Some(front) = self.order.pop_front()
            {
                self.order.push_back(front);
            }
        }
        true
    }
}

/// The waiting claims of both classes, under the scheduler lock.
#[derive(Default)]
pub(super) struct FairClaims {
    next_id: u64,
    live: ClassQueue,
    bulk: ClassQueue,
}

impl FairClaims {
    fn class(&mut self, work: ExtractionWork) -> &mut ClassQueue {
        match work {
            ExtractionWork::Live => &mut self.live,
            ExtractionWork::Bulk => &mut self.bulk,
        }
    }

    /// Enters a claim of `caller`'s in `work`'s class; its ticket.
    pub(super) fn enqueue(&mut self, work: ExtractionWork, caller: &ExtractionCaller) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let class = self.class(work);
        if !class.order.contains(caller) {
            class.order.push_back(caller.clone());
        }
        class.tickets.push_back(Ticket {
            id,
            caller: caller.clone(),
        });
        id
    }

    /// Whether claim `id` is the one whose turn it is in `work`'s class.
    pub(super) fn is_next(&self, work: ExtractionWork, id: u64) -> bool {
        let class = match work {
            ExtractionWork::Live => &self.live,
            ExtractionWork::Bulk => &self.bulk,
        };
        class.head() == Some(id)
    }

    /// Claim `id` took its room: its caller's turn passes on.
    pub(super) fn granted(&mut self, work: ExtractionWork, id: u64) {
        self.class(work).take(id, true);
    }

    /// Claim `id` stopped waiting before it took room: it leaves the queue.
    pub(super) fn withdrawn(&mut self, work: ExtractionWork, id: u64) -> bool {
        self.class(work).take(id, false)
    }
}

/// The class worker's next unit comes from: live, unless `streak` live units
/// have run in a row and `bulk_held`, a bulk call the worker holds, waits.
pub(super) fn next_class(streak: usize, bulk_held: bool) -> ExtractionWork {
    if streak >= LIVE_STREAK_CAP && bulk_held {
        ExtractionWork::Bulk
    } else {
        ExtractionWork::Live
    }
}
