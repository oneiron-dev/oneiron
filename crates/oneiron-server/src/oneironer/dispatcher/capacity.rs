//! Room in the dispatcher's pending caps, as owned claims (FIX 6755).
//!
//! A caller holds a [`DispatchClaim`] for one call in its class from the
//! moment the class has room until the call is queued. A claim that has to
//! wait enters its class's fair queue under its caller ([`super::fair`],
//! FIX 9519) and takes room only at its turn: callers in turn, oldest first
//! within each. A blocking caller waits on the scheduler's condvar; the
//! tagging coordinator awaits its class's own signal, its waiter registered
//! before its turn and room are tested, holding no lock, no store
//! transaction and no admission while it waits, and a wait it drops leaves
//! the queue at once. A claim dropped unused gives its room back and wakes
//! both kinds of waiter; a
//! submitted one gives it back exactly once, when its call is answered or
//! stranded. The answer is a oneshot the coordinator awaits and a blocking
//! caller polls on its own thread. Nothing here refuses or times out.

use std::sync::{Arc, PoisonError};
use std::time::Instant;

use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, ExtractionCaller, ExtractionWork,
};
use tokio::sync::{Notify, oneshot};

use super::policy::{BULK_PENDING_CAP, LIVE_PENDING_CAP};
use super::{DISPATCH_TOOL, Job, NO_WORKER, Shared, answer, failure};

/// The pending cap of `work`'s class: the policy's, the only one.
pub(crate) fn pending_cap(work: ExtractionWork) -> usize {
    match work {
        ExtractionWork::Live => LIVE_PENDING_CAP,
        ExtractionWork::Bulk => BULK_PENDING_CAP,
    }
}

/// Room for one call in its class, claimed and not yet queued.
pub(crate) struct DispatchClaim {
    shared: Arc<Shared>,
    work: ExtractionWork,
    /// Whether it still holds its room: dropped so, it gives it back.
    holds_room: bool,
}

impl DispatchClaim {
    /// A claim on room already counted in `work`'s class.
    fn holding(shared: &Arc<Shared>, work: ExtractionWork) -> Self {
        Self {
            shared: Arc::clone(shared),
            work,
            holds_room: true,
        }
    }

    /// Queues the call under this claim; it never waits. Its window is
    /// counted first, once, with no lock held (FIX 6755): a call whose
    /// window cannot be built fails as its infer would. A call no worker
    /// that can run it is ready or coming for, or one a closed dispatcher
    /// would never run, is answered at once. The room is the call's from
    /// here: given back when it is answered or stranded, never by this claim.
    pub(crate) fn submit(self, input: EncoderInput) -> Completion {
        let counted = self.shared.count(&input);
        self.submit_counted(input, counted)
    }

    /// [`Self::submit`] with the window already `counted` by the caller, on
    /// its own blocking unit: the tagging coordinator counts it there, so the
    /// tokenizer encode never runs on its async task (FIX 7331).
    pub(crate) fn submit_counted(
        mut self,
        input: EncoderInput,
        counted: oneiron::Result<usize>,
    ) -> Completion {
        self.holds_room = false;
        let (reply, completion) = oneshot::channel();
        let job = Job {
            input,
            work: self.work,
            window: counted.as_ref().copied().unwrap_or(0),
            queued_at: Instant::now(),
            reply,
        };
        let unqueued = match counted {
            Ok(_) => {
                let queued = self.shared.lock().queue(job);
                queued
                    .err()
                    .map(|job| (job, failure(DISPATCH_TOOL, NO_WORKER)))
            }
            Err(error) => Some((job, error)),
        };
        self.shared.work.notify_all();
        if let Some((job, error)) = unqueued {
            *self.shared.lock().pending(job.work) -= 1;
            self.shared.room_freed([job.work]);
            answer(job, error);
        }
        Completion { answer: completion }
    }
}

impl Drop for DispatchClaim {
    /// An unused claim gives its room back and wakes its class's waiters.
    fn drop(&mut self) {
        if !self.holds_room {
            return;
        }
        *self.shared.lock().pending(self.work) -= 1;
        self.shared.room_freed([self.work]);
    }
}

/// The answer a queued call is owed.
pub(crate) struct Completion {
    answer: oneshot::Receiver<EncoderAttempt>,
}

impl Completion {
    /// The answer of the worker that ran the call, awaited with nothing held.
    pub(crate) async fn answer(self) -> EncoderAttempt {
        self.answer.await.unwrap_or_else(|_| closed())
    }

    /// Blocks this thread until the worker that ran the call answers. It
    /// polls the same oneshot here, so it never needs the runtime.
    pub(super) fn wait(self) -> EncoderAttempt {
        crate::ladder_poll::block_on(self.answer())
    }
}

/// The answer of a call whose dispatcher closed before any worker answered.
fn closed() -> EncoderAttempt {
    EncoderAttempt {
        execution: None,
        result: Err(failure(DISPATCH_TOOL, "the oneironer dispatcher closed")),
    }
}

/// Room for one call in `work`'s class for `caller`, on the caller's
/// thread. It waits its turn in the class's fair queue and, past the class's
/// pending cap, on the scheduler's condvar, the lock released, until room is
/// given back. It never refuses.
pub(super) fn claim_blocking(
    shared: &Arc<Shared>,
    work: ExtractionWork,
    caller: &ExtractionCaller,
) -> DispatchClaim {
    let cap = pending_cap(work);
    let mut scheduler = shared.lock();
    let ticket = scheduler.fair.enqueue(work, caller);
    while *scheduler.pending(work) >= cap || !scheduler.fair.is_next(work, ticket) {
        scheduler = shared
            .room
            .wait(scheduler)
            .unwrap_or_else(PoisonError::into_inner);
    }
    scheduler.fair.granted(work, ticket);
    *scheduler.pending(work) += 1;
    drop(scheduler);
    // The next claim's turn has come: it may find room too.
    shared.turn_passed(work);
    DispatchClaim::holding(shared, work)
}

/// [`claim_blocking`] for an async caller. It awaits its class's signal,
/// registered before its turn and room are tested, so a turn or room given
/// after the test still wakes it. The scheduler lock is taken only to test
/// and count, never across the await. Dropped before it resolves, it holds
/// no room and leaves the queue.
pub(super) async fn claim(
    shared: Arc<Shared>,
    work: ExtractionWork,
    caller: ExtractionCaller,
) -> DispatchClaim {
    let mut waiting = Waiting::enter(shared, work, &caller);
    loop {
        let shared = Arc::clone(&waiting.shared);
        let signal = shared.room_signal(work).notified();
        let mut signal = std::pin::pin!(signal);
        signal.as_mut().enable();
        if let Some(claim) = waiting.try_claim() {
            return claim;
        }
        signal.await;
    }
}

/// An async claim's place in its class's fair queue, until it takes room or
/// is dropped: a dropped wait leaves the queue and wakes the claims behind.
struct Waiting {
    shared: Arc<Shared>,
    work: ExtractionWork,
    ticket: u64,
    granted: bool,
}

impl Waiting {
    fn enter(shared: Arc<Shared>, work: ExtractionWork, caller: &ExtractionCaller) -> Self {
        let ticket = shared.lock().fair.enqueue(work, caller);
        Self {
            shared,
            work,
            ticket,
            granted: false,
        }
    }

    /// Room for its call, if its turn has come and the class is under its
    /// cap now.
    fn try_claim(&mut self) -> Option<DispatchClaim> {
        {
            let mut scheduler = self.shared.lock();
            if *scheduler.pending(self.work) >= pending_cap(self.work)
                || !scheduler.fair.is_next(self.work, self.ticket)
            {
                return None;
            }
            scheduler.fair.granted(self.work, self.ticket);
            *scheduler.pending(self.work) += 1;
        }
        self.granted = true;
        self.shared.turn_passed(self.work);
        Some(DispatchClaim::holding(&self.shared, self.work))
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if self.granted {
            return;
        }
        let withdrawn = self.shared.lock().fair.withdrawn(self.work, self.ticket);
        if withdrawn {
            self.shared.turn_passed(self.work);
        }
    }
}

impl Shared {
    /// The signal an async claim in `work`'s class waits on.
    fn room_signal(&self, work: ExtractionWork) -> &Notify {
        match work {
            ExtractionWork::Live => &self.live_room,
            ExtractionWork::Bulk => &self.bulk_room,
        }
    }

    /// A claim in `work`'s class took its turn or left the queue: the claim
    /// whose turn comes next may go.
    fn turn_passed(&self, work: ExtractionWork) {
        self.room_freed([work]);
    }

    /// Room was given back in each class of `freed`: wakes every blocking
    /// claim, and every async claim waiting in those classes.
    pub(super) fn room_freed(&self, freed: impl IntoIterator<Item = ExtractionWork>) {
        self.room.notify_all();
        let (mut live, mut bulk) = (false, false);
        for work in freed {
            match work {
                ExtractionWork::Live => live = true,
                ExtractionWork::Bulk => bulk = true,
            }
        }
        if live {
            self.live_room.notify_waiters();
        }
        if bulk {
            self.bulk_room.notify_waiters();
        }
    }
}
