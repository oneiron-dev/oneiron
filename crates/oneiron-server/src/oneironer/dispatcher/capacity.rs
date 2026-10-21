//! Room in the dispatcher's pending caps, as owned claims (FIX 6755).
//!
//! A caller holds a [`DispatchClaim`] for one call in its class from the
//! moment the class has room until the call is queued. A blocking caller
//! waits for room on the scheduler's condvar; the tagging coordinator awaits
//! it on its class's own signal, its waiter registered before room is tested,
//! holding no lock, no store transaction and no admission while it waits. A
//! claim dropped unused gives its room back and wakes both kinds of waiter; a
//! submitted one gives it back exactly once, when its call is answered or
//! stranded. The answer is a oneshot the coordinator awaits and a blocking
//! caller polls on its own thread. Nothing here refuses or times out.

use std::sync::{Arc, PoisonError};
use std::time::Instant;

use oneiron::memory::extraction::{EncoderAttempt, EncoderInput, ExtractionWork};
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
    pub(crate) fn submit(mut self, input: EncoderInput) -> Completion {
        self.holds_room = false;
        let (reply, completion) = oneshot::channel();
        let counted = self.shared.count(&input);
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

/// Room for one call in `work`'s class, on the caller's thread. Past the
/// class's pending cap it waits on the scheduler's condvar, the lock
/// released, until room is given back. It never refuses.
pub(super) fn claim_blocking(shared: &Arc<Shared>, work: ExtractionWork) -> DispatchClaim {
    let cap = pending_cap(work);
    let mut scheduler = shared.lock();
    while *scheduler.pending(work) >= cap {
        scheduler = shared
            .room
            .wait(scheduler)
            .unwrap_or_else(PoisonError::into_inner);
    }
    *scheduler.pending(work) += 1;
    drop(scheduler);
    DispatchClaim::holding(shared, work)
}

/// [`claim_blocking`] for an async caller. Past the cap it awaits its class's
/// signal, registered before room is tested so room given back after the test
/// still wakes it. The scheduler lock is taken only to test and count room,
/// never across the await. Dropped before it resolves, it holds no room.
pub(super) async fn claim(shared: Arc<Shared>, work: ExtractionWork) -> DispatchClaim {
    loop {
        let signal = shared.room_signal(work).notified();
        let mut signal = std::pin::pin!(signal);
        signal.as_mut().enable();
        if let Some(claim) = try_claim(&shared, work) {
            return claim;
        }
        signal.await;
    }
}

/// Room for one call in `work`'s class, if the class is under its cap now.
fn try_claim(shared: &Arc<Shared>, work: ExtractionWork) -> Option<DispatchClaim> {
    {
        let mut scheduler = shared.lock();
        if *scheduler.pending(work) >= pending_cap(work) {
            return None;
        }
        *scheduler.pending(work) += 1;
    }
    Some(DispatchClaim::holding(shared, work))
}

impl Shared {
    /// The signal an async claim in `work`'s class waits on.
    fn room_signal(&self, work: ExtractionWork) -> &Notify {
        match work {
            ExtractionWork::Live => &self.live_room,
            ExtractionWork::Bulk => &self.bulk_room,
        }
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
