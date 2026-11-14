//! The lines authenticated booking requests wait in (ARCH-0062
//! #booking-turn-divergence): one first-in, first-out line per booking
//! window, so no request takes a window ahead of a request that waited on it
//! first. The work past a bound waits in a fair queue with a deadline
//! (ARCH-0044 C5), as the permit queues do.
//!
//! The one window an authenticated request still waits on is its page
//! session's active-hold cap (`booking_anti_abuse::guards::enforce_hold`):
//! since FIX 128-131 it spends none of the per-minute windows, and its
//! quarantine admission is never rate limited. A line is keyed by that page
//! session ([`SessionKey`], bound to the page). Nothing here is persisted, and
//! a line nobody is in is forgotten.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::booking::SessionKey;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Every booking window some authenticated request is in line for.
#[derive(Default)]
pub(crate) struct BookingTurnLines {
    /// One line per window: a semaphore of one permit, which tokio hands out
    /// in the order it was asked for.
    lines: Mutex<HashMap<SessionKey, Arc<Semaphore>>>,
}

/// A request's place at the head of its window's line. It is held while the
/// request runs admission, waits for the window and writes what it was
/// admitted for; dropping it lets the next request in the line go on.
pub(crate) struct LinePlace<'a> {
    lines: &'a BookingTurnLines,
    window: SessionKey,
    head: Option<OwnedSemaphorePermit>,
}

impl BookingTurnLines {
    /// Joins `window`'s line and waits there, until `deadline`, for every
    /// request ahead to be answered. `None` when the deadline came first: the
    /// request has left the line, holding nothing.
    pub(crate) async fn join(
        &self,
        window: SessionKey,
        deadline: Instant,
    ) -> Option<LinePlace<'_>> {
        let line = {
            let mut lines = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                lines
                    .entry(window)
                    .or_insert_with(|| Arc::new(Semaphore::new(1))),
            )
        };
        // The wait owns its handle on the line, and drops it when it ends.
        let waited = tokio::time::timeout_at(deadline, line.acquire_owned()).await;
        match waited {
            Ok(Ok(head)) => Some(LinePlace {
                lines: self,
                window,
                head: Some(head),
            }),
            // The deadline came first, or the line closed (it never does):
            // the waiter's handle on the line went with its wait.
            Ok(Err(_)) | Err(_) => {
                self.forget_if_empty(window);
                None
            }
        }
    }

    /// How many windows have a line: the test door's view of what is held.
    #[cfg(oneiron_test_support)]
    pub(crate) fn held(&self) -> usize {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Forgets `window`'s line once nobody holds or waits on it: the map's
    /// own handle is then the only one. A request joining takes its handle
    /// under the same lock, so a line it joins is never forgotten under it.
    fn forget_if_empty(&self, window: SessionKey) {
        let mut lines = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
        if lines
            .get(&window)
            .is_some_and(|line| Arc::strong_count(line) == 1)
        {
            lines.remove(&window);
        }
    }
}

impl Drop for LinePlace<'_> {
    fn drop(&mut self) {
        // The next request in the line takes the head before the line is
        // checked for anyone left in it.
        drop(self.head.take());
        self.lines.forget_if_empty(self.window);
    }
}
