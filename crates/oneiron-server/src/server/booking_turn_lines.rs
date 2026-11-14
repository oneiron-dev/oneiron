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
    lines: Mutex<HashMap<SessionKey, Line>>,
}

/// One window's line: a semaphore of one permit, which tokio hands out in
/// the order it was asked for, and how many requests are in the line,
/// waiting or at its head.
struct Line {
    turn: Arc<Semaphore>,
    members: usize,
}

/// A request's membership of its window's line, from the moment it joins
/// until it is dropped, by whichever way its request ends: answered, past
/// its deadline, or cancelled while it waited (a client gone before the
/// line reached it). The last member out forgets the line.
struct LineMembership<'a> {
    lines: &'a BookingTurnLines,
    window: SessionKey,
}

/// A request's place at the head of its window's line. It is held while the
/// request runs admission, waits for the window and writes what it was
/// admitted for; dropping it lets the next request in the line go on.
pub(crate) struct LinePlace<'a> {
    // Fields drop in this order: the head passes to the next request in the
    // line before this request's membership leaves it.
    _head: OwnedSemaphorePermit,
    _membership: LineMembership<'a>,
}

impl BookingTurnLines {
    /// Joins `window`'s line and waits there, until `deadline`, for every
    /// request ahead to be answered. `None` when the deadline came first: the
    /// request has left the line, holding nothing. A request dropped while
    /// it waits leaves the line too.
    pub(crate) async fn join(
        &self,
        window: SessionKey,
        deadline: Instant,
    ) -> Option<LinePlace<'_>> {
        let (membership, turn) = {
            let mut lines = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
            let line = lines.entry(window).or_insert_with(|| Line {
                turn: Arc::new(Semaphore::new(1)),
                members: 0,
            });
            line.members = line.members.saturating_add(1);
            (
                LineMembership {
                    lines: self,
                    window,
                },
                Arc::clone(&line.turn),
            )
        };
        match tokio::time::timeout_at(deadline, turn.acquire_owned()).await {
            Ok(Ok(head)) => Some(LinePlace {
                _head: head,
                _membership: membership,
            }),
            // The deadline came first, or the line closed (it never does):
            // the membership leaves the line as it drops here.
            Ok(Err(_)) | Err(_) => None,
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
}

impl Drop for LineMembership<'_> {
    fn drop(&mut self) {
        let mut lines = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(line) = lines.get_mut(&self.window) {
            line.members = line.members.saturating_sub(1);
            if line.members == 0 {
                lines.remove(&self.window);
            }
        }
    }
}
