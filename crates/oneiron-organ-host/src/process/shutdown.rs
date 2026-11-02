//! A call the host's mesh stop cancels (FIX 4756): told with the protocol's
//! shutdown reason, as a deadline tells it, and stopped with its process
//! once its grace ends unanswered. Its wait for a seat ends with the stop.

use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_protocol::CancelReason;

use super::{CallFailure, OrganProcess, lock};

impl OrganProcess {
    /// Cancels call `id` for the host's stop. A reply within `grace` ends
    /// the call as the organ answered; with none, the call's entry goes and
    /// the process is stopped, so its waiting thread ends now rather than at
    /// the call's own deadline.
    pub(crate) fn interrupt(&self, id: u64, grace: Duration) {
        if !self.inbox.in_flight(id) {
            return;
        }
        let until = Instant::now() + grace;
        self.cancel(id, CancelReason::Shutdown, until);
        loop {
            let left = until.saturating_duration_since(Instant::now());
            {
                let mut pending = lock(&self.inbox.pending);
                // The reader takes a call's entry when its reply comes.
                if !pending.contains_key(&id) {
                    return;
                }
                if left.is_zero() {
                    pending.remove(&id);
                    drop(pending);
                    self.stop();
                    return;
                }
            }
            thread::sleep(left.min(Duration::from_millis(5)));
        }
    }

    /// Wakes every call waiting for a seat, so each sees the stop.
    pub(crate) fn wake_seats(&self) {
        self.seats.freed.notify_all();
    }
}

/// A wait for a seat goes on only while the host's stop has not cancelled
/// its work: then it ends, as a seat that stayed taken does.
pub(super) fn seat_open() -> Result<(), CallFailure> {
    if crate::shutdown::interrupted() {
        Err(CallFailure::Busy)
    } else {
        Ok(())
    }
}

/// Call `id` went out on this thread: the stop's cancel reaches it.
pub(super) fn sent(id: u64) {
    crate::shutdown::sent(id);
}
