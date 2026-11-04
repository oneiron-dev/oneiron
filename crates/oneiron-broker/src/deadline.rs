//! One call's deadline (FIX 8559). It starts when the broker accepts the
//! call and bounds everything after it: the wait for a slot, the frame read,
//! the provider send and every reply write. Its length is the send policy's
//! timeout and one frame allowance, [`FRAME_DEADLINE`].

use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::time::Instant;

/// How long a peer has to deliver its frame, and to take each reply write:
/// the ceiling of each one, inside the call's deadline.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(10);

/// How far ahead a deadline lies whose length the clock cannot add: tokio's
/// own reach for such a sleep.
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

/// One call's deadline: the send policy's timeout, then one frame allowance,
/// from the moment the broker accepted the call.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallDeadline {
    /// When the call's last reply write must have ended.
    end: Instant,
}

impl CallDeadline {
    /// A deadline that starts now, for a send policy whose timeout is
    /// `timeout`.
    pub(crate) fn start(timeout: Duration) -> Self {
        let now = Instant::now();
        let length = timeout.saturating_add(FRAME_DEADLINE);
        Self {
            end: now.checked_add(length).unwrap_or(now + FAR_FUTURE),
        }
    }

    /// When the wait for a slot and the send must have ended: one frame
    /// allowance before the end, so a call out of time still has its frame
    /// read and its answer written.
    pub(crate) fn send_by(self) -> Instant {
        self.end.checked_sub(FRAME_DEADLINE).unwrap_or(self.end)
    }

    /// The send's time left, or `None` once it is gone: the call is then
    /// answered as timed out, and nothing is sent.
    pub(crate) fn send_left(self) -> Option<Duration> {
        Some(self.send_by().saturating_duration_since(Instant::now()))
            .filter(|left| !left.is_zero())
    }

    /// When one frame read or reply write must have ended: within its own
    /// allowance, and never past the end.
    pub(crate) fn frame_by(self) -> Instant {
        (Instant::now() + FRAME_DEADLINE).min(self.end)
    }
}

/// One write to the daemon, within its frame allowance and the call's
/// `deadline`.
pub(crate) async fn within(
    deadline: CallDeadline,
    write: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    tokio::time::timeout_at(deadline.frame_by(), write)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}
