//! The supervisor's copy of a stream socket's guest end (FIX 6788).
//!
//! `socket()` takes the copy before the notification's ADDFD gives the
//! guest its end, so no later call takes a descriptor out of a guest
//! process. The copy shares the guest end's open file description: through
//! it the supervisor reads the mode the guest set (`O_NONBLOCK`) and the
//! socket's send timeout (`SO_SNDTIMEO`). A listen moves the copy into the
//! listener, which reads its readiness tokens back through it. A connect
//! that succeeds drops it: held on, it would keep the peer from reading the
//! end once the guest closes its socket. The copy holds its own room on the
//! host floor ([`CONTROL`]), which moves with it.

use super::{Socket, State};
use crate::HostNetPermit;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// What the copy holds of the host floor while it lives, as (descriptors,
/// workers): the copy itself.
const CONTROL: (usize, usize) = (1, 0);

/// A close-on-exec copy of a stream socket's guest end, with its room on
/// the host floor.
pub(super) struct Control {
    guest: OwnedFd,
    _charge: HostNetPermit,
}

impl Control {
    /// Copies `guest` once its room on the host floor is held. A full floor
    /// is the floor's named back-pressure.
    pub(super) fn new(state: &State, guest: &UnixStream) -> io::Result<Self> {
        let (fds, workers) = CONTROL;
        let charge = state.relay.host_net_floor().acquire(fds, workers)?;
        Ok(Self {
            guest: guest.try_clone()?.into(),
            _charge: charge,
        })
    }

    /// Whether the guest put its socket in nonblocking mode.
    pub(super) fn nonblocking(&self) -> bool {
        // SAFETY: F_GETFL only reads the status flags of a live descriptor.
        let flags = unsafe { libc::fcntl(self.guest.as_raw_fd(), libc::F_GETFL) };
        flags >= 0 && flags & libc::O_NONBLOCK != 0
    }

    /// The send timeout the guest set on its socket (`SO_SNDTIMEO`). Zero
    /// is no timeout: `None`.
    fn send_timeout(&self) -> io::Result<Option<Duration>> {
        let mut value = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut size = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `size` bytes into the live
        // timeval and its length into the live `size`.
        let read = unsafe {
            libc::getsockopt(
                self.guest.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                (&mut value as *mut libc::timeval).cast(),
                &mut size,
            )
        };
        if read != 0 {
            return Err(io::Error::last_os_error());
        }
        let seconds = Duration::from_secs(u64::try_from(value.tv_sec).unwrap_or(0));
        let micros = Duration::from_micros(u64::try_from(value.tv_usec).unwrap_or(0));
        // A timeout too long to count is no timeout.
        Ok(seconds
            .checked_add(micros)
            .filter(|timeout| !timeout.is_zero()))
    }
}

impl AsRawFd for Control {
    fn as_raw_fd(&self) -> RawFd {
        self.guest.as_raw_fd()
    }
}

impl Socket {
    /// How a connect on this socket waits, read when the call starts:
    /// whether the guest's end is in nonblocking mode, and the monotonic
    /// deadline its send timeout sets (`None`: no deadline). A socket with
    /// no copy left listens or is connected: `EISCONN`.
    pub(super) fn connect_mode(&self) -> io::Result<(bool, Option<Instant>)> {
        let control = self
            .control
            .lock()
            .map_err(|_| io::Error::other("fence state poisoned"))?;
        let control = control
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EISCONN))?;
        let deadline = control
            .send_timeout()?
            .and_then(|timeout| Instant::now().checked_add(timeout));
        Ok((control.nonblocking(), deadline))
    }

    /// Drops the copy of a socket that is now connected.
    pub(super) fn release_control(&self) {
        if let Ok(mut control) = self.control.lock() {
            control.take();
        }
    }
}
