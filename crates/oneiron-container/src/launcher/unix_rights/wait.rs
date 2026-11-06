//! The wait of a brokered call on its socket, and the send that waits
//! (FIX 6185).
//!
//! The launcher sends and receives without waiting. When the socket is not
//! ready and the guest's call may wait, the launcher polls the socket in
//! slices of [`socket_lifetime::SOCKET_INVENTORY_EVERY`] and checks after
//! each that the call is still live. So a call that ended waits no more,
//! and the launcher keeps nothing for it. The socket's timeout bounds the
//! wait as it bounds the guest's own call, and so does a recvmmsg's own
//! timeout after its first message.

use super::{Call, Outgoing, rebuild};
use crate::{linux, socket_lifetime};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// How a wait ended.
pub(super) enum Waited {
    /// The socket reports what the call waits for, an error or an end: the
    /// call tries again.
    Ready,
    /// The guest's call ended: it takes nothing more and is answered no
    /// more.
    Ended,
}

/// The wait of one guest call on its socket, in one direction.
pub(super) struct Wait {
    /// POLLIN for a receive, POLLOUT for a send, and zero for a send to a
    /// name: no poll sees that receiver's queue, so the call tries again
    /// after each slice.
    events: i16,
    /// When the socket's timeout runs out, counted from the wait's start,
    /// or the call's own deadline when that comes first: `None` without
    /// either.
    deadline: Option<Instant>,
}

impl Wait {
    /// A wait for `events`, bounded by the socket's timeout `option`
    /// (SO_RCVTIMEO or SO_SNDTIMEO) and by the call's own deadline `limit`.
    pub(super) fn new(
        socket: &OwnedFd,
        events: i16,
        option: i32,
        limit: Option<Instant>,
    ) -> io::Result<Self> {
        let expires =
            timeout(socket, option)?.and_then(|timeout| Instant::now().checked_add(timeout));
        let deadline = [expires, limit].into_iter().flatten().min();
        Ok(Self { events, deadline })
    }

    /// Waits until `socket` is ready, one slice at a time; after each slice
    /// the call must still be live. A wait for no events ends after one
    /// slice, or at an error or an end. Past the deadline it answers EAGAIN,
    /// as the kernel answers a call whose timeout ran out.
    pub(super) fn ready(
        &self,
        listener: &OwnedFd,
        id: u64,
        socket: &OwnedFd,
    ) -> io::Result<Waited> {
        loop {
            let mut slice = socket_lifetime::SOCKET_INVENTORY_EVERY;
            if let Some(deadline) = self.deadline {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::from_raw_os_error(libc::EAGAIN));
                }
                slice = slice.min(left);
            }
            let mut poll = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: self.events,
                revents: 0,
            };
            // Whole milliseconds, rounded up: a slice never ends early.
            let milliseconds = slice.as_nanos().div_ceil(1_000_000) as i32;
            // SAFETY: poll reads and writes one live pollfd.
            let polled = unsafe { libc::poll(&mut poll, 1, milliseconds) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            if linux::valid(listener.as_raw_fd(), id).is_err() {
                return Ok(Waited::Ended);
            }
            if polled > 0 || self.events == 0 {
                return Ok(Waited::Ready);
            }
        }
    }
}

impl Outgoing {
    /// Sends the copy on the launcher's duplicate of the guest's socket,
    /// with the guest's flags, and returns the length sent: `None` once the
    /// call ended while it waited. When the socket is full and the guest's
    /// call may wait (`blocking`), it waits as that call would, and a
    /// stream that took part of the message takes the rest. The copies and
    /// the witness's write end close as it returns: once the message is
    /// queued, only the queue holds the witness.
    pub(super) fn transmit(
        self,
        call: &Call<'_>,
        listener: &OwnedFd,
        flags: i32,
        blocking: bool,
    ) -> io::Result<Option<usize>> {
        let witness = self.witness.as_ref().map(AsRawFd::as_raw_fd);
        let control = rebuild(&self.control, &self.copies, witness);
        let events = if self.name.is_empty() {
            libc::POLLOUT
        } else {
            0
        };
        let wait = if blocking {
            Some(Wait::new(&call.socket, events, libc::SO_SNDTIMEO, None)?)
        } else {
            None
        };
        let mut sent = 0;
        loop {
            // The descriptors go with the first part a stream takes.
            let rights: &[u8] = if sent == 0 { &control } else { &[] };
            let waited =
                match send_part(&call.socket, &self.bytes[sent..], &self.name, rights, flags) {
                    Ok(length) => {
                        sent += length;
                        if sent == self.bytes.len() || wait.is_none() {
                            return Ok(Some(sent));
                        }
                        Ok(Waited::Ready)
                    }
                    Err(error) => match &wait {
                        Some(wait) if error.kind() == io::ErrorKind::WouldBlock => {
                            wait.ready(listener, call.n.id, &call.socket)
                        }
                        _ => Err(error),
                    },
                };
            match waited {
                Ok(Waited::Ready) => {}
                Ok(Waited::Ended) => return Ok(None),
                // A stream that took a part answers its length, as the
                // kernel does.
                Err(_) if sent > 0 => return Ok(Some(sent)),
                Err(error) => return Err(error),
            }
        }
    }
}

/// One sendmsg of `bytes` to `name` with `control`, that never waits; it
/// returns the length sent.
fn send_part(
    socket: &OwnedFd,
    bytes: &[u8],
    name: &[u8],
    control: &[u8],
    flags: i32,
) -> io::Result<usize> {
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: a zeroed msghdr is a valid empty header.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !name.is_empty() {
        message.msg_name = name.as_ptr() as *mut libc::c_void;
        message.msg_namelen = name.len() as libc::socklen_t;
    }
    if !control.is_empty() {
        message.msg_control = control.as_ptr() as *mut libc::c_void;
        message.msg_controllen = control.len();
    }
    // SAFETY: every pointer references live launcher storage of the stated
    // length; the kernel only reads it. MSG_NOSIGNAL keeps a closed peer's
    // SIGPIPE from the launcher.
    let sent = unsafe {
        libc::sendmsg(
            socket.as_raw_fd(),
            &message,
            flags | libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sent as usize)
}

/// Whether the guest's call may wait: its flags hold no MSG_DONTWAIT, and
/// the socket is not in nonblocking mode. The launcher's copy shares the
/// guest's open file description, and with it its mode.
pub(super) fn may_wait(socket: &OwnedFd, flags: i32) -> bool {
    // SAFETY: F_GETFL only reads the status flags of a live descriptor.
    let status = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    flags & libc::MSG_DONTWAIT == 0 && (status < 0 || status & libc::O_NONBLOCK == 0)
}

/// The socket's timeout `option`, SO_RCVTIMEO or SO_SNDTIMEO: `None` for
/// zero, which is none.
fn timeout(socket: &OwnedFd, option: i32) -> io::Result<Option<Duration>> {
    let mut value = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: getsockopt writes one timeval into live storage of its size.
    let read = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::timeval).cast(),
            &mut size,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    let timeout =
        Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec as u64);
    Ok((!timeout.is_zero()).then_some(timeout))
}
