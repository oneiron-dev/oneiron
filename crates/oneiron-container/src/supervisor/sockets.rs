//! A guest's `socket()` (FIX 5978): the guest gets one end of a fresh Unix
//! pair, which the notification's ADDFD installs, and the host keeps the
//! other in the socket's entry.

use super::{Socket, State, datagram_writer, inode, lifetime};
use crate::{linux, wire};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// Brokers one `socket()` call: its entry, its room on the host floor, and
/// the descriptor the guest receives as the call's result.
pub(super) fn open(
    request: &wire::Request,
    listener: &OwnedFd,
    state: &Arc<State>,
    family: &i32,
    kind: &i32,
    protocol: &i32,
    reply: &mut wire::Reply,
) -> io::Result<()> {
    let base = kind & 0xf;
    if !matches!(*family, libc::AF_INET | libc::AF_INET6)
        || !matches!(base, libc::SOCK_STREAM | libc::SOCK_DGRAM)
        || !matches!(*protocol, 0 | libc::IPPROTO_TCP | libc::IPPROTO_UDP)
    {
        return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
    }
    // The entry's descriptors and writer take their room on the host
    // floor first; a full floor is EAGAIN (FIX 5978).
    let (fds, workers) = if base == libc::SOCK_STREAM {
        lifetime::STREAM_ENTRY
    } else {
        lifetime::DATAGRAM_ENTRY
    };
    let charge = state.relay.host_net_floor().acquire(fds, workers)?;
    let (socket, id, guest): (Arc<Socket>, u64, OwnedFd) = if base == libc::SOCK_STREAM {
        let (guest, host) = UnixStream::pair()?;
        guest.set_nonblocking(kind & libc::SOCK_NONBLOCK != 0)?;
        let id = inode(&guest)?;
        (
            Arc::new(Socket {
                family: *family,
                kind: base,
                target: Mutex::new(None),
                stream: Mutex::new(Some(host)),
                datagram: None,
                closed: AtomicBool::new(false),
                _charge: charge,
            }),
            id,
            guest.into(),
        )
    } else {
        let (guest, host) = UnixDatagram::pair()?;
        guest.set_nonblocking(kind & libc::SOCK_NONBLOCK != 0)?;
        let id = inode(&guest)?;
        let copy = guest.try_clone()?;
        (
            Arc::new(Socket {
                family: *family,
                kind: base,
                target: Mutex::new(None),
                stream: Mutex::new(None),
                datagram: Some((copy, host)),
                closed: AtomicBool::new(false),
                _charge: charge,
            }),
            id,
            guest.into(),
        )
    };
    state
        .sockets
        .lock()
        .map_err(|_| io::Error::other("fence state poisoned"))?
        .insert(id, Arc::clone(&socket));
    let injected = linux::inject(
        listener.as_raw_fd(),
        request.notification,
        guest.as_raw_fd(),
        kind & libc::SOCK_CLOEXEC != 0,
    );
    // A socket the guest never received has no entry (FIX 5978).
    reply.value = i64::from(injected.inspect_err(|_| {
        if let Ok(mut sockets) = state.sockets.lock()
            && sockets
                .get(&id)
                .is_some_and(|held| Arc::ptr_eq(held, &socket))
        {
            sockets.remove(&id);
        }
    })?);
    if base == libc::SOCK_DGRAM {
        datagram_writer(socket, Arc::clone(state));
    }
    Ok(())
}
