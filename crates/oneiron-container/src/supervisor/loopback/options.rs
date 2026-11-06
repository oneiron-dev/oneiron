//! The socket options the fence keeps itself, since a socket's Unix
//! stand-in cannot answer them: SO_ACCEPTCONN (FIX 6784), which only the
//! registry knows, and IPV6_V6ONLY (FIX 6787), which decides whether an
//! AF_INET6 socket takes IPv4-mapped loopback addresses.

use super::{errno, poisoned};
use crate::supervisor::{State, get};
use crate::wire::{self, SocketOption};
use std::io;
use std::sync::atomic::Ordering;

/// A getsockopt of `option` on socket `id`: the reply's value.
/// SO_ACCEPTCONN is 1 for a virtual listener and 0 for any other socket.
/// IPV6_V6ONLY on an AF_INET socket is `ENOPROTOOPT`, as on Linux.
pub(in crate::supervisor) fn get_option(
    state: &State,
    id: u64,
    option: SocketOption,
) -> io::Result<wire::Reply> {
    let socket = get(state, id)?;
    let value = match option {
        SocketOption::AcceptConnection => state
            .loopback
            .lock()
            .map_err(|_| poisoned())?
            .listeners
            .contains_key(&id),
        SocketOption::Ipv6Only if socket.family == libc::AF_INET6 => {
            socket.ipv6_only.load(Ordering::Acquire)
        }
        SocketOption::Ipv6Only => return Err(errno(libc::ENOPROTOOPT)),
    };
    Ok(wire::Reply {
        value: i64::from(value),
        ..Default::default()
    })
}

/// A setsockopt of `option` on socket `id` to `value`. SO_ACCEPTCONN is
/// read-only: `ENOPROTOOPT`, as Linux answers it. IPV6_V6ONLY is
/// `ENOPROTOOPT` on an AF_INET socket, and `EINVAL` once the socket is
/// bound, listening, connected or connecting, as on Linux.
pub(in crate::supervisor) fn set_option(
    state: &State,
    id: u64,
    option: SocketOption,
    value: i32,
) -> io::Result<wire::Reply> {
    let socket = get(state, id)?;
    if option != SocketOption::Ipv6Only || socket.family != libc::AF_INET6 {
        return Err(errno(libc::ENOPROTOOPT));
    }
    // Under the registry's lock, so no bind lands between the look and
    // the change.
    let registry = state.loopback.lock().map_err(|_| poisoned())?;
    let stream = socket.kind == libc::SOCK_STREAM;
    let connected = stream && socket.stream.lock().map_err(|_| poisoned())?.is_none();
    let addressed =
        registry.local.contains_key(&id) || socket.target.lock().map_err(|_| poisoned())?.is_some();
    if connected || addressed || socket.connecting.load(Ordering::Acquire) {
        return Err(errno(libc::EINVAL));
    }
    socket.ipv6_only.store(value != 0, Ordering::Release);
    Ok(wire::Reply::default())
}
