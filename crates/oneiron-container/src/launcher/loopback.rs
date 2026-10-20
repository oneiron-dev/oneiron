//! The launcher's half of the guest's virtual loopback (FIX 6680). It
//! copies each bind's address and each accept's output for the supervisor,
//! which acts on its copy: no bind, listen or accept on a brokered socket
//! continues to the kernel, so no kernel INET listener ever exists.

use super::{Bridge, address, put_address};
use crate::{linux, wire};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;

/// The calls this brokers on a brokered socket.
pub(super) const CALLS: [i64; 4] = [
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
];

/// Brokers a bind, listen, accept or accept4 on the brokered socket
/// `socket`. On a datagram socket a listen or an accept continues: the
/// kernel answers it as before, since no datagram socket listens.
pub(super) fn dispatch(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
    socket: u64,
    datagram: bool,
) -> io::Result<()> {
    let fd = listener.as_raw_fd();
    let a = n.data.args;
    let nr = i64::from(n.data.nr);
    let reply = if nr == libc::SYS_bind {
        // The supervisor binds this copy; the guest's buffer is not read
        // again, so no later write to it can change the address.
        let Some(address) = address(n.pid, a[1], a[2])? else {
            return linux::respond(fd, n.id, 0, libc::EAFNOSUPPORT, 0);
        };
        bridge.call(n.id, wire::Operation::Bind { socket, address })?
    } else if datagram {
        return linux::respond(fd, n.id, 0, 0, linux::CONTINUE);
    } else if nr == libc::SYS_listen {
        let guest = guest_end(n.pid, a[0], socket)?;
        let backlog = a[1] as i32;
        bridge.carry(
            n.id,
            wire::Operation::Listen { socket, backlog },
            Some(guest),
        )?
    } else {
        return accept(fd, bridge, n, socket);
    };
    linux::respond(fd, n.id, reply.value, reply.errno, 0)
}

/// An accept. The supervisor reserves the next connection and names its
/// peer, this writes that address into the guest's buffer, and then the
/// supervisor's ADDFD installs the connection and completes the call. A
/// connection whose address cannot be written goes back to its queue.
fn accept(fd: RawFd, bridge: &Bridge, n: linux::Notification, socket: u64) -> io::Result<()> {
    let a = n.data.args;
    let flags = if i64::from(n.data.nr) == libc::SYS_accept4 {
        a[3] as i32
    } else {
        0
    };
    if flags & !(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) != 0 {
        return linux::respond(fd, n.id, 0, libc::EINVAL, 0);
    }
    let reserved = bridge.call(n.id, wire::Operation::Accept { socket })?;
    if reserved.errno != 0 {
        return linux::respond(fd, n.id, 0, reserved.errno, 0);
    }
    let written = match reserved.address {
        Some(peer) => linux::valid(fd, n.id).and_then(|()| put_address(n.pid, a[1], a[2], peer)),
        None => Ok(()),
    };
    let finish = wire::Operation::AcceptFinish {
        socket,
        ticket: reserved.value as u64,
        commit: written.is_ok(),
        flags,
    };
    let finished = {
        // Like a socket(), an install holds off the inventory (FIX 5978).
        let _shared = bridge
            .sockets
            .read()
            .map_err(|_| io::Error::other("fence state poisoned"))?;
        bridge.call(n.id, finish)?
    };
    written?;
    // The installed connection completed the call.
    if finished.errno == 0 {
        Ok(())
    } else {
        linux::respond(fd, n.id, 0, finished.errno, 0)
    }
}

/// The listener's guest end, duplicated out of the calling task's process
/// (the access process_vm_readv already has): the supervisor reads the
/// listener's readiness tokens back through it. It must be `socket`.
fn guest_end(pid: u32, fd: u64, socket: u64) -> io::Result<OwnedFd> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let process = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|id| id.trim().parse::<i32>().ok())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
    // SAFETY: pidfd_open takes two integers and passes no pointer.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, process, 0) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful pidfd_open returned a new descriptor, owned once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    // SAFETY: pidfd_getfd takes three integers and passes no pointer.
    let copy = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd as RawFd, 0) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful pidfd_getfd returned a new close-on-exec
    // descriptor, owned once.
    let copy = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(copy as RawFd) });
    if copy.metadata()?.ino() != socket {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    Ok(copy.into())
}
