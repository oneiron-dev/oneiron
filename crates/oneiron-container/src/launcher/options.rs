//! getsockopt and setsockopt on a brokered socket (FIX 6784, FIX 6787).
//!
//! The fence answers three options itself: SO_DOMAIN from the socket's
//! family, SO_ACCEPTCONN from the supervisor's loopback registry (1 for a
//! virtual listener, 0 for any other socket), and IPV6_V6ONLY, which the
//! supervisor keeps per socket because it decides whether an AF_INET6
//! socket takes IPv4-mapped loopback addresses. Every other SOL_SOCKET
//! option, a setsockopt of SO_DOMAIN or SO_ACCEPTCONN included, continues
//! to the socket's Unix stand-in. An option of any other level is
//! acknowledged, and reads as zero.

use super::{Bridge, load, remote, store};
use crate::{linux, wire};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::OnceLock;

/// The size of a C int, which every option the fence answers is.
const INT: usize = std::mem::size_of::<i32>();

/// The guest kernel's default for IPV6_V6ONLY (`net.ipv6.bindv6only`),
/// read once: a new AF_INET6 socket starts with it. With no IPv6 sysctl
/// it is off, Linux's own default.
pub(super) fn default_ipv6_only() -> bool {
    static DEFAULT: OnceLock<bool> = OnceLock::new();
    *DEFAULT.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only")
            .is_ok_and(|value| value.trim() != "0")
    })
}

/// How the fence answers one option.
enum Answer {
    /// SO_DOMAIN: the socket's family.
    Domain,
    /// An option the supervisor keeps.
    Kept(wire::SocketOption),
    /// An option of another level: a set is acknowledged, a get reads zero.
    Acknowledged,
}

/// Brokers a getsockopt or setsockopt on the brokered socket `socket`, of
/// `family`.
pub(super) fn dispatch(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
    socket: u64,
    family: i32,
) -> io::Result<()> {
    let fd = listener.as_raw_fd();
    let a = n.data.args;
    let getting = i64::from(n.data.nr) == libc::SYS_getsockopt;
    let answer = match (a[1] as i32, a[2] as i32) {
        (libc::SOL_SOCKET, libc::SO_DOMAIN) if getting => Answer::Domain,
        (libc::SOL_SOCKET, libc::SO_ACCEPTCONN) if getting => {
            Answer::Kept(wire::SocketOption::AcceptConnection)
        }
        (libc::SOL_SOCKET, _) => return linux::respond(fd, n.id, 0, 0, linux::CONTINUE),
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY) => Answer::Kept(wire::SocketOption::Ipv6Only),
        _ => Answer::Acknowledged,
    };
    if !getting {
        let Answer::Kept(option) = answer else {
            return linux::respond(fd, n.id, 0, 0, 0);
        };
        let value = set_value(n.pid, a[3], a[4])?;
        let set = wire::Operation::SetOption {
            socket,
            option,
            value,
        };
        let reply = bridge.call(n.id, set)?;
        return linux::respond(fd, n.id, 0, reply.errno, 0);
    }
    let value = match answer {
        Answer::Domain => family,
        Answer::Kept(option) => {
            let reply = bridge.call(n.id, wire::Operation::GetOption { socket, option })?;
            if reply.errno != 0 {
                return linux::respond(fd, n.id, 0, reply.errno, 0);
            }
            i32::try_from(reply.value).unwrap_or(0)
        }
        Answer::Acknowledged => 0,
    };
    linux::valid(fd, n.id)?;
    put_int(n.pid, a[3], a[4], value)?;
    linux::respond(fd, n.id, 0, 0, 0)
}

/// The int a setsockopt passes at `pointer`, `length` bytes long, read as
/// Linux reads it: a length under an int's is `EINVAL`, and a null pointer
/// reads zero.
fn set_value(pid: u32, pointer: u64, length: u64) -> io::Result<i32> {
    // The kernel takes the length as a C int: a negative one is short too.
    if (length as i32) < INT as i32 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    if pointer == 0 {
        return Ok(0);
    }
    load(pid, pointer)
}

/// Writes an int option's `value` as Linux does: as many of its bytes as
/// the caller's length at `length` holds, at most an int's, at `pointer`,
/// and then the length written. A negative length is `EINVAL`.
fn put_int(pid: u32, pointer: u64, length: u64, value: i32) -> io::Result<()> {
    let held: i32 = load(pid, length)?;
    let size = usize::try_from(held)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
        .min(INT);
    if size > 0 {
        remote(pid, pointer, &mut value.to_ne_bytes()[..size], true)?;
    }
    store(pid, length, size as i32)
}
