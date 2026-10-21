//! Route netlink as the guest's network setup speaks it: one dump of the
//! links, and the three changes it makes (a link up, an address, a route),
//! each sent asking for the kernel's answer, which is then checked. An
//! answer of 0 is the change made; any other is the change refused, with
//! the kernel's errno.
//!
//! The messages are built byte for byte from the kernel's fixed route
//! netlink ABI (`linux/netlink.h`, `linux/rtnetlink.h`, `linux/if_link.h`
//! and `linux/if_addr.h`): numbers in host byte order, addresses in network
//! order.

use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
/// A route's output link.
const RTA_OUTPUT_LINK: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
/// `struct nlmsghdr`'s size, and `struct ifinfomsg`'s.
const HEADER_BYTES: usize = 16;
const IFINFOMSG_BYTES: usize = 16;
/// Room for any one answer's datagram: the kernel's dump datagrams are at
/// most 32 KiB.
const RECEIVE_BYTES: usize = 64 * 1024;

/// A route netlink socket to the kernel, and its last request's sequence
/// number.
pub(super) struct Route {
    socket: OwnedFd,
    seq: u32,
}

/// One link as the kernel's dump names it.
pub(super) struct Link {
    pub(super) index: u32,
    pub(super) name: String,
    /// Its hardware address, when it is a six-octet one.
    pub(super) mac: Option<[u8; 6]>,
    pub(super) loopback: bool,
}

impl Route {
    pub(super) fn open() -> io::Result<Self> {
        // SAFETY: socket takes no pointers, and its result is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is the socket just made, this process's alone, and it
        // is taken over once.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { socket, seq: 0 })
    }

    /// Every link the kernel has.
    pub(super) fn links(&mut self) -> io::Result<Vec<Link>> {
        // An all-zero `struct ifinfomsg` (`AF_UNSPEC`, no index) asks for
        // every link.
        let seq = self.send(
            RTM_GETLINK,
            NLM_F_REQUEST | NLM_F_DUMP,
            &[0; IFINFOMSG_BYTES],
        )?;
        let mut links = Vec::new();
        let mut buffer = vec![0u8; RECEIVE_BYTES];
        loop {
            let read = self.receive(&mut buffer)?;
            for (kind, answered, payload) in messages(&buffer[..read])? {
                if answered != seq {
                    continue;
                }
                match kind {
                    NLMSG_DONE => return answer(payload).map(|()| links),
                    NLMSG_ERROR => answer(payload)?,
                    RTM_NEWLINK => links.push(Link::parse(payload)?),
                    _ => {}
                }
            }
        }
    }

    /// Brings the link `index` up.
    pub(super) fn set_up(&mut self, index: u32) -> io::Result<()> {
        // `struct ifinfomsg`: family, padding and type, then the index, the
        // flags and the flags changed.
        let mut link = vec![AF_UNSPEC, 0, 0, 0];
        link.extend_from_slice(&index.to_ne_bytes());
        link.extend_from_slice(&IFF_UP.to_ne_bytes());
        link.extend_from_slice(&IFF_UP.to_ne_bytes());
        self.change(RTM_NEWLINK, 0, &link)
    }

    /// Gives the link `index` the IPv4 `address` on a prefix of
    /// `prefix_len`, refused when it holds it already.
    pub(super) fn add_address(
        &mut self,
        index: u32,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> io::Result<()> {
        // `struct ifaddrmsg`: family, prefix length, flags and scope, then
        // the index.
        let mut message = vec![AF_INET, prefix_len, 0, RT_SCOPE_UNIVERSE];
        message.extend_from_slice(&index.to_ne_bytes());
        attribute(&mut message, IFA_LOCAL, &address.octets());
        attribute(&mut message, IFA_ADDRESS, &address.octets());
        self.change(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &message)
    }

    /// Adds the main table's default IPv4 route through `gateway` on the
    /// link `index`, refused when there is one already.
    pub(super) fn add_default_route(&mut self, index: u32, gateway: Ipv4Addr) -> io::Result<()> {
        // `struct rtmsg`: family, destination, source and TOS (a default
        // route's are 0), table, protocol, scope and type, then its flags.
        let mut message = vec![
            AF_INET,
            0,
            0,
            0,
            RT_TABLE_MAIN,
            RTPROT_BOOT,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
        ];
        message.extend_from_slice(&0u32.to_ne_bytes());
        attribute(&mut message, RTA_GATEWAY, &gateway.octets());
        attribute(&mut message, RTA_OUTPUT_LINK, &index.to_ne_bytes());
        self.change(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &message)
    }

    /// Sends one change asking for the kernel's answer, and checks it.
    fn change(&mut self, kind: u16, flags: u16, body: &[u8]) -> io::Result<()> {
        let seq = self.send(kind, NLM_F_REQUEST | NLM_F_ACK | flags, body)?;
        let mut buffer = vec![0u8; RECEIVE_BYTES];
        loop {
            let read = self.receive(&mut buffer)?;
            for (answered_kind, answered, payload) in messages(&buffer[..read])? {
                if answered_kind == NLMSG_ERROR && answered == seq {
                    return answer(payload);
                }
            }
        }
    }

    /// Sends one request, its header before `body`; its sequence number.
    fn send(&mut self, kind: u16, flags: u16, body: &[u8]) -> io::Result<u32> {
        self.seq += 1;
        let len = HEADER_BYTES + body.len();
        let mut message = Vec::with_capacity(len);
        message.extend_from_slice(&(len as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&self.seq.to_ne_bytes());
        // The port id, which the kernel fills in.
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        // SAFETY: the pointer and the length are `message`'s, which outlives
        // the call.
        let sent = unsafe {
            libc::send(
                self.socket.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
            )
        };
        match usize::try_from(sent) {
            Ok(sent) if sent == message.len() => Ok(self.seq),
            Ok(_) => Err(io::Error::other(
                "the kernel took part of a netlink request",
            )),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

    /// One datagram from the kernel into `buffer`; its length. One longer
    /// than the buffer is refused, never read cut short.
    fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: the pointer and the length are `buffer`'s, which outlives
        // the call; with MSG_TRUNC the kernel answers the datagram's whole
        // length and still writes no more than the buffer holds.
        let read = unsafe {
            libc::recv(
                self.socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        let read = usize::try_from(read).map_err(|_| io::Error::last_os_error())?;
        if read > buffer.len() {
            return Err(io::Error::other(
                "a netlink answer is longer than its buffer",
            ));
        }
        Ok(read)
    }
}

impl Link {
    /// One `RTM_NEWLINK` message's link: its `struct ifinfomsg` (the index
    /// and the flags), then its attributes.
    fn parse(payload: &[u8]) -> io::Result<Self> {
        let flags = u32::from_ne_bytes(field(payload, 8)?);
        let mut link = Self {
            index: u32::from_ne_bytes(field(payload, 4)?),
            name: String::new(),
            mac: None,
            loopback: flags & IFF_LOOPBACK != 0,
        };
        let attributes = payload.get(IFINFOMSG_BYTES..).ok_or_else(malformed)?;
        for (kind, data) in each_attribute(attributes)? {
            match kind {
                IFLA_ADDRESS => link.mac = data.try_into().ok(),
                IFLA_IFNAME => {
                    link.name = CStr::from_bytes_until_nul(data)
                        .ok()
                        .and_then(|name| name.to_str().ok())
                        .ok_or_else(malformed)?
                        .to_owned();
                }
                _ => {}
            }
        }
        Ok(link)
    }
}

/// Each message in one datagram: its type, its sequence number and its
/// payload.
fn messages(datagram: &[u8]) -> io::Result<Vec<(u16, u32, &[u8])>> {
    let mut found = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let len = u32::from_ne_bytes(field(rest, 0)?) as usize;
        let payload = rest.get(HEADER_BYTES..len).ok_or_else(malformed)?;
        let kind = u16::from_ne_bytes(field(rest, 4)?);
        let seq = u32::from_ne_bytes(field(rest, 8)?);
        found.push((kind, seq, payload));
        rest = rest.get(aligned(len)..).unwrap_or_default();
    }
    Ok(found)
}

/// Each attribute in `bytes`: its type and its data.
fn each_attribute(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut found = Vec::new();
    while !bytes.is_empty() {
        let len = usize::from(u16::from_ne_bytes(field(bytes, 0)?));
        let data = bytes.get(4..len).ok_or_else(malformed)?;
        found.push((u16::from_ne_bytes(field(bytes, 2)?), data));
        bytes = bytes.get(aligned(len)..).unwrap_or_default();
    }
    Ok(found)
}

/// Appends one attribute to `message`: its length and type, its data, and
/// the padding before the next.
fn attribute(message: &mut Vec<u8>, kind: u16, data: &[u8]) {
    message.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(data);
    message.resize(aligned(message.len()), 0);
}

/// The code an `NLMSG_ERROR` or `NLMSG_DONE` payload opens with: 0 is the
/// request done, a negative errno is it refused.
fn answer(payload: &[u8]) -> io::Result<()> {
    match i32::from_ne_bytes(field(payload, 0)?) {
        0 => Ok(()),
        code => Err(io::Error::from_raw_os_error(code.wrapping_neg())),
    }
}

/// The `N` bytes of `bytes` at `at`, refused when it is shorter.
fn field<const N: usize>(bytes: &[u8], at: usize) -> io::Result<[u8; N]> {
    bytes
        .get(at..at + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(malformed)
}

/// `len` rounded up to the 4-byte alignment netlink keeps.
fn aligned(len: usize) -> usize {
    len.next_multiple_of(4)
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a malformed netlink answer")
}
