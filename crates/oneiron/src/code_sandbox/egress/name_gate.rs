//! The name a raw stream carries to an address that a name of the owner
//! allowlist admitted (FIX 7652, FIX 634). Its TLS ClientHello's visible
//! server name, or its HTTP request's Host, must name an allowed name bound
//! to that address now, on any port. Other protocols go on unread.
//!
//! The gate reads the guest's opening bytes after its connect was answered
//! and before any reaches the remote. It reassembles them across reads and
//! TLS records with no byte threshold: a ClientHello or a request head is
//! judged whole.

use super::*;
use std::sync::atomic::Ordering;

/// A raw stream the name gate refused (FIX 7652). Nothing the guest wrote
/// on it is sent; the owner's raw endpoint grant for its endpoint
/// ([`RawEndpointGrant`]) admits it unread.
#[derive(Debug, thiserror::Error)]
pub enum EgressNameRefusal {
    /// `egress_name_unverifiable`: the opening carries no name the
    /// allowlist can check: TLS with no server name, a ClientHello or a
    /// request name that does not parse, or HTTP with no Host.
    #[error(
        "egress_name_unverifiable: the stream to {target} carries no name the owner allowlist can check ({why})"
    )]
    Unverifiable {
        target: SocketAddr,
        why: &'static str,
    },
    /// `egress_name_ungranted`: the opening names `name`, which the
    /// allowlist does not admit or which is not bound to the address now.
    #[error(
        "egress_name_ungranted: the stream to {target} names {name}, which the owner allowlist does not bind to that address"
    )]
    Ungranted { target: SocketAddr, name: String },
}

impl EgressNameRefusal {
    /// The refusal's stable reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Unverifiable { .. } => "egress_name_unverifiable",
            Self::Ungranted { .. } => "egress_name_ungranted",
        }
    }

    /// The address and port the refused stream was connected to.
    #[must_use]
    pub const fn target(&self) -> SocketAddr {
        match self {
            Self::Unverifiable { target, .. } | Self::Ungranted { target, .. } => *target,
        }
    }
}

/// What a stream's opening bytes say so far.
enum Opening {
    /// More bytes decide it.
    Pending,
    /// Neither TLS nor HTTP: the stream goes on unread.
    Opaque,
    /// The names the opening carries, each of which must be bound.
    Names(Vec<String>),
    /// TLS or HTTP whose name cannot be checked.
    Unverifiable(&'static str),
}

/// The TLS handshake record type.
const HANDSHAKE: u8 = 0x16;
/// The ClientHello handshake message type.
const CLIENT_HELLO: u8 = 1;
/// The server_name extension (RFC 6066 3).
const SERVER_NAME: u16 = 0;

/// Reads `guest`'s opening bytes on a stream to `target` while `alive`
/// holds, until they are judged, and answers them to send first. A refusal
/// is receipted as blocked, naming the address and port.
pub(super) fn open_upload(
    proxy: &OpenEgressProxy,
    target: SocketAddr,
    guest: &mut dyn io::Read,
    alive: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let mut seen = Vec::new();
    let mut chunk = [0; 32768];
    let mut ended = false;
    loop {
        match opening(&seen, ended) {
            Opening::Pending if ended => {
                let why = "the stream ended inside its opening";
                return Err(refuse(
                    proxy,
                    EgressNameRefusal::Unverifiable { target, why },
                ));
            }
            Opening::Pending => {}
            Opening::Opaque => return Ok(seen),
            Opening::Names(names) => {
                return match names
                    .into_iter()
                    .find(|name| !dns::name_bound(proxy, name, target.ip()))
                {
                    None => Ok(seen),
                    Some(name) => Err(refuse(proxy, EgressNameRefusal::Ungranted { target, name })),
                };
            }
            Opening::Unverifiable(why) => {
                return Err(refuse(
                    proxy,
                    EgressNameRefusal::Unverifiable { target, why },
                ));
            }
        }
        if !alive.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the guest session ended",
            ));
        }
        match guest.read(&mut chunk) {
            Ok(0) => ended = true,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}

/// Receipts `refusal` as a blocked connect naming its address and port, and
/// answers it as the stream's error.
fn refuse(proxy: &OpenEgressProxy, refusal: EgressNameRefusal) -> io::Error {
    if let Err(error) = proxy.record(
        "connect_name",
        &format!("tcp://{}", refusal.target()),
        refusal.to_string().as_bytes(),
        PolicyClassifyDecision::Block,
        PolicyVerdictCategory::None,
        None,
    ) {
        tracing::error!(%error, "egress name refusal receipt failed");
    }
    io::Error::new(io::ErrorKind::PermissionDenied, refusal)
}

/// What `seen`, a stream's opening so far, says; `ended` once the guest
/// closed its side.
fn opening(seen: &[u8], ended: bool) -> Opening {
    match seen.first() {
        None if ended => Opening::Opaque,
        None => Opening::Pending,
        Some(&HANDSHAKE) => tls(seen, ended),
        Some(_) => http(seen, ended),
    }
}

/// A TLS client's opening: handshake records, reassembled until the whole
/// ClientHello they carry is in, whatever their sizes, then its server
/// name. A stream whose first bytes are no TLS record header goes on.
fn tls(seen: &[u8], ended: bool) -> Opening {
    match seen.get(1) {
        Some(3) => {}
        None if !ended => return Opening::Pending,
        _ => return Opening::Opaque,
    }
    let mut handshake = Vec::new();
    let mut at = 0;
    while let Some(header) = seen.get(at..at + 5) {
        if header[0] != HANDSHAKE {
            return Opening::Unverifiable(
                "a record that is no handshake came inside the ClientHello",
            );
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let Some(fragment) = seen.get(at + 5..at + 5 + len) else {
            break;
        };
        handshake.extend_from_slice(fragment);
        at += 5 + len;
        if let [kind, a, b, c, ..] = handshake[..] {
            if kind != CLIENT_HELLO {
                return Opening::Unverifiable("the first handshake message is no ClientHello");
            }
            let size = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
            if let Some(body) = handshake.get(4..4 + size) {
                return client_hello(body)
                    .unwrap_or(Opening::Unverifiable("the ClientHello does not parse"));
            }
        }
    }
    Opening::Pending
}

/// The visible server name a whole ClientHello body carries. An encrypted
/// ClientHello (ECH) is judged by this outer name too: a GREASE one carries
/// the real name here, and a real one's public name is rarely bound to the
/// address. None for a body that does not parse.
fn client_hello(body: &[u8]) -> Option<Opening> {
    let mut hello = Fields(body);
    // The legacy version and random, the session ID, the cipher suites and
    // the compression methods.
    hello.take(34)?;
    hello.vec8()?;
    hello.vec16()?;
    hello.vec8()?;
    let none = Opening::Unverifiable("the ClientHello carries no server name");
    if hello.0.is_empty() {
        return Some(none);
    }
    let mut extensions = Fields(hello.vec16()?);
    if !hello.0.is_empty() {
        return None;
    }
    let mut kinds = Vec::new();
    let mut name = None;
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        if kinds.contains(&kind) {
            return None;
        }
        kinds.push(kind);
        if kind == SERVER_NAME {
            name = Some(host_name(data)?);
        }
    }
    Some(name.map_or(none, |name| Opening::Names(vec![name])))
}

/// The one host name a server_name extension lists (RFC 6066 3).
fn host_name(data: &[u8]) -> Option<String> {
    let mut extension = Fields(data);
    let mut list = Fields(extension.vec16()?);
    if !extension.0.is_empty() {
        return None;
    }
    let mut name = None;
    while !list.0.is_empty() {
        let kind = list.take(1)?[0];
        let entry = list.vec16()?;
        if kind == 0 {
            if name.is_some() {
                return None;
            }
            name = Some(host(entry)?);
        }
    }
    name
}

/// A name as the gate compares it: ASCII letters, digits, `-`, `_` and
/// dots, lowercased, with no trailing dot.
fn host(bytes: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(bytes).ok()?.trim_end_matches('.');
    let valid = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.');
    (!name.is_empty() && name.bytes().all(valid)).then(|| name.to_ascii_lowercase())
}

/// A cursor over length-prefixed TLS fields.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.take(1)?[0]);
        self.take(len)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

/// An HTTP/1 client's opening: a request line `method target HTTP/x.y`
/// (blank lines before it and runs of spaces or tabs inside it allowed, as
/// lenient servers read it), then its head up to the blank line. The names
/// it carries are its Host and an absolute-form or CONNECT target's host.
/// Bytes that stop reading as a request line go on unread.
fn http(seen: &[u8], ended: bool) -> Opening {
    let (method, target, mut at) = match request_line(seen, ended) {
        Ok(line) => line,
        Err(opening) => return opening,
    };
    // The request line is whole: this is HTTP, judged on its whole head.
    let mut lines = Vec::new();
    loop {
        let Some(end) = seen[at..].iter().position(|b| *b == b'\n') else {
            return if ended {
                Opening::Unverifiable("the stream ended inside its request head")
            } else {
                Opening::Pending
            };
        };
        let line = &seen[at..at + end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        at += end + 1;
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    request_names(method, target, &lines)
}

/// A whole request line's method and target, and where its head starts; or
/// what bytes that do not make one yet say.
fn request_line(seen: &[u8], ended: bool) -> Result<(&[u8], &[u8], usize), Opening> {
    let mut at = 0;
    while seen.get(at).is_some_and(|b| matches!(b, b'\r' | b'\n')) {
        at += 1;
    }
    let method = at;
    at = step(run(seen, at, tchar), ended)?;
    let method = &seen[method..at];
    at = step(run(seen, at, |b| matches!(b, b' ' | b'\t')), ended)?;
    let target = at;
    at = step(run(seen, at, |b| b > b' ' && b != 0x7f), ended)?;
    let target = &seen[target..at];
    at = step(run(seen, at, |b| matches!(b, b' ' | b'\t')), ended)?;
    for expected in b"HTTP/" {
        at = step(byte(seen, at, |b| b.eq_ignore_ascii_case(expected)), ended)?;
    }
    let version: [fn(&u8) -> bool; 3] = [u8::is_ascii_digit, |b| *b == b'.', u8::is_ascii_digit];
    for accepts in version {
        at = step(byte(seen, at, accepts), ended)?;
    }
    while seen
        .get(at)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r'))
    {
        at += 1;
    }
    at = step(byte(seen, at, |b| *b == b'\n'), ended)?;
    Ok((method, target, at))
}

/// Where a run of the bytes `take` accepts from `at` ends: `Err(true)` when
/// it reaches the end of what was seen, `Err(false)` when it is empty.
fn run(seen: &[u8], at: usize, take: impl Fn(u8) -> bool) -> Result<usize, bool> {
    match seen[at..].iter().position(|b| !take(*b)) {
        None => Err(true),
        Some(0) => Err(false),
        Some(len) => Ok(at + len),
    }
}

/// Past the byte at `at` when `accepts` takes it: `Err(true)` when nothing
/// was seen there yet, `Err(false)` when it is refused.
fn byte(seen: &[u8], at: usize, accepts: impl Fn(&u8) -> bool) -> Result<usize, bool> {
    match seen.get(at) {
        None => Err(true),
        Some(b) if accepts(b) => Ok(at + 1),
        Some(_) => Err(false),
    }
}

/// A request line step's end, or what its stop says: more bytes are
/// awaited until the guest closes its side; a refused byte is no request.
fn step(found: Result<usize, bool>, ended: bool) -> Result<usize, Opening> {
    found.map_err(|more| {
        if more && !ended {
            Opening::Pending
        } else {
            Opening::Opaque
        }
    })
}

/// The names a request head carries: its one Host, and the host of an
/// absolute-form target or a CONNECT target, which a server takes over it.
fn request_names(method: &[u8], target: &[u8], lines: &[&[u8]]) -> Opening {
    let unparsed = Opening::Unverifiable("a host the request names does not parse");
    let mut names = Vec::new();
    let authority = if method.eq_ignore_ascii_case(b"CONNECT") {
        Some(target)
    } else {
        absolute_authority(target)
    };
    if let Some(authority) = authority {
        let Some(name) = authority_host(authority) else {
            return unparsed;
        };
        names.push(name);
    }
    let mut hosts = 0;
    let mut in_host = false;
    for line in lines {
        if line.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
            if in_host {
                return Opening::Unverifiable("the request folds its Host line");
            }
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            in_host = false;
            continue;
        };
        in_host = line[..colon].trim_ascii_end().eq_ignore_ascii_case(b"host");
        if in_host {
            hosts += 1;
            let Some(name) = authority_host(line[colon + 1..].trim_ascii()) else {
                return unparsed;
            };
            names.push(name);
        }
    }
    if hosts > 1 {
        return Opening::Unverifiable("the request names Host more than once");
    }
    if names.is_empty() {
        return Opening::Unverifiable("the request names no Host");
    }
    names.dedup();
    Opening::Names(names)
}

/// The authority of an absolute-form request target (`scheme://authority`).
fn absolute_authority(target: &[u8]) -> Option<&[u8]> {
    let colon = target.iter().position(|b| *b == b':')?;
    let scheme = &target[..colon];
    let valid = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.');
    if scheme.first().is_none_or(|b| !b.is_ascii_alphabetic()) || !scheme.iter().all(valid) {
        return None;
    }
    let rest = target[colon + 1..].strip_prefix(b"//")?;
    let end = rest
        .iter()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The host of an authority (`[userinfo@]host[:port]`): a name as [`host`]
/// reads it, or a bracketed IPv6 literal.
fn authority_host(authority: &[u8]) -> Option<String> {
    let authority = authority
        .iter()
        .rposition(|b| *b == b'@')
        .map_or(authority, |at| &authority[at + 1..]);
    if let Some(literal) = authority.strip_prefix(b"[") {
        let end = literal.iter().position(|b| *b == b']')?;
        let address = std::str::from_utf8(&literal[..end])
            .ok()?
            .parse::<std::net::Ipv6Addr>()
            .ok()?;
        return Some(address.to_string());
    }
    let end = authority
        .iter()
        .position(|b| *b == b':')
        .unwrap_or(authority.len());
    host(&authority[..end])
}

/// An HTTP token character (RFC 9110 5.6.2).
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
