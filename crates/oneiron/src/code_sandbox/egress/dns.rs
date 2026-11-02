//! DNS goes to the host's resolver through the same proxy. All query types
//! relay by default; A/AAAA answers still get the shared public-address check.
//!
//! An answer binds raw socket authority to the name asked alone (FIX 7652):
//! the A/AAAA records its Answer section's CNAME chain reaches from the
//! question it matches, each until the least TTL on its way ends.
use super::*;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

pub(super) fn answer(proxy: &OpenEgressProxy, query: &[u8]) -> io::Result<Vec<u8>> {
    let result = (|| {
        if query.get(2).is_none_or(|b| b & 0x80 != 0) {
            return Err(io::Error::other("DNS query expected"));
        }
        let (host, _) = question(query)?;
        if !proxy.domain_allowed(&host) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner DNS allowlist",
            ));
        }
        let answer =
            exchange_dns_query(query, proxy.config.request_timeout, UnusableResolver::Fail)?;
        check_answers(&answer)?;
        // The answer binds the name the guest asked for, once the whole
        // reply is checked (FIX 7652).
        if let Some(bound) = bindings(query, &answer) {
            publish(proxy, &host.to_ascii_lowercase(), &bound);
        }
        Ok((host, answer))
    })();
    match result {
        Ok((host, answer)) => {
            proxy.record(
                "dns",
                &format!("dns://{host}"),
                &answer,
                PolicyClassifyDecision::Allow,
                PolicyVerdictCategory::None,
                None,
            )?;
            Ok(answer)
        }
        Err(error) => {
            let host = question(query)
                .map(|(h, _)| h)
                .unwrap_or_else(|_| "invalid".into());
            proxy.record(
                "dns",
                &format!("dns://{host}"),
                &[],
                PolicyClassifyDecision::Block,
                PolicyVerdictCategory::None,
                None,
            )?;
            Err(error)
        }
    }
}

/// What the shared DNS transport does with a host resolver it cannot use
/// for the query: one it fails to reach over UDP, or whose reply is not an
/// answer to the query (FIX 7558). A resolver that never answers is always
/// skipped, and a truncated reply's TCP exchange always decides, under both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnusableResolver {
    /// Fails the query with that resolver's error: the sandbox door's rule,
    /// whose first resolver to answer decides.
    Fail,
    /// Asks the next host resolver, failing only when none is left: the
    /// headless relay's rule, whose first valid answer wins.
    Skip,
}

/// The host resolvers' reply to `query`: from `/etc/resolv.conf`'s
/// resolvers in order over UDP, and again over TCP where a UDP reply came
/// back truncated, each read bounded by `wait` (FIX 7558). The sandbox door
/// ([`answer`]) and the headless relay share this transport: it checks no
/// allowlist, refuses no address and keeps no receipt, and each caller keeps
/// its own query check. What a resolver the transport cannot use does to
/// the query is `fallback`.
pub fn exchange_dns_query(
    query: &[u8],
    wait: Duration,
    fallback: UnusableResolver,
) -> io::Result<Vec<u8>> {
    let config = std::fs::read_to_string("/etc/resolv.conf")?;
    let resolvers: Vec<IpAddr> = config
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next()?.parse().ok())
                .flatten()
        })
        .collect();
    let mut error = io::Error::other("host has no DNS resolver");
    for resolver in resolvers {
        let target = SocketAddr::new(resolver, 53);
        let socket = match udp_query(target, query, wait) {
            Ok(socket) => socket,
            Err(failed) => {
                if fallback == UnusableResolver::Skip {
                    error = failed;
                    continue;
                }
                return Err(failed);
            }
        };
        let mut answer = vec![0; 65536];
        match socket.recv(&mut answer) {
            Ok(n) => {
                answer.truncate(n);
                if answer.len() < 12 || answer[..2] != query[..2] || answer[2] & 0x80 == 0 {
                    let failed = io::Error::other("invalid host DNS reply");
                    if fallback == UnusableResolver::Skip {
                        error = failed;
                        continue;
                    }
                    return Err(failed);
                }
                if answer[2] & 2 == 0 {
                    return Ok(answer);
                }
                return tcp_answer(target, query, wait, fallback);
            }
            Err(e) => error = e,
        }
    }
    Err(error)
}

/// `query` sent to `target` over UDP, its answer's read bounded by `wait`.
fn udp_query(target: SocketAddr, query: &[u8], wait: Duration) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(wait))?;
    socket.connect(target)?;
    socket.send(query)?;
    Ok(socket)
}

/// `target`'s reply to `query` over TCP, each wait bounded by `wait`: the
/// second asking of a truncated UDP reply. Under [`UnusableResolver::Fail`]
/// any reply with the query's id answers, under [`UnusableResolver::Skip`]
/// only an answer to it does, as each caller read before (FIX 7558).
fn tcp_answer(
    target: SocketAddr,
    query: &[u8],
    wait: Duration,
    fallback: UnusableResolver,
) -> io::Result<Vec<u8>> {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect_timeout(&target, wait)?;
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(wait))?;
    let prefixed = match fallback {
        UnusableResolver::Fail => query.len() as u16,
        UnusableResolver::Skip => u16::try_from(query.len()).map_err(io::Error::other)?,
    };
    stream.write_all(&prefixed.to_be_bytes())?;
    stream.write_all(query)?;
    let mut len = [0; 2];
    stream.read_exact(&mut len)?;
    let mut answer = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut answer)?;
    match fallback {
        UnusableResolver::Fail => {
            if answer.len() < 12 || answer[..2] != query[..2] {
                return Err(io::Error::other("invalid TCP DNS reply"));
            }
        }
        UnusableResolver::Skip => {
            if answer.len() < 12 || answer[..2] != query[..2] || answer[2] & 0x80 == 0 {
                return Err(io::Error::other("invalid host DNS reply"));
            }
        }
    }
    Ok(answer)
}

/// A name of the owner allowlist that `wanted` takes and `ip` is bound to
/// now: a fresh binding, else an ended one looked up again and answered
/// with `ip` (FIX 7652).
pub(super) fn bound_name(
    proxy: &OpenEgressProxy,
    ip: IpAddr,
    wanted: impl Fn(&str) -> bool,
) -> Option<String> {
    let now = Instant::now();
    let mut fresh = Vec::new();
    let mut ended = Vec::new();
    {
        let bindings = proxy.bindings.lock().ok()?;
        for (name, expires) in bindings.get(&ip)? {
            if proxy.domain_allowed(name) && wanted(name.as_str()) {
                if *expires > now {
                    fresh.push(name.clone());
                } else {
                    ended.push(name.clone());
                }
            }
        }
    }
    fresh
        .into_iter()
        .next()
        .or_else(|| ended.into_iter().find(|name| refresh(proxy, name, ip)))
}

/// Whether `name`, a name the owner allowlist admits, is bound to `ip` now:
/// freshly, or by looking it up again (FIX 7652).
pub(super) fn name_bound(proxy: &OpenEgressProxy, name: &str, ip: IpAddr) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !proxy.domain_allowed(&name) {
        return false;
    }
    let fresh = proxy.bindings.lock().is_ok_and(|bindings| {
        bindings
            .get(&ip)
            .and_then(|names| names.get(&name))
            .is_some_and(|expires| *expires > Instant::now())
    });
    fresh || refresh(proxy, &name, ip)
}

/// Looks `name` up again at the host's resolvers for `ip`'s family and keeps
/// what the checked answer binds (FIX 7652): whether `ip` is among its
/// addresses, which admits this one use even at TTL 0. An answer without
/// `ip` ends that binding; a lookup that fails keeps it as it was.
fn refresh(proxy: &OpenEgressProxy, name: &str, ip: IpAddr) -> bool {
    let Some(query) = query_for(name, ip) else {
        return false;
    };
    let reply = exchange_dns_query(&query, proxy.config.request_timeout, UnusableResolver::Fail)
        .and_then(|reply| check_answers(&reply).map(|()| reply));
    let (bytes, decision) = match &reply {
        Ok(reply) => (reply.as_slice(), PolicyClassifyDecision::Allow),
        Err(_) => (&[][..], PolicyClassifyDecision::Block),
    };
    let recorded = proxy.record(
        "dns",
        &format!("dns://{name}"),
        bytes,
        decision,
        PolicyVerdictCategory::None,
        None,
    );
    let (Ok(reply), Ok(())) = (reply, recorded) else {
        return false;
    };
    let Some(bound) = bindings(&query, &reply) else {
        return false;
    };
    publish(proxy, name, &bound);
    let found = bound.iter().any(|(address, _)| *address == ip);
    if !found
        && let Ok(mut bindings) = proxy.bindings.lock()
        && let Some(names) = bindings.get_mut(&ip)
        && names
            .get(name)
            .is_some_and(|expires| *expires <= Instant::now())
    {
        names.remove(name);
    }
    found
}

/// A recursive query for `name`'s addresses of `ip`'s family, under a
/// random ID; none when `name` cannot be written as a DNS name.
fn query_for(name: &str, ip: IpAddr) -> Option<Vec<u8>> {
    let mut query = rand::random::<u16>().to_be_bytes().to_vec();
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|len| (1..=63).contains(len))?;
        query.push(len);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    let kind = if ip.is_ipv4() { TYPE_A } else { TYPE_AAAA };
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(query)
}

/// Keeps `bound`'s public addresses bound to `name` until their TTLs end.
/// Each replaces what that name and address held, so the newest answer's
/// TTL counts and a TTL of 0 is never fresh (FIX 7652). Without an owner
/// allowlist nothing is kept: no binding admits anything there.
fn publish(proxy: &OpenEgressProxy, name: &str, bound: &[(IpAddr, u32)]) {
    if proxy.config.allowed_domains.is_none() {
        return;
    }
    let now = Instant::now();
    let Ok(mut bindings) = proxy.bindings.lock() else {
        return;
    };
    for (ip, ttl) in bound.iter().filter(|(ip, _)| global_address(*ip)) {
        let expires = now
            .checked_add(Duration::from_secs(u64::from(*ttl)))
            .unwrap_or(now);
        bindings
            .entry(*ip)
            .or_default()
            .insert(name.to_owned(), expires);
    }
}

/// The addresses a reply answers `query`'s question with, each with the
/// least TTL on its way: the IN A/AAAA records of the Answer section the
/// question's CNAME chain reaches, in any order (FIX 7652). None unless the
/// reply is a whole, successful answer to exactly that question.
fn bindings(query: &[u8], reply: &[u8]) -> Option<Vec<(IpAddr, u32)>> {
    let (qname, end) = question(query).ok()?;
    let qname = qname.to_ascii_lowercase();
    let qtail = query.get(end - 4..end)?;
    let wanted: &[u16] = match (
        u16::from_be_bytes([qtail[0], qtail[1]]),
        u16::from_be_bytes([qtail[2], qtail[3]]),
    ) {
        (TYPE_A, CLASS_IN) => &[TYPE_A],
        (TYPE_AAAA, CLASS_IN) => &[TYPE_AAAA],
        (TYPE_ANY, CLASS_IN) => &[TYPE_A, TYPE_AAAA],
        _ => return None,
    };
    let header = reply.get(..12)?;
    // The same ID; a response to a standard query, not truncated, NOERROR,
    // with one question.
    if header[..2] != query[..2]
        || header[2] & 0xfa != 0x80
        || header[3] & 0x0f != 0
        || header[4..6] != [0, 1]
    {
        return None;
    }
    let (name, at) = read_name(reply, 12)?;
    if name != qname || reply.get(at..at + 4)? != qtail {
        return None;
    }
    let mut at = at + 4;
    let mut aliases = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..u16::from_be_bytes([header[6], header[7]]) {
        let (owner, end) = read_name(reply, at)?;
        let record = reply.get(end..end + 10)?;
        let kind = u16::from_be_bytes([record[0], record[1]]);
        let class = u16::from_be_bytes([record[2], record[3]]);
        let ttl = ttl(u32::from_be_bytes([
            record[4], record[5], record[6], record[7],
        ]));
        let size = usize::from(u16::from_be_bytes([record[8], record[9]]));
        let data = reply.get(end + 10..end + 10 + size)?;
        at = end + 10 + size;
        if class != CLASS_IN {
            continue;
        }
        let ip = match kind {
            TYPE_A => IpAddr::from(<[u8; 4]>::try_from(data).ok()?),
            TYPE_AAAA => IpAddr::from(<[u8; 16]>::try_from(data).ok()?),
            TYPE_CNAME => {
                let (target, after) = read_name(reply, end + 10)?;
                if after != at {
                    return None;
                }
                aliases.push((owner, target, ttl));
                continue;
            }
            _ => continue,
        };
        if wanted.contains(&kind) {
            addresses.push((owner, ip, ttl));
        }
    }
    // The least TTL on the way from the question to each name its CNAME
    // chain reaches. A loop or a fork only lowers a TTL, so this ends.
    let mut reach = HashMap::from([(qname, u32::MAX)]);
    loop {
        let mut grew = false;
        for (owner, target, ttl) in &aliases {
            let Some(&via) = reach.get(owner) else {
                continue;
            };
            let ttl = via.min(*ttl);
            if reach.get(target).is_none_or(|known| ttl < *known) {
                reach.insert(target.clone(), ttl);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    Some(
        addresses
            .into_iter()
            .filter_map(|(owner, ip, ttl)| reach.get(&owner).map(|via| (ip, ttl.min(*via))))
            .collect(),
    )
}

/// A record's TTL; one with its top bit set is 0 (RFC 2181 8).
const fn ttl(raw: u32) -> u32 {
    if raw & 0x8000_0000 == 0 { raw } else { 0 }
}

/// The name at `at` in `message`, lowercased, and the offset after it in
/// place. A compression pointer goes strictly back, before where the labels
/// it ends began, so every name ends (RFC 1035 4.1.4). None for a name that
/// does not decode, or a label holding a dot.
fn read_name(message: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut run = at;
    let mut after = None;
    loop {
        let len = *message.get(at)?;
        match len & 0xc0 {
            0xc0 => {
                let target = usize::from(u16::from_be_bytes([len & 0x3f, *message.get(at + 1)?]));
                after.get_or_insert(at + 2);
                if target >= run {
                    return None;
                }
                (at, run) = (target, target);
            }
            0 => {
                at += 1;
                if len == 0 {
                    break;
                }
                labels.push(message.get(at..at + usize::from(len))?);
                at += usize::from(len);
            }
            _ => return None,
        }
    }
    let mut name = String::new();
    for label in labels {
        let label = std::str::from_utf8(label)
            .ok()
            .filter(|label| !label.contains('.'))?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&label.to_ascii_lowercase());
    }
    Some((name, after.unwrap_or(at)))
}

fn name_end(bytes: &[u8], mut at: usize) -> io::Result<usize> {
    for _ in 0..128 {
        let len = *bytes.get(at).ok_or_else(|| io::Error::other("DNS name"))?;
        if len & 0xc0 == 0xc0 {
            if bytes.get(at + 1).is_none() {
                return Err(io::Error::other("DNS pointer"));
            }
            return Ok(at + 2);
        }
        at += 1;
        if len == 0 {
            return Ok(at);
        }
        if len > 63 || at + len as usize > bytes.len() {
            return Err(io::Error::other("DNS label"));
        }
        at += len as usize;
    }
    Err(io::Error::other("DNS name bound"))
}
fn question(bytes: &[u8]) -> io::Result<(String, usize)> {
    if bytes.len() < 17 || bytes[2] & 0x78 != 0 || bytes[4..6] != [0, 1] {
        return Err(io::Error::other("DNS question"));
    }
    let mut labels = Vec::new();
    let mut at = 12;
    loop {
        let len = *bytes.get(at).ok_or_else(|| io::Error::other("DNS name"))? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 || at + len > bytes.len() || at + len > 267 {
            return Err(io::Error::other("DNS label"));
        }
        labels.push(std::str::from_utf8(&bytes[at..at + len]).map_err(io::Error::other)?);
        at += len;
    }
    if bytes.get(at..at + 4).is_none() {
        return Err(io::Error::other("DNS question tail"));
    }
    Ok((labels.join("."), at + 4))
}
/// Refuses a reply holding a non-public address in any section, as the
/// guest's DNS always has. It binds nothing: [`bindings`] reads what a reply
/// binds.
fn check_answers(bytes: &[u8]) -> io::Result<()> {
    let (_, mut at) = question(bytes)?;
    let count = u16::from_be_bytes([bytes[6], bytes[7]]) as usize
        + u16::from_be_bytes([bytes[8], bytes[9]]) as usize
        + u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
    for _ in 0..count {
        at = name_end(bytes, at)?;
        let header = bytes
            .get(at..at + 10)
            .ok_or_else(|| io::Error::other("DNS record"))?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let size = u16::from_be_bytes([header[8], header[9]]) as usize;
        at += 10;
        let data = bytes
            .get(at..at + size)
            .ok_or_else(|| io::Error::other("DNS record body"))?;
        let ip = match (kind, size) {
            (1, 4) => Some(IpAddr::V4(std::net::Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (28, 16) => Some(IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(data).map_err(io::Error::other)?,
            ))),
            _ => None,
        };
        if let Some(ip) = ip {
            if !global_address(ip) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "non-public DNS answer",
                ));
            }
        }
        at += size;
    }
    Ok(())
}
