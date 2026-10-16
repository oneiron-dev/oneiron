//! DNS goes to the host's resolver through the same proxy. All query types
//! relay by default; A/AAAA answers still get the shared public-address check.
use super::*;

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
            let socket = UdpSocket::bind(if resolver.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })?;
            socket.set_read_timeout(Some(proxy.config.request_timeout))?;
            socket.connect(SocketAddr::new(resolver, 53))?;
            socket.send(query)?;
            let mut answer = vec![0; 65536];
            match socket.recv(&mut answer) {
                Ok(n) => {
                    answer.truncate(n);
                    if answer.len() < 12 || answer[..2] != query[..2] || answer[2] & 0x80 == 0 {
                        return Err(io::Error::other("invalid host DNS reply"));
                    }
                    if answer[2] & 2 != 0 {
                        use std::io::{Read, Write};
                        let mut stream = TcpStream::connect_timeout(
                            &SocketAddr::new(resolver, 53),
                            proxy.config.request_timeout,
                        )?;
                        stream.set_read_timeout(Some(proxy.config.request_timeout))?;
                        stream.set_write_timeout(Some(proxy.config.request_timeout))?;
                        stream.write_all(&(query.len() as u16).to_be_bytes())?;
                        stream.write_all(query)?;
                        let mut len = [0; 2];
                        stream.read_exact(&mut len)?;
                        answer.resize(u16::from_be_bytes(len) as usize, 0);
                        stream.read_exact(&mut answer)?;
                        if answer.len() < 12 || answer[..2] != query[..2] {
                            return Err(io::Error::other("invalid TCP DNS reply"));
                        }
                    }
                    check_answers(proxy, &host, &answer)?;
                    return Ok((host, answer));
                }
                Err(e) => error = e,
            }
        }
        Err(error)
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
fn check_answers(proxy: &OpenEgressProxy, host: &str, bytes: &[u8]) -> io::Result<()> {
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
            let mut resolutions = proxy
                .resolutions
                .lock()
                .map_err(|_| io::Error::other("DNS state poisoned"))?;
            let names = resolutions.entry(ip).or_default();
            if !names.iter().any(|h| h == host) {
                names.push(host.to_owned());
            }
        }
        at += size;
    }
    Ok(())
}
