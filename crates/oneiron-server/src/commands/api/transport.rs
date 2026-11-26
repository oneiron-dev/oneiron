//! How curl reaches the server for one `oneiron api` call beyond the request
//! itself: the connect pin (`--resolve-address`) and the transfer deadline
//! (`--max-time`).

use std::net::IpAddr;

use super::normalized_base;

/// The longest `--max-time` handed to curl. curl keeps the deadline in
/// milliseconds in a C `long`, 32 bits on some hosts, and refuses a larger
/// one only once it runs, after this process has read the body.
const MAX_TIME_SECS_LIMIT: u64 = i32::MAX as u64 / 1000;

/// How curl reaches the server for one call, beyond the request itself. The
/// default is curl's own: a name lookup for the host, and no deadline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CurlTransport {
    /// One curl `--resolve` value, `host:port:addr[,addr]...`, built by
    /// [`curl_transport`] from the base URL, so it names no other host or port.
    pub(crate) resolve: Option<String>,
    /// curl's `--max-time`: whole seconds, from 1 to `MAX_TIME_SECS_LIMIT`.
    pub(crate) max_time_secs: Option<u64>,
}

/// The transport `--resolve-address` and `--max-time` ask for, checked against
/// the base URL before anything is read or sent.
///
/// The pin is for the base URL's own host and port (the scheme's default when
/// it names none), so the host must be a name curl looks up, without user
/// info, and each address an IP address. A deadline of zero (curl's "none")
/// or past curl's range is refused. No message quotes the base URL, which can
/// carry a password in its user info.
pub(crate) fn curl_transport(
    base_url: &str,
    addresses: &[String],
    max_time_secs: Option<u64>,
) -> anyhow::Result<CurlTransport> {
    if let Some(secs) = max_time_secs {
        anyhow::ensure!(
            (1..=MAX_TIME_SECS_LIMIT).contains(&secs),
            "--max-time must be from 1 to {MAX_TIME_SECS_LIMIT} seconds; nothing was sent"
        );
    }
    if addresses.is_empty() {
        return Ok(CurlTransport {
            resolve: None,
            max_time_secs,
        });
    }
    let base = normalized_base(base_url).map_err(|_| {
        anyhow::anyhow!(
            "--resolve-address needs a plain http(s) origin as the base URL; nothing was sent"
        )
    })?;
    let (scheme, authority) = base.split_once("://").unwrap_or_default();
    anyhow::ensure!(
        !authority.contains('@'),
        "--resolve-address needs a base URL without user info; nothing was sent"
    );
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !authority.starts_with('[') => (host, port),
        _ => (authority, if scheme == "https" { "443" } else { "80" }),
    };
    anyhow::ensure!(
        is_host_name(host),
        "--resolve-address needs a host name in the base URL, not an address; nothing was sent"
    );
    anyhow::ensure!(
        port.parse::<u16>().is_ok_and(|port| port != 0),
        "the base URL's port must be a number from 1 to 65535; nothing was sent"
    );
    let mut pinned: Vec<String> = Vec::new();
    for address in addresses {
        let address: IpAddr = address
            .parse()
            .map_err(|_| anyhow::anyhow!("--resolve-address must be an IP address: {address:?}"))?;
        let address = match address {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        if !pinned.contains(&address) {
            pinned.push(address);
        }
    }
    Ok(CurlTransport {
        resolve: Some(format!("{host}:{port}:{}", pinned.join(","))),
        max_time_secs,
    })
}

/// A name curl looks up, as opposed to an address literal in any spelling
/// curl reads as one: dotted (`192.0.2.7`), shortened (`127.1`), octal or hex
/// parts (`0177.0.0.1`, `0x7f.1`), one number (`2130706433`), or bracketed
/// IPv6. A name's last label is never all digits (RFC 3696 section 2), so a
/// last label of digits or of a `0x` number marks an address. Every label is
/// a DNS label: not empty, and starting and ending with a letter or digit, so
/// the `--resolve` entry never starts with `-` (curl's "remove this entry").
fn is_host_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    // ASCII first: the label checks below slice by byte.
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return false;
    }
    if name
        .split('.')
        .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
    {
        return false;
    }
    let last = name.rsplit('.').next().unwrap_or_default();
    let digits = last.bytes().all(|b| b.is_ascii_digit());
    let hex = last.len() >= 2
        && last[..2].eq_ignore_ascii_case("0x")
        && last[2..].bytes().all(|b| b.is_ascii_hexdigit());
    !last.is_empty() && !digits && !hex && name.parse::<IpAddr>().is_err()
}
