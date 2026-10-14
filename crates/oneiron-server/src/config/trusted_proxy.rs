//! `trusted_proxies`: the reverse proxies whose `X-Forwarded-For` entries the
//! server believes when it keys a request by client address.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// One trusted proxy address block: `ip/prefix`, or a bare address for one
/// host. Parsed at startup, so an entry the server cannot read stops serve
/// instead of quietly trusting nothing or everything.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    /// Whether `ip` sits inside this block. An IPv4-mapped IPv6 address is
    /// judged as the IPv4 address it carries.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for TrustedProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let unreadable = || format!("trusted proxy {value:?} is not an address or ip/prefix");
        let (address, prefix) = match value.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value.trim(), None),
        };
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| unreadable())?
            .to_canonical();
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= width)
                .ok_or_else(unreadable)?,
            None => width,
        };
        Ok(Self { network, prefix })
    }
}

impl fmt::Debug for TrustedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Parses every configured entry, refusing the first one it cannot read.
pub(super) fn parse_trusted_proxies(values: &[String]) -> anyhow::Result<Vec<TrustedProxy>> {
    values
        .iter()
        .map(|value| value.parse().map_err(anyhow::Error::msg))
        .collect()
}
