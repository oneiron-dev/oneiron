//! `trusted_proxies`: the reverse proxies whose `X-Forwarded-For` entries the
//! server believes when it keys a request by client address.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// One trusted proxy address block: `ip/prefix`, or a bare address for one
/// host. Parsed at startup, so an entry the server cannot read stops serve
/// instead of quietly trusting nothing or everything. A `/0` block, which
/// would believe every caller, and an address with bits set past its prefix,
/// which would trust a whole network where one host was meant, are refused.
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
        let ip = ip.to_canonical();
        let block_of_ip = Self {
            network: ip,
            prefix: self.prefix,
        };
        ip.is_ipv4() == self.network.is_ipv4() && block_of_ip.masked() == self.network
    }

    /// The block's address with every bit past its prefix cleared.
    fn masked(&self) -> IpAddr {
        match self.network {
            IpAddr::V4(network) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4((u32::from(network) & mask).into())
            }
            IpAddr::V6(network) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6((u128::from(network) & mask).into())
            }
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
        // The prefix is read in the family the address is written in.
        let network = address.parse::<IpAddr>().map_err(|_| unreadable())?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| (1..=width).contains(prefix))
                .ok_or_else(unreadable)?,
            None => width,
        };
        let block = Self { network, prefix };
        let masked = block.masked();
        if masked != network {
            return Err(format!(
                "trusted proxy {value:?} has host bits set; write {masked}/{prefix} for the network or the address alone for one host"
            ));
        }
        // An IPv4-mapped block is the IPv4 block it covers. One reaching past
        // the mapped range, or all of it, would be IPv4 /0 or wider.
        match network.to_canonical() {
            IpAddr::V4(ipv4) if network.is_ipv6() => Ok(Self {
                network: IpAddr::V4(ipv4),
                prefix: prefix
                    .checked_sub(96)
                    .filter(|prefix| *prefix > 0)
                    .ok_or_else(unreadable)?,
            }),
            _ => Ok(block),
        }
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
