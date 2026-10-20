//! The managed (hosted) node's web-fetch egress guard (SCAN C447). A hosted
//! node's fetcher never reaches the infrastructure it runs on: loopback,
//! link-local (169.254.0.0/16, fe80::/10), the node's own addresses and the
//! cloud metadata endpoints. A self-hosted node carries no guard: the owner's
//! own private services stay his to fetch.
//!
//! The guard judges RESOLVED addresses, never the URL's spelling. The fetcher
//! checks every page it is asked for, each crawl page included, before any
//! rung runs, and refuses it typed ([`WebFetchError::HostedInfrastructure`]).
//! The host's transport checks every address it connects to, a redirect's
//! included, through [`HostedEgressGuard::refuses`], and fails that connection
//! with [`HostedInfrastructureRefusal`], which the rung's diagnostic names.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;

use reqwest::Url;

use super::render::redact_url_credentials;
use super::{WebFetchError, WebFetchResult, WebFetcher};

/// The named reason every hosted-infrastructure refusal carries.
pub const HOSTED_INFRASTRUCTURE_REASON: &str = "hosted_infrastructure";

/// Cloud metadata endpoints outside link-local: Alibaba Cloud's, Oracle
/// Cloud's legacy one and Azure's platform (WireServer) address. The
/// link-local ones (169.254.169.254, 169.254.170.2, ...) are refused as
/// link-local.
const CLOUD_METADATA_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(192, 0, 0, 192),
    Ipv4Addr::new(168, 63, 129, 16),
];

/// Cloud metadata endpoints on IPv6: AWS's (fd00:ec2::254) and Google
/// Cloud's (fd20:ce::254).
const CLOUD_METADATA_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254),
];

/// What a hosted node's fetcher may not reach, judged by resolved address.
#[derive(Debug, Clone, Default)]
pub struct HostedEgressGuard {
    /// The node's own addresses, as its host found them.
    node: BTreeSet<IpAddr>,
}

impl HostedEgressGuard {
    /// A guard that also refuses each of `node`, the node's own addresses.
    #[must_use]
    pub fn new(node: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            node: node.into_iter().map(unwrapped).collect(),
        }
    }

    /// Whether `ip` is hosted infrastructure: loopback or "this host"
    /// (0.0.0.0/8, ::), link-local, a cloud metadata endpoint or one of the
    /// node's own addresses, an IPv4 address spelled inside IPv6
    /// (IPv4-mapped, IPv4-compatible, NAT64) judged as itself.
    #[must_use]
    pub fn refuses(&self, ip: IpAddr) -> bool {
        let ip = unwrapped(ip);
        self.node.contains(&ip)
            || match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.octets()[0] == 0
                        || v4.is_link_local()
                        || CLOUD_METADATA_V4.contains(&v4)
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_unicast_link_local()
                        || CLOUD_METADATA_V6.contains(&v6)
                }
            }
    }

    /// Refuses `url` when any address its host resolves to is hosted
    /// infrastructure. A host that does not resolve is left to the
    /// transport, which fails it as before.
    pub(super) fn admit(&self, url: &Url) -> WebFetchResult<()> {
        let Some(host) = url.host_str() else {
            return Ok(());
        };
        let literal = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        let refused = match literal.parse::<IpAddr>() {
            Ok(ip) => self.refuses(ip),
            Err(_) => (literal, url.port_or_known_default().unwrap_or(0))
                .to_socket_addrs()
                .is_ok_and(|mut addresses| addresses.any(|address| self.refuses(address.ip()))),
        };
        if refused {
            return Err(WebFetchError::HostedInfrastructure {
                url: redact_url_credentials(url.as_str()),
            });
        }
        Ok(())
    }
}

/// `ip`, with an IPv4 address embedded in IPv6 taken out, so one rule
/// judges every spelling of it.
fn unwrapped(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let segments = v6.segments();
    let nat64 = segments[..6] == [0x64_u16, 0xff9b, 0, 0, 0, 0];
    let compatible = segments[..6] == [0_u16; 6] && !v6.is_loopback() && !v6.is_unspecified();
    if nat64 || compatible {
        let [.., a, b, c, d] = v6.octets();
        return IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    }
    ip
}

/// The refusal a host's transport fails a connection to hosted
/// infrastructure with (its resolver's, or its redirect policy's), so the
/// rung's diagnostic names [`HOSTED_INFRASTRUCTURE_REASON`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HostedInfrastructureRefusal;

impl std::fmt::Display for HostedInfrastructureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "web fetch refused ({HOSTED_INFRASTRUCTURE_REASON}): on a hosted node, the destination resolves to the hosting infrastructure (loopback, link-local, this node's own address or a cloud metadata endpoint); a self-hosted node fetches it"
        )
    }
}

impl std::error::Error for HostedInfrastructureRefusal {}

impl WebFetcher {
    /// A managed (hosted) node's fetcher: every page it is asked for, each
    /// crawl page included, is refused before any rung runs when it resolves
    /// to hosted infrastructure (SCAN C447). A self-hosted node's fetcher
    /// carries no guard.
    #[must_use]
    pub fn with_hosted_egress_guard(mut self, guard: Arc<HostedEgressGuard>) -> Self {
        self.egress = Some(guard);
        self
    }

    /// The guard's check of `url`, when this fetcher carries one.
    pub(super) fn admit_destination(&self, url: &Url) -> WebFetchResult<()> {
        match &self.egress {
            Some(guard) => guard.admit(url),
            None => Ok(()),
        }
    }
}
