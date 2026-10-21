//! The managed (hosted) node's web-fetch egress guard (SCAN C447). A hosted
//! node's fetcher never reaches the infrastructure it runs on: loopback,
//! link-local (169.254.0.0/16, fe80::/10), the node's own addresses and the
//! cloud metadata endpoints. A self-hosted node carries no guard: the owner's
//! own private services stay his to fetch.
//!
//! The guard judges RESOLVED addresses, never the URL's spelling, and reads
//! the node's own addresses afresh at every check, so an address assigned
//! after boot is refused too (FIX 6101). The fetcher checks every page it is
//! asked for, each crawl page included, before any rung runs; it hands each
//! rung the guard ([`Renderer::render_guarded`]) for the hops and addresses
//! the rung reaches, and checks the navigation-final URL every rung hands
//! back. The host's transport checks every address it connects to, a
//! redirect's included, through [`HostedEgressGuard::refuses_any`], and fails
//! that connection with [`HostedInfrastructureRefusal`]. Every one of these
//! refusals ends the ladder typed ([`WebFetchError::HostedInfrastructure`]).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use reqwest::Url;

use super::render::{redact_url_credentials, validated_web_url};
use super::{
    RenderedPage, Renderer, RendererError, RendererErrorKind, RendererResult, WebFetchError,
    WebFetchResult, WebFetcher,
};

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
#[derive(Clone)]
pub struct HostedEgressGuard {
    /// Reads the node's own addresses as its host finds them now: called at
    /// every check, never cached, so the guard follows address changes.
    node: Arc<dyn Fn() -> BTreeSet<IpAddr> + Send + Sync>,
}

impl std::fmt::Debug for HostedEgressGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedEgressGuard").finish_non_exhaustive()
    }
}

impl HostedEgressGuard {
    /// A guard that also refuses the node's own addresses, as `node_addresses`
    /// reads them at each check.
    #[must_use]
    pub fn new(node_addresses: impl Fn() -> BTreeSet<IpAddr> + Send + Sync + 'static) -> Self {
        Self {
            node: Arc::new(node_addresses),
        }
    }

    /// Whether `ip` is hosted infrastructure: loopback or "this host"
    /// (0.0.0.0/8, ::), link-local, a cloud metadata endpoint or one of the
    /// node's own addresses, an IPv4 address spelled inside IPv6
    /// (IPv4-mapped, IPv4-compatible, NAT64) judged as itself.
    #[must_use]
    pub fn refuses(&self, ip: IpAddr) -> bool {
        self.refuses_any([ip])
    }

    /// Whether any of `ips` is hosted infrastructure ([`Self::refuses`]),
    /// reading the node's own addresses at most once for the whole set.
    #[must_use]
    pub fn refuses_any(&self, ips: impl IntoIterator<Item = IpAddr>) -> bool {
        let mut node: Option<BTreeSet<IpAddr>> = None;
        ips.into_iter().map(unwrapped).any(|ip| {
            is_infrastructure(ip)
                || node
                    .get_or_insert_with(|| (self.node)().into_iter().map(unwrapped).collect())
                    .contains(&ip)
        })
    }

    /// Whether any address `url`'s host resolves to now is hosted
    /// infrastructure. A host that does not resolve is left to the
    /// transport, which fails it as before.
    fn reaches_infrastructure(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let literal = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        match literal.parse::<IpAddr>() {
            Ok(ip) => self.refuses(ip),
            Err(_) => (literal, url.port_or_known_default().unwrap_or(0))
                .to_socket_addrs()
                .is_ok_and(|addresses| self.refuses_any(addresses.map(|address| address.ip()))),
        }
    }

    /// Refuses `url`, a page the fetcher is asked for, when it resolves to
    /// hosted infrastructure.
    pub(super) fn admit(&self, url: &Url) -> WebFetchResult<()> {
        if self.reaches_infrastructure(url) {
            return Err(WebFetchError::HostedInfrastructure {
                url: redact_url_credentials(url.as_str()),
            });
        }
        Ok(())
    }

    /// Refuses the response a rung's client handed back when the address it
    /// actually came from (`peer`, when the client reports one) is hosted
    /// infrastructure: a final hop whose name was re-resolved (rebound) after
    /// any earlier check, whatever client the host supplied.
    pub(super) fn admit_peer(&self, peer: Option<SocketAddr>, url: &Url) -> RendererResult<()> {
        if peer.is_some_and(|peer| self.refuses(peer.ip())) {
            return Err(RendererError::hosted_infrastructure(format!(
                "the response for {} came from the hosting infrastructure: {HostedInfrastructureRefusal}",
                redact_url_credentials(url.as_str())
            )));
        }
        Ok(())
    }

    /// Refuses a page whose navigation-final URL, as its rung reported it,
    /// resolves to hosted infrastructure.
    fn admit_landing(&self, page: &RenderedPage) -> RendererResult<()> {
        let Some(landing) = page.final_url.as_deref().and_then(validated_web_url) else {
            return Ok(());
        };
        if self.reaches_infrastructure(&landing) {
            return Err(RendererError::hosted_infrastructure(format!(
                "the rung landed on {}: {HostedInfrastructureRefusal}",
                redact_url_credentials(landing.as_str())
            )));
        }
        Ok(())
    }
}

/// Whether `ip`, already unwrapped, is infrastructure on every node: loopback,
/// "this host", link-local or a cloud metadata endpoint.
fn is_infrastructure(ip: IpAddr) -> bool {
    match ip {
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
/// infrastructure with (its resolver's, or its redirect policy's); the rung
/// turns it into a [`RendererErrorKind::HostedInfrastructure`] error.
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

impl RendererError {
    /// A managed node's egress guard refused a hop, an address or a landing
    /// this rung reached (SCAN C447). The ladder stops on it and reports
    /// [`WebFetchError::HostedInfrastructure`]; no lower rung runs.
    #[must_use]
    pub fn hosted_infrastructure(message: impl Into<String>) -> Self {
        Self {
            kind: RendererErrorKind::HostedInfrastructure,
            message: message.into(),
        }
    }
}

impl WebFetcher {
    /// Makes this a managed (hosted) node's fetcher (SCAN C447): every page
    /// it is asked for, each crawl page included, is refused before any rung
    /// runs when it resolves to hosted infrastructure; each rung renders with
    /// the guard ([`Renderer::render_guarded`]); and the navigation-final URL
    /// each rung hands back is checked too. Takes a shared reference, so a
    /// host installs it on a ladder it was handed, at first use; a fetcher
    /// that already carries a guard keeps it. A self-hosted node's fetcher
    /// carries none.
    pub fn install_hosted_egress_guard(&self, guard: Arc<HostedEgressGuard>) {
        // `Err` only hands back `guard` when one is already installed.
        let _ = self.egress.set(guard);
    }

    /// The guard's check of `url`, when this fetcher carries one.
    pub(super) fn admit_destination(&self, url: &Url) -> WebFetchResult<()> {
        match self.egress.get() {
            Some(guard) => guard.admit(url),
            None => Ok(()),
        }
    }

    /// Runs one rung: unguarded on a self-hosted node; on a managed one
    /// through [`Renderer::render_guarded`], with the navigation-final URL it
    /// hands back checked as well (FIX 6101).
    pub(super) fn render_rung(
        &self,
        renderer: &dyn Renderer,
        url: &str,
    ) -> RendererResult<RenderedPage> {
        let Some(guard) = self.egress.get() else {
            return renderer.render(url);
        };
        let page = renderer.render_guarded(url, guard)?;
        guard.admit_landing(&page)?;
        Ok(page)
    }
}
