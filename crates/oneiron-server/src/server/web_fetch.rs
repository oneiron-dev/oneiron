//! The host owns renderer configuration; acquisition itself stays in the engine.
//!
//! A managed (hosted) node's fetcher never reaches the infrastructure it runs
//! on (SCAN C447): the engine refuses each page it is asked for, typed, and
//! this client refuses every address it connects to, a redirect's included,
//! with the same [`HostedEgressGuard`]. A self-hosted node fetches as before.
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::web_fetch::{
    HostedEgressGuard, HostedInfrastructureRefusal, NativeReadabilityRenderer, WebFetcher,
};

use super::SyncServer;

impl SyncServer {
    /// Supplies the host's fixed renderer ladder, including any isolated
    /// headless or self-hosted Firecrawl adapters. No caller controls it.
    #[must_use]
    pub fn with_web_fetcher(mut self, fetcher: WebFetcher) -> Self {
        self.web_fetcher = std::sync::OnceLock::from(Arc::new(fetcher));
        self
    }

    /// Called off the async runtime. The default rung is a credential-free
    /// native GET; a host that supplies a ladder keeps that exact ladder. On
    /// a managed node the default ladder carries the hosted egress guard.
    pub(crate) fn web_fetcher(&self) -> MemoryResult<Arc<WebFetcher>> {
        if let Some(fetcher) = self.web_fetcher.get() {
            return Ok(Arc::clone(fetcher));
        }
        // The managed switch every hosted-only rule reads: set only by
        // managed boot.
        let guard = self
            .managed_issuer
            .is_some()
            .then(|| Arc::new(HostedEgressGuard::new(node_addresses())));
        let builder = reqwest::blocking::Client::builder().no_proxy();
        let builder = match &guard {
            Some(guard) => builder
                .dns_resolver(Arc::new(HostedResolver(Arc::clone(guard))))
                .redirect(hosted_redirects(Arc::clone(guard))),
            None => builder,
        };
        let client = builder.build().map_err(|_| {
            MemoryError::new("WEB_FETCH_FAILED", "web HTTP client unavailable", &[])
        })?;
        let mut fetcher = WebFetcher::new(Arc::new(NativeReadabilityRenderer::new(client)))
            .map_err(|error| MemoryError::new("WEB_FETCH_FAILED", error.to_string(), &[]))?;
        if let Some(guard) = guard {
            fetcher = fetcher.with_hosted_egress_guard(guard);
        }
        Ok(Arc::clone(
            self.web_fetcher.get_or_init(|| Arc::new(fetcher)),
        ))
    }
}

/// A managed client's resolver: every name a fetch connects to, a
/// redirect's included, resolves here, and a name that resolves to hosted
/// infrastructure fails its connection.
struct HostedResolver(Arc<HostedEgressGuard>);

impl reqwest::dns::Resolve for HostedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(resolve_admitted(
            Arc::clone(&self.0),
            name.as_str().to_owned(),
        ))
    }
}

async fn resolve_admitted(
    guard: Arc<HostedEgressGuard>,
    host: String,
) -> Result<reqwest::dns::Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
    if addresses.iter().any(|address| guard.refuses(address.ip())) {
        return Err(Box::new(HostedInfrastructureRefusal));
    }
    Ok(Box::new(addresses.into_iter()))
}

/// The default redirect policy, with a hop to an address literal that is
/// hosted infrastructure refused: a named hop is checked by
/// [`HostedResolver`] when it connects.
fn hosted_redirects(guard: Arc<HostedEgressGuard>) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let literal = attempt
            .url()
            .host_str()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|host| host.parse::<IpAddr>().ok());
        if literal.is_some_and(|ip| guard.refuses(ip)) {
            return attempt.error(HostedInfrastructureRefusal);
        }
        reqwest::redirect::Policy::default().redirect(attempt)
    })
}

/// This node's own addresses, as far as the standard library reaches them:
/// the source address it sends from on each family (a connected UDP socket
/// sends nothing), and on Linux every local address the kernel lists.
fn node_addresses() -> BTreeSet<IpAddr> {
    let mut found = BTreeSet::new();
    let probes = [
        (
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 80)),
        ),
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 80)),
        ),
    ];
    for (bind, probe) in probes {
        if let Ok(socket) = UdpSocket::bind(bind)
            && socket.connect(probe).is_ok()
            && let Ok(local) = socket.local_addr()
        {
            found.insert(local.ip());
        }
    }
    #[cfg(target_os = "linux")]
    kernel_local_addresses(&mut found);
    found
}

/// Every local address the Linux kernel lists: IPv4 from the local routing
/// table, IPv6 from the interface list. A table that does not read adds none.
#[cfg(target_os = "linux")]
fn kernel_local_addresses(found: &mut BTreeSet<IpAddr>) {
    if let Ok(table) = std::fs::read_to_string("/proc/net/fib_trie") {
        let mut last = None;
        for line in table.lines().map(str::trim) {
            if let Some(address) = line.strip_prefix("|-- ") {
                last = address.parse::<Ipv4Addr>().ok();
            } else if line.ends_with("host LOCAL")
                && let Some(address) = last
            {
                found.insert(IpAddr::V4(address));
            }
        }
    }
    if let Ok(table) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in table.lines() {
            if let Some(address) = line
                .split_whitespace()
                .next()
                .and_then(|hex| u128::from_str_radix(hex, 16).ok())
            {
                found.insert(IpAddr::V6(Ipv6Addr::from(address)));
            }
        }
    }
}
