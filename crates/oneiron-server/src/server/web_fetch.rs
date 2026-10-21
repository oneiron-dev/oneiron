//! The host owns renderer configuration; acquisition itself stays in the engine.
//!
//! A managed (hosted) node's fetcher never reaches the infrastructure it runs
//! on (SCAN C447), nor a private network (RFC1918, CGNAT, ULA) except at the
//! private origins the operator passed (`--hosted-private-origin`, FIX 7657):
//! the engine refuses each page it is asked for and each hop, address and
//! landing its rungs reach, typed, and the client the engine's
//! [`build_web_fetch_client`] builds here refuses every address it connects
//! to, a redirect's included, with the same [`HostedEgressGuard`]. The guard
//! reads the node's own addresses afresh at each check, and a ladder the host
//! supplied carries it too (FIX 6101). A self-hosted node fetches as before.
//!
//! A managed node whose host names a `[browser]` guest renders its default
//! ladder's second rung in a fresh guest of that image per render (FIX 7122,
//! `headless`): every request, redirect and connection of the render is
//! checked with the same guard. Without `[browser]`, and on a self-hosted
//! node, the default ladder is readability only, as before.
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::web_fetch::{
    HostedEgressGuard, NativeHeadlessRenderer, NativeReadabilityRenderer, WebFetchError,
    WebFetcher, build_web_fetch_client,
};

use super::{HandleLine, SyncServer};

mod headless;

impl SyncServer {
    /// Supplies the host's fixed renderer ladder, including any isolated
    /// headless or self-hosted Firecrawl adapters. No caller controls it. On
    /// a managed node it carries the hosted egress guard like the default
    /// ladder (FIX 6101), installed at first use. A managed host builds that
    /// ladder's readability client with
    /// [`build_web_fetch_client`]`(Some(guard))`, so every redirect hop it
    /// follows is checked too (FIX 7123); a client built otherwise is used
    /// as supplied.
    #[must_use]
    pub fn with_web_fetcher(mut self, fetcher: WebFetcher) -> Self {
        self.web_fetcher = std::sync::OnceLock::from(Arc::new(fetcher));
        self
    }

    /// Called off the async runtime. The default rung is a credential-free
    /// native GET, with the host's headless browser after it on a managed
    /// node with a `[browser]` guest (FIX 7122); a host that supplies a
    /// ladder keeps that exact ladder. On a managed node every ladder, a
    /// supplied one included, carries the hosted egress guard.
    pub(crate) fn web_fetcher(&self) -> MemoryResult<Arc<WebFetcher>> {
        // The managed switch every hosted-only rule reads: set only by
        // managed boot, which alone passes the operator's private origins.
        let guard = self.managed_issuer.is_some().then(|| {
            Arc::new(HostedEgressGuard::new(
                node_addresses,
                self.config.hosted_private_origins.clone(),
            ))
        });
        let fetcher = match self.web_fetcher.get() {
            Some(fetcher) => Arc::clone(fetcher),
            None => {
                // A managed node with a `[browser]` guest renders the second
                // rung in it (FIX 7122); every other default ladder is
                // readability only.
                let headless = guard.as_ref().and(self.browser_guest()).map(|guest| {
                    headless::GuestHeadless::new(
                        guest.clone(),
                        HandleLine::of(self),
                        Arc::clone(self.vault()),
                        self.browser_readiness().clone(),
                    )
                });
                let fetcher = default_web_fetcher(guard.as_ref(), headless)?;
                Arc::clone(self.web_fetcher.get_or_init(|| Arc::new(fetcher)))
            }
        };
        // Installed here, at first use, and not by the builder: managed boot
        // sets the switch after the builder chain, so only now is it final.
        // Every fetch reaches the ladder through this call, so none runs
        // unguarded on a managed node (FIX 6101).
        if let Some(guard) = guard {
            fetcher.install_hosted_egress_guard(guard);
        }
        Ok(fetcher)
    }
}

/// The default ladder: one credential-free native GET rung, its client
/// checking every connection with the guard on a managed node, then the
/// host's `headless` browser where a managed node has one.
fn default_web_fetcher(
    guard: Option<&Arc<HostedEgressGuard>>,
    headless: Option<headless::GuestHeadless>,
) -> MemoryResult<WebFetcher> {
    let client = build_web_fetch_client(guard.cloned())
        .map_err(|_| MemoryError::new("WEB_FETCH_FAILED", "web HTTP client unavailable", &[]))?;
    let failed =
        |error: WebFetchError| MemoryError::new("WEB_FETCH_FAILED", error.to_string(), &[]);
    let fetcher =
        WebFetcher::new(Arc::new(NativeReadabilityRenderer::new(client))).map_err(failed)?;
    match headless {
        Some(headless) => fetcher
            .with_headless(Arc::new(NativeHeadlessRenderer::new(Arc::new(headless))))
            .map_err(failed),
        None => Ok(fetcher),
    }
}

/// This node's own addresses, as far as the standard library reaches them:
/// the source address it sends from on each family (a connected UDP socket
/// sends nothing), and on Linux, where managed nodes run, every local address
/// the kernel lists. The guard calls it at every check, so an address
/// assigned after boot is refused too (FIX 6101); each call is a few
/// syscalls and two small procfs reads.
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
