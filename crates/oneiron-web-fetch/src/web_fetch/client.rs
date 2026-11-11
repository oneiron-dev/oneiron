//! The readability rung's HTTP client as a host builds it (FIX 7123,
//! FIX 4734). [`build_single_hop_client`] builds a client that follows no
//! redirect, and the readability rung takes it only as that
//! [`SingleHopClient`]: the rung follows each redirect hop itself, holding
//! it to a same-site crawl's pinned origin and checking it with a managed
//! node's guard before it is sent, so no client a host hands in follows a
//! hop unchecked. [`hosted_dns_resolver`] is that client's resolver alone,
//! for a host that drives its own requests, a browser's among them, on its
//! own async runtime (FIX 7122, FIX 7557).
//!
//! On a managed node every name the client connects to resolves through
//! the node's [`HostedEgressGuard`]: a name with any address that is hosted
//! infrastructure, or a private-network address while the name is no
//! operator origin's (FIX 7657), fails its connection with the
//! [`HostedEgressRefusal`](super::HostedEgressRefusal), and the connection
//! goes only to the addresses the guard just admitted. The client uses no
//! proxy, so nothing resolves the name elsewhere.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::Url;

use super::HostedEgressGuard;

/// A blocking client that follows no redirect, for the readability rung
/// ([`NativeReadabilityRenderer::new`](super::NativeReadabilityRenderer::new)),
/// built only by [`build_single_hop_client`]. Its client is private: the
/// rung sends one request per hop through it.
#[derive(Debug, Clone)]
pub struct SingleHopClient(reqwest::blocking::Client);

impl SingleHopClient {
    /// One GET of `url`, never followed past a redirect.
    pub(super) fn get(&self, url: Url) -> reqwest::blocking::RequestBuilder {
        self.0.get(url)
    }
}

/// The readability rung's client: no proxy, following no redirect, every
/// other setting reqwest's default. With `Some(guard)`, a managed node's:
/// every name it connects to resolves through `guard`, a name `guard`
/// refuses by its answers fails its connection with the
/// [`HostedEgressRefusal`](super::HostedEgressRefusal), and the connection
/// goes only to the addresses the guard admitted; the request keeps its URL,
/// so its Host header and TLS server name stay the requested name. With
/// `None`, the plain client a self-hosted node fetches with.
///
/// The rung checks each URL before this client sends it: the page, and each
/// redirect hop, which it follows itself (FIX 4734).
///
/// # Errors
/// Returns reqwest's error when the client cannot be built.
pub fn build_single_hop_client(
    guard: Option<Arc<HostedEgressGuard>>,
) -> reqwest::Result<SingleHopClient> {
    let builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    let builder = match guard {
        Some(guard) => builder.dns_resolver(Arc::new(HostedResolver(guard))),
        None => builder,
    };
    builder.build().map(SingleHopClient)
}

/// The guarded resolver as an async client takes it: every name the client
/// connects to resolves through `guard`, exactly as with
/// [`build_single_hop_client`]`(Some(guard))`, while the host drives its
/// requests on its own runtime, where each stays cancellable (FIX 7557).
pub fn hosted_dns_resolver(guard: Arc<HostedEgressGuard>) -> Arc<impl reqwest::dns::Resolve> {
    Arc::new(HostedResolver(guard))
}

/// A managed client's resolver: every name a fetch connects to, a
/// redirect's included, resolves here, and a name the guard refuses by its
/// answers ([`HostedEgressGuard::refuses_resolved`]) fails its connection.
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
    // Every address the name resolves to now, at connect time: a name that
    // rebinds after the engine's own check is refused here (FIX 6101).
    if let Some(refused) = guard.refuses_resolved(&host, addresses.iter().map(SocketAddr::ip)) {
        return Err(Box::new(refused));
    }
    Ok(Box::new(addresses.into_iter()))
}
