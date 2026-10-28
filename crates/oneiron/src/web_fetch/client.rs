//! The readability rung's HTTP client as a host builds it (FIX 7123). The
//! server builds its default ladder's client here, and a host that supplies
//! its own ladder builds the same client through [`build_web_fetch_client`],
//! so on a managed (hosted) node an injected ladder's client checks every
//! redirect hop too. [`build_single_hop_client`] is that client for one
//! request at a time, for a host that performs each request a browser makes
//! (FIX 7122). [`hosted_dns_resolver`] is that client's resolver alone, for
//! a host that drives those requests on its own async runtime (FIX 7557).
//!
//! On a managed node every name either client connects to resolves through
//! the node's [`HostedEgressGuard`]: a name with any address that is hosted
//! infrastructure, or a private-network address while the name is no
//! operator origin's (FIX 7657), fails its connection with the
//! [`HostedEgressRefusal`](super::HostedEgressRefusal), and the connection
//! goes only to the addresses the guard just admitted. Neither client uses a
//! proxy, so nothing resolves the name elsewhere.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::HostedEgressGuard;

/// The readability rung's client: no proxy, every other setting reqwest's
/// default. With `Some(guard)`, a managed node's client: every name it
/// connects to, a redirect's included, resolves through `guard`, and a
/// redirect `guard` refuses (an address literal it refuses, or a listed
/// private name at an origin no entry lists) fails with the
/// [`HostedEgressRefusal`](super::HostedEgressRefusal); other redirects
/// follow reqwest's default policy. With `None`, the plain client a
/// self-hosted node fetches with.
///
/// The ladder still checks the page it is asked for, an address literal
/// included, before this client sends the request.
///
/// # Errors
/// Returns reqwest's error when the client cannot be built.
pub fn build_web_fetch_client(
    guard: Option<Arc<HostedEgressGuard>>,
) -> reqwest::Result<reqwest::blocking::Client> {
    no_proxy_client(guard.map(|guard| (Arc::clone(&guard), hosted_redirects(guard))))
}

/// A managed node's client for exactly one request: the guarded client of
/// [`build_web_fetch_client`], following no redirect, for a host that
/// performs each request a browser makes, every redirect hop included, as
/// its own request (FIX 7122). Each connection resolves its name once,
/// through `guard`, and goes only to the addresses the guard admitted; the
/// request keeps its URL, so its Host header and TLS server name stay the
/// requested name. An address-literal URL resolves nothing: its caller checks
/// that address with [`HostedEgressGuard::check_request`] before sending,
/// and a named one's origin with [`HostedEgressGuard::refuses_origin`].
///
/// # Errors
/// Returns reqwest's error when the client cannot be built.
pub fn build_single_hop_client(
    guard: Arc<HostedEgressGuard>,
) -> reqwest::Result<reqwest::blocking::Client> {
    no_proxy_client(Some((guard, reqwest::redirect::Policy::none())))
}

/// The guarded resolver as an async client takes it: every name the client
/// connects to resolves through `guard`, exactly as with
/// [`build_single_hop_client`], while the host drives its requests on its
/// own runtime, where each stays cancellable (FIX 7557).
pub fn hosted_dns_resolver(guard: Arc<HostedEgressGuard>) -> Arc<impl reqwest::dns::Resolve> {
    Arc::new(HostedResolver(guard))
}

/// The body both builders share: a client with no proxy; with `guarded`, its
/// guard resolves every name the client connects to and its policy decides
/// each redirect, and without, reqwest's defaults stand.
fn no_proxy_client(
    guarded: Option<(Arc<HostedEgressGuard>, reqwest::redirect::Policy)>,
) -> reqwest::Result<reqwest::blocking::Client> {
    let builder = reqwest::blocking::Client::builder().no_proxy();
    let builder = match guarded {
        Some((guard, redirects)) => builder
            .dns_resolver(Arc::new(HostedResolver(guard)))
            .redirect(redirects),
        None => builder,
    };
    builder.build()
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

/// The default redirect policy, with a hop to an address literal the guard
/// refuses, and every hop to a listed private name at an origin no entry
/// lists (FIX 7657), refused: a named hop's addresses are checked by
/// [`HostedResolver`] when it connects.
fn hosted_redirects(guard: Arc<HostedEgressGuard>) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let url = attempt.url();
        let literal = url
            .host_str()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|host| host.parse::<IpAddr>().ok());
        let refused = match literal {
            Some(ip) => guard.refuses(ip),
            None => guard.refuses_origin(url),
        };
        if let Some(refused) = refused {
            return attempt.error(refused);
        }
        reqwest::redirect::Policy::default().redirect(attempt)
    })
}
