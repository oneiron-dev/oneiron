//! The address a request's client is charged under: the key booking
//! admission counts per-address quotas by.
//!
//! It is never a locality input. [`caller_locality`](super::caller_locality)
//! decides whether a caller sits on this device, and there a forwarding header
//! only ever narrows; nothing here can make a caller local.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{Extensions, HeaderMap, request::Parts};

use crate::config::TrustedProxy;
use crate::managed::UnixPeer;
use crate::server::SyncServer;

/// The client address of one request.
///
/// The connection's own peer, unless that peer is a configured trusted proxy.
/// Then `X-Forwarded-For` is read right to left: each entry was appended by
/// the hop to its right, so the walk continues only while that hop is
/// trusted, and the first address no trusted proxy vouches for is the client.
/// An entry that does not parse ends the walk at the last trusted hop.
///
/// A kernel-verified peer on the managed socket is the supervisor. It is
/// charged as loopback and its forwarding headers are not read: the managed
/// contract believes no header the supervisor did not sign, and it signs no
/// client address.
///
/// `None` when the connection recorded no peer to start from: a caller that
/// cannot be told apart from every other must not share or mint a bucket.
pub(crate) fn client_address(
    headers: &HeaderMap,
    extensions: &Extensions,
    trusted: &[TrustedProxy],
) -> Option<IpAddr> {
    let trusts = |ip: IpAddr| trusted.iter().any(|proxy| proxy.contains(ip));
    let Some(ConnectInfo(peer)) = extensions.get::<ConnectInfo<SocketAddr>>() else {
        let supervisor = extensions
            .get::<ConnectInfo<UnixPeer>>()
            .is_some_and(|ConnectInfo(peer)| peer.verified());
        return supervisor.then_some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    };
    let mut client = peer.ip().to_canonical();
    if !trusts(client) {
        return Some(client);
    }
    for entry in forwarded_for(headers).iter().rev() {
        let Some(hop) = forwarded_address(entry) else {
            break;
        };
        client = hop;
        if !trusts(hop) {
            break;
        }
    }
    Some(client)
}

/// Every `X-Forwarded-For` entry, oldest first, across repeated headers. A
/// header that is not text makes the whole chain unreadable.
fn forwarded_for(headers: &HeaderMap) -> Vec<&str> {
    let mut entries = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            return Vec::new();
        };
        entries.extend(value.split(',').map(str::trim));
    }
    entries
}

/// One entry as an address, with or without a port.
fn forwarded_address(entry: &str) -> Option<IpAddr> {
    entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<SocketAddr>().map(|address| address.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

/// The request's [`client_address`] under the server's `trusted_proxies`.
pub(crate) struct ClientAddress(pub(crate) Option<IpAddr>);

impl FromRequestParts<Arc<SyncServer>> for ClientAddress {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(client_address(
            &parts.headers,
            &parts.extensions,
            &server.config.trusted_proxies,
        )))
    }
}
