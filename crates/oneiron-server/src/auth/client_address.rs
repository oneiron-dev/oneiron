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
/// Then `X-Forwarded-For` is read right to left, across repeated fields: each
/// entry was appended by the hop to its right, so the walk continues only
/// while that hop is trusted, and the first address no trusted proxy vouches
/// for is the client. An entry that is not text or not an address ends the
/// walk at the last trusted hop; nothing left of it is read.
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
    let entries = headers
        .get_all("x-forwarded-for")
        .iter()
        .rev()
        .flat_map(|field| field.as_bytes().rsplit(|byte| *byte == b','));
    for entry in entries {
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

/// One entry as an address, with or without a port.
fn forwarded_address(entry: &[u8]) -> Option<IpAddr> {
    let entry = std::str::from_utf8(entry).ok()?.trim();
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
