//! Where the caller of a request sits (DEC-0005): on this device or off it.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{HeaderMap, request::Parts};
use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;

/// Proxy forwarding headers. A request that carries any of them came through
/// a proxy on someone else's behalf.
const FORWARDING_HEADERS: [&str; 4] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
];

/// Where the caller of a request sits (DEC-0005): a TCP peer on loopback, or
/// a kernel-verified peer on the local socket, is on this device. Any other
/// peer, or a connection the listener recorded no peer for, is off it. A
/// request carrying a proxy forwarding header is off it even on loopback: a
/// header can only narrow, never widen, so a spoofed one costs its sender
/// only. A reverse proxy on this device that adds no such header passes its
/// callers as local.
pub(crate) fn caller_locality(
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> CallerLocality {
    if FORWARDING_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return CallerLocality::OffDevice;
    }
    let loopback = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| peer.ip().to_canonical().is_loopback());
    let local_socket = extensions
        .get::<ConnectInfo<crate::managed::UnixPeer>>()
        .is_some_and(|ConnectInfo(peer)| peer.verified());
    if loopback || local_socket {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    }
}

/// The machine a request's connection proved, beside its
/// [`caller_locality`] (mesh PR2b): the [`PeerMachine`] the binding door
/// verified from the request's own slip and machine proof, never a TCP
/// address or an owner principal. A request a proxy forwarded carries an
/// onward hop nobody proved, so it is `Unknown`; a header only narrows here
/// too. A request the binding door never saw is `Unknown`.
pub(crate) fn proved_peer(headers: &HeaderMap, extensions: &axum::http::Extensions) -> PeerMachine {
    if FORWARDING_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return PeerMachine::Unknown;
    }
    extensions
        .get::<PeerMachine>()
        .copied()
        .unwrap_or(PeerMachine::Unknown)
}

impl super::CoreAuth {
    /// This caller, on a connection that proved `peer` (mesh PR2b).
    #[must_use]
    pub(crate) fn toward(mut self, peer: PeerMachine) -> Self {
        self.peer = peer;
        self
    }

    /// The machine this caller's connection proved, or `Unknown`.
    pub(crate) fn peer(&self) -> PeerMachine {
        self.peer
    }

    /// Where this caller's rows go: its locality, with the machine its
    /// connection proved. Every read and release judges the world settings
    /// for that machine again in its own snapshot; only an unproved one is
    /// an unknown destination.
    pub(crate) fn destination(&self) -> oneiron::settings::ReadDestination {
        oneiron::settings::ReadDestination::at(self.locality, self.peer)
    }
}

/// The request's [`caller_locality`], for a handler that reads without a
/// [`CoreAuth`](super::CoreAuth).
pub(crate) struct Locality(pub(crate) CallerLocality);

impl<S: Send + Sync> FromRequestParts<S> for Locality {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(caller_locality(&parts.headers, &parts.extensions)))
    }
}
