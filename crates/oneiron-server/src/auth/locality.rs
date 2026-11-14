//! Where the caller of a request sits (DEC-0005): on this device or off it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::{HeaderMap, request::Parts};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;

use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::server::SyncServer;

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
/// callers as local. A request managed ingress handed on
/// ([`ManagedIngress`](crate::managed::ManagedIngress)) came from its
/// supervisor on a caller's behalf, so it is off this device too, though it
/// reached a local socket (FIX 5125).
pub(crate) fn caller_locality(
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> CallerLocality {
    if forwarded(headers) || managed_ingress(extensions) {
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

/// Whether `config` runs the unauthenticated development hatch: with
/// `allow_unauthenticated` and no `auth_secret`, a request with no credential
/// acts as the owner. An empty secret counts as none, as serve's bind check
/// counts it.
pub(crate) fn runs_unauthenticated_hatch(config: &SyncServerConfig) -> bool {
    config.allow_unauthenticated && config.auth_secret.as_deref().is_none_or(str::is_empty)
}

/// Set once the first off-device caller of a hatch server is refused, so
/// the operator's warning is written once per process.
static OFF_DEVICE_HATCH_CALLER_WARNED: AtomicBool = AtomicBool::new(false);

/// A server that runs the unauthenticated development hatch answers only
/// callers on this device ([`caller_locality`]); any other request is refused
/// 401 before it reaches a route. Serve refuses to bind such a server
/// anywhere but loopback (`commands/serve.rs`); this judges each request
/// the same way, so an embedder that serves [`crate::build_app`] itself
/// (ARCH-0028 #unauth-loopback-open) keeps the hatch off the network too.
/// A connection the listener recorded no peer for is off this device, so
/// the app must be served with `into_make_service_with_connect_info`, as
/// [`crate::managed::BoundServeListener`] does. With a secret set, or the
/// hatch off, every request passes.
pub(crate) async fn refuse_off_device_hatch_callers(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    if runs_unauthenticated_hatch(&server.config)
        && matches!(
            caller_locality(request.headers(), request.extensions()),
            CallerLocality::OffDevice
        )
    {
        if !OFF_DEVICE_HATCH_CALLER_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "unauthenticated mode (allow_unauthenticated with no auth_secret) answers only callers on this device: a loopback peer, a local socket peer, or the in-process channel, with no forwarding header; a caller off this device, or on a connection that recorded no peer, is refused 401. Serve the app with into_make_service_with_connect_info on loopback, or set ONEIRON_AUTH_SECRET"
            );
        }
        return ApiError::unauthorized().into_response();
    }
    next.run(request).await
}

/// The machine a request's connection proved, beside its
/// [`caller_locality`] (mesh PR2b): the [`PeerMachine`] the binding door
/// verified from the request's own slip and machine proof, never a TCP
/// address or an owner principal. A request a proxy forwarded carries an
/// onward hop nobody proved, so it is `Unknown`; a header only narrows here
/// too. A request the binding door never saw is `Unknown`. Through managed
/// ingress the forwarding hop is the supervisor's own, which passes the
/// caller's slip, holder proof and machine proof on unchanged: the machine
/// that proof shows stays the request's, off this device (FIX 5125).
pub(crate) fn proved_peer(headers: &HeaderMap, extensions: &axum::http::Extensions) -> PeerMachine {
    if forwarded(headers) && !managed_ingress(extensions) {
        return PeerMachine::Unknown;
    }
    extensions
        .get::<PeerMachine>()
        .copied()
        .unwrap_or(PeerMachine::Unknown)
}

/// Whether `headers` carry any proxy forwarding header.
fn forwarded(headers: &HeaderMap) -> bool {
    FORWARDING_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
}

/// Whether managed ingress handed this request on.
fn managed_ingress(extensions: &axum::http::Extensions) -> bool {
    extensions.get::<crate::managed::ManagedIngress>().is_some()
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
        oneiron::settings::read_destination_at(self.locality, self.peer)
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
