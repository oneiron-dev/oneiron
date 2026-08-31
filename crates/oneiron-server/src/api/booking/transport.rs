use std::net::{IpAddr, Ipv4Addr};

use axum::http::HeaderMap;

use super::{BookingTransport, BookingTransportContext};
use crate::api::check_api_auth;
use crate::error::ApiError;
use crate::server::SyncServer;

/// Builds the transport context for one HTTP request.
///
/// The bearer check is the existing `check_api_auth` door. The actor
/// reference, when the credential carries one, is read from the authenticated
/// principal — never from the request body.
pub(super) fn http_transport_context(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<BookingTransportContext, ApiError> {
    check_api_auth(headers, server)?;
    Ok(BookingTransportContext {
        source_ip: request_source_ip(headers),
        authenticated_actor_ref: None,
        transport: BookingTransport::PublicHttp,
    })
}

/// The caller address admission keys on.
///
/// The app is served without connection-info state, so the forwarding header
/// a reverse proxy sets is the connection evidence available. With no header
/// the request came over the loopback listener and is keyed as such — never as
/// an absent or wildcard address, which would merge every caller into one
/// bucket.
fn request_source_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}
