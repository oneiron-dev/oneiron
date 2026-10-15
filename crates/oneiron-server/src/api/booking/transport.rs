use axum::http::HeaderMap;
use oneiron::EntityId;

use super::{BookingTransport, BookingTransportContext};
use crate::api::check_api_auth;
use crate::auth::ClientAddress;
use crate::error::ApiError;
use crate::server::SyncServer;

/// Builds the transport context for one HTTP request.
///
/// The bearer check is the existing `check_api_auth` door. Admission keys on
/// the client address the connection proves ([`ClientAddress`]): a forwarding
/// header counts only behind a configured trusted proxy, so rotating one mints
/// no fresh budget. A connection with no peer to key on fails closed. The
/// actor is the principal the verified credential names, when it names an
/// entity; nothing the request carries can supply one.
pub(super) fn http_transport_context(
    headers: &HeaderMap,
    server: &SyncServer,
    ClientAddress(client): ClientAddress,
) -> Result<BookingTransportContext, ApiError> {
    let auth = check_api_auth(headers, server)?;
    let source_ip = client
        .ok_or_else(|| ApiError::internal_server_error("booking peer context unavailable"))?;
    Ok(BookingTransportContext {
        source_ip,
        authenticated_actor_ref: auth
            .principal_ref()
            .and_then(|principal| EntityId::from_hex(principal).ok()),
        transport: BookingTransport::PublicHttp,
    })
}
