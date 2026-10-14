use axum::http::HeaderMap;

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
/// no fresh budget. A connection with no peer to key on fails closed.
pub(super) fn http_transport_context(
    headers: &HeaderMap,
    server: &SyncServer,
    ClientAddress(client): ClientAddress,
) -> Result<BookingTransportContext, ApiError> {
    check_api_auth(headers, server)?;
    let source_ip = client
        .ok_or_else(|| ApiError::internal_server_error("booking peer context unavailable"))?;
    Ok(BookingTransportContext {
        source_ip,
        authenticated_actor_ref: None,
        transport: BookingTransport::PublicHttp,
    })
}
