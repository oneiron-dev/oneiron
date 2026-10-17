use axum::http::HeaderMap;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::{BookingTransport, BookingTransportContext};
use crate::api::check_api_auth;
use crate::auth::ClientAddress;
use crate::error::ApiError;
use crate::server::SyncServer;

/// Builds the transport context for one HTTP request.
///
/// The bearer check is the existing `check_api_auth` door; the credential it
/// verified keys this request's turn past a window. Admission keys on
/// the client address the connection proves ([`ClientAddress`]): a forwarding
/// header counts only behind a configured trusted proxy, so rotating one mints
/// no fresh budget. A connection with no peer to key on fails closed.
pub(super) fn http_transport_context(
    headers: &HeaderMap,
    server: &SyncServer,
    ClientAddress(client): ClientAddress,
) -> Result<BookingTransportContext, ApiError> {
    let auth = check_api_auth(headers, server)?;
    let source_ip = client
        .ok_or_else(|| ApiError::internal_server_error("booking peer context unavailable"))?;
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).ok(),
        None if auth.is_owner_grade() => server.vault().ensure_embedded_owner_actor().ok(),
        None => None,
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok(BookingTransportContext {
        source_ip,
        authenticated_actor_ref: None,
        credential: Some(auth.principal().to_owned()),
        owner_grade: auth.is_owner_grade(),
        principal: actor.map(|actor| WriteActor::new(actor, class)),
        transport: BookingTransport::PublicHttp,
    })
}
