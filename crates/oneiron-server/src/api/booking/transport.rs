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
/// A booking is an owner act (FIX 2222): a self-hosted root or the dev mode
/// books as the owner it acts as, a hosted operator's root is refused, and
/// no request creates an owner to book as.
pub(super) fn http_transport_context(
    headers: &HeaderMap,
    server: &SyncServer,
    ClientAddress(client): ClientAddress,
) -> Result<BookingTransportContext, ApiError> {
    let auth = check_api_auth(headers, server)?;
    let host_action = crate::api::host_action::require_host_owner_act(server, &auth)?;
    let source_ip = client
        .ok_or_else(|| ApiError::internal_server_error("booking peer context unavailable"))?;
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    let principal = match host_action {
        Some(action) => Some(action.actor()),
        None => auth
            .principal_ref()
            .and_then(|reference| EntityId::from_hex(reference).ok())
            .map(|actor| WriteActor::new(actor, class)),
    };
    Ok(BookingTransportContext {
        source_ip,
        authenticated_actor_ref: None,
        credential: Some(auth.principal().to_owned()),
        owner_grade: auth.is_owner_grade(),
        principal,
        transport: BookingTransport::PublicHttp,
    })
}
