use axum::http::request::Parts;
use oneiron::booking::anti_abuse::booking_ip_hash;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::{BookingTransport, BookingTransportContext};
use crate::api::scoped_auth::check_request_auth;
use crate::auth::{ClientAddress, CoreAuth};
use crate::error::ApiError;
use crate::server::SyncServer;

/// Builds the transport context for one HTTP request.
///
/// The bearer check is the legacy door's `check_request_auth`: on a managed
/// vault the request's one caller, its supervisor's attested owner included.
/// The credential it verified keys this request's turn past a window.
/// Admission keys on the client address the connection proves
/// ([`ClientAddress`]): a forwarding header counts only behind a configured
/// trusted proxy, so rotating one mints no fresh budget. A connection with no
/// peer to key on fails closed.
/// A booking is an owner act (FIX 2222): a self-hosted root or the dev mode
/// books as the owner it acts as, a hosted operator's root is refused, and
/// no request creates an owner to book as.
pub(super) fn http_transport_context(
    parts: &Parts,
    server: &SyncServer,
    ClientAddress(client): ClientAddress,
) -> Result<BookingTransportContext, ApiError> {
    let auth = check_request_auth(parts, server)?;
    let host_action = crate::api::host_action::require_host_owner_act(server, &auth)?;
    let source_ip = client
        .ok_or_else(|| ApiError::internal_server_error("booking peer context unavailable"))?;
    let principal = match host_action {
        Some(action) => Some(action.actor()),
        None => credential_principal(server, &auth)?,
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

/// Admission and spend identity after a transport has authenticated its caller.
#[derive(Clone)]
pub(crate) struct BookingAdmissionContext {
    pub(super) ip_hash: [u8; 32],
    pub(super) credential: Option<String>,
    pub(super) owner_grade: bool,
    pub(super) principal: Option<WriteActor>,
    pub(super) transport: BookingTransport,
}

impl From<&BookingTransportContext> for BookingAdmissionContext {
    fn from(transport: &BookingTransportContext) -> Self {
        let mut material = transport.source_ip.to_string();
        if let Some(actor) = transport.actor_key() {
            material.push('\0');
            material.push_str(&actor);
        }
        Self {
            ip_hash: booking_ip_hash(&material),
            credential: transport.credential.clone(),
            owner_grade: transport.owner_grade,
            principal: transport.principal,
            transport: transport.transport,
        }
    }
}

impl From<&BookingAdmissionContext> for BookingAdmissionContext {
    fn from(transport: &BookingAdmissionContext) -> Self {
        transport.clone()
    }
}

/// A generated host call has no HTTP peer. Its verified credential alone
/// keys admission, and its own principal pays; no source address is invented.
pub(crate) fn credential_transport_context(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<BookingAdmissionContext, ApiError> {
    let host_action = crate::api::host_action::require_host_owner_act(server, auth)?;
    let principal = match host_action {
        Some(action) => Some(action.actor()),
        None => credential_principal(server, auth)?,
    };
    Ok(BookingAdmissionContext {
        ip_hash: booking_ip_hash(&format!("credential\0{}", auth.principal())),
        credential: Some(auth.principal().to_owned()),
        owner_grade: auth.is_owner_grade(),
        principal,
        transport: BookingTransport::Credential,
    })
}

/// The caller's own principal, who pays for what it books. A managed vault's
/// attested owner pays as the person his request's own owner proof
/// revalidates now (FIX 4372), never as an id the request merely names; one
/// the vault does not record as its live owner is refused as the owner door
/// refuses.
fn credential_principal(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<Option<WriteActor>, ApiError> {
    if let Some(holder) = auth.managed_owner() {
        let refused = || ApiError::forbidden_scope("owner");
        let owner =
            crate::api::owner_routes::managed_owner_proof(server, holder)?.ok_or_else(refused)?;
        let person = owner
            .revalidate_person(server.vault())
            .map_err(|_| refused())?;
        return Ok(Some(WriteActor::new(person, EdgeActorClass::Human)));
    }
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok(auth
        .principal_ref()
        .and_then(|reference| EntityId::from_hex(reference).ok())
        .map(|actor| WriteActor::new(actor, class)))
}
