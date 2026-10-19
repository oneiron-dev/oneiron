use axum::http::request::Parts;
use oneiron::authority::HostActionAuthority;
use oneiron::booking::anti_abuse::booking_ip_hash;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::constants::{
    BOOKING_PAYER_DOORS, BOOKING_PAYER_FACADE_ROOT, STALE_BOOKING_KEEPS_OWNER_GRADE,
};
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
/// no request creates an owner to book as. An attested holder the vault no
/// longer records as its live owner books here too (FIX 5327), as himself
/// or as the public ([`resolve_booking_payer`]), and only a page its owner
/// published, as the public would.
pub(super) fn http_transport_context(
    parts: &Parts,
    server: &SyncServer,
    ClientAddress(client): ClientAddress,
) -> Result<BookingTransportContext, ApiError> {
    let auth = booking_request_auth(parts, server)?;
    let host_action = crate::api::host_action::require_host_owner_act(server, &auth)?;
    let source_ip = client
        .ok_or_else(|| ApiError::internal_server_error("booking peer context unavailable"))?;
    let payer = resolve_booking_payer(server, &auth, host_action);
    Ok(BookingTransportContext {
        source_ip,
        authenticated_actor_ref: None,
        credential: Some(auth.principal().to_owned()),
        owner_grade: payer.owner_grade,
        principal: payer.principal,
        requires_publication: auth.is_attested_booking_holder(),
        payer_guard: payer.guard,
        transport: BookingTransport::PublicHttp,
    })
}

/// The caller of a legacy booking request: the one `check_request_auth`
/// admits, or, on a managed vault, an attested holder with no slip whom the
/// vault no longer records as its live owner, which this booking door alone
/// takes (FIX 5327, [`CoreAuth::for_attested_booking_holder`]). Every other
/// caller, the live owner, a slip, an anonymous request and every other
/// vault's, is judged by `check_request_auth` exactly as before.
fn booking_request_auth(parts: &Parts, server: &SyncServer) -> Result<CoreAuth, ApiError> {
    if crate::auth::attested_owner(&parts.extensions, server).is_some()
        && !crate::auth::carries_caller_slip(&parts.headers)
        && let Some(Ok(auth)) = CoreAuth::for_managed_request(
            &parts.headers,
            &parts.extensions,
            crate::auth::request_path(parts),
            server,
        )
        && auth.is_attested_booking_holder()
    {
        return Ok(auth);
    }
    check_request_auth(parts, server)
}

/// Whether `path` is one of [`BOOKING_PAYER_DOORS`], by its exact route
/// shape (FIX 5327): the doors a stale owner sign-in still books at.
pub(crate) fn is_booking_payer_door(path: &str) -> bool {
    BOOKING_PAYER_DOORS.iter().any(|door| {
        let mut door = door.split('/');
        let mut path = path.split('/');
        loop {
            match (door.next(), path.next()) {
                (None, None) => return true,
                (Some("{page_token}"), Some(segment)) if !segment.is_empty() => {}
                (Some(expected), Some(segment)) if expected == segment => {}
                _ => return false,
            }
        }
    })
}

/// The generated booking verbs among [`BOOKING_PAYER_DOORS`]: the managed-MCP
/// booking tools a stale owner sign-in may call (FIX 5327).
pub(crate) fn booking_payer_verbs() -> impl Iterator<Item = &'static str> {
    BOOKING_PAYER_DOORS
        .iter()
        .filter_map(|door| door.strip_prefix(BOOKING_PAYER_FACADE_ROOT))
}

/// Admission and spend identity after a transport has authenticated its caller.
#[derive(Clone)]
pub(crate) struct BookingAdmissionContext {
    pub(super) ip_hash: [u8; 32],
    pub(super) credential: Option<String>,
    pub(super) owner_grade: bool,
    pub(super) principal: Option<WriteActor>,
    /// Whether this request books only a page its owner published, through
    /// the public booking authority.
    pub(super) requires_publication: bool,
    /// What made a stale owner sign-in the payer, if anything did
    /// ([`Self::payer_now`]).
    payer_guard: Option<BookingPayerGuard>,
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
            requires_publication: transport.requires_publication,
            payer_guard: transport.payer_guard.clone(),
            transport: transport.transport,
        }
    }
}

impl From<&BookingAdmissionContext> for BookingAdmissionContext {
    fn from(transport: &BookingAdmissionContext) -> Self {
        transport.clone()
    }
}

impl BookingAdmissionContext {
    /// Who pays the model call this request is about to make: its principal
    /// as the transport resolved it. A stale owner sign-in that pays as
    /// himself (FIX 5327) does so only while the one grant that made him the
    /// payer still stands now, judged by that grant alone and never by a
    /// second scan for another; once it does not, the page's publisher pays,
    /// as for an anonymous visitor (CALLS "FIX 5327 payer recheck").
    pub(super) fn payer_now(&self, vault: &oneiron::Vault) -> Option<WriteActor> {
        let Some(guard) = &self.payer_guard else {
            return self.principal;
        };
        if vault
            .booking_payer_grant_stands(&guard.person, guard.grant)
            .unwrap_or(false)
        {
            self.principal
        } else {
            None
        }
    }
}

/// A generated host call has no HTTP peer. Its verified credential alone
/// keys admission, and its own principal pays; no source address is invented.
pub(crate) fn credential_transport_context(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<BookingAdmissionContext, ApiError> {
    let host_action = crate::api::host_action::require_host_owner_act(server, auth)?;
    let payer = resolve_booking_payer(server, auth, host_action);
    Ok(BookingAdmissionContext {
        ip_hash: booking_ip_hash(&format!("credential\0{}", auth.principal())),
        credential: Some(auth.principal().to_owned()),
        owner_grade: payer.owner_grade,
        principal: payer.principal,
        requires_publication: true,
        payer_guard: payer.guard,
        transport: BookingTransport::Credential,
    })
}

/// The evidence a stale owner sign-in pays as himself on (FIX 5327): the
/// person his attestation names, proved as a live person and never as an
/// owner, and the grant that names him. Payer evidence only: it never
/// reaches an owner binding, an owner route, an act or a read key.
#[derive(Clone, Debug)]
pub(super) struct BookingPayerGuard {
    person: AuthenticatedOwner,
    grant: EntityId,
}

/// Who pays for what a booking request's caller books, and whether that
/// caller books for the owner.
struct BookingPayer {
    principal: Option<WriteActor>,
    owner_grade: bool,
    guard: Option<BookingPayerGuard>,
}

/// The caller's own principal, who pays for what it books (FIX 5327, one
/// resolution for every booking surface). A self-hosted root or the dev
/// mode pays as the owner it acts as. A managed vault's attested holder the
/// vault records as its live owner pays as the person his request's own
/// owner proof revalidates now (FIX 4372), never as an id the request merely
/// names. One it no longer records so is the person his attestation names
/// and nothing more ([`stale_owner_payer`]). Any other credential pays as its
/// own principal. Nothing here refuses.
fn resolve_booking_payer(
    server: &SyncServer,
    auth: &CoreAuth,
    host_action: Option<HostActionAuthority>,
) -> BookingPayer {
    let unchanged = |principal| BookingPayer {
        principal,
        owner_grade: auth.is_owner_grade(),
        guard: None,
    };
    if let Some(action) = host_action {
        return unchanged(Some(action.actor()));
    }
    let Some(holder) = auth.managed_owner() else {
        return unchanged(credential_principal(auth));
    };
    if let Ok(Some(owner)) = crate::api::owner_routes::managed_owner_proof(server, holder) {
        return unchanged(
            owner
                .revalidate_person(server.vault())
                .ok()
                .map(|person| WriteActor::new(person, EdgeActorClass::Human)),
        );
    }
    stale_owner_payer(server, auth, holder)
}

/// A stale owner sign-in's payer (FIX 5327, Engine ruling (a) 10-20): the
/// person his managed attestation names, authenticated as that verified
/// attestation says and proved live, pays as himself while one live member
/// or guest grant here names him (`Vault::booking_payer_grant`); else, or
/// when any of that cannot be read, nobody does, and the page's publisher
/// pays, as for an anonymous visitor. Either way he books as the public
/// sees, and not for the owner (`STALE_BOOKING_KEEPS_OWNER_GRADE`).
fn stale_owner_payer(server: &SyncServer, auth: &CoreAuth, holder: EntityId) -> BookingPayer {
    let vault = server.vault();
    let standing = vault
        .authenticate_owner(holder, &holder.to_hex(), true, GateDecisionId::now())
        .ok()
        .and_then(|person| {
            let actor = person.revalidate_person(vault).ok()?;
            let grant = vault.booking_payer_grant(&person).ok().flatten()?;
            Some((
                WriteActor::new(actor, EdgeActorClass::Human),
                BookingPayerGuard { person, grant },
            ))
        });
    let (principal, guard) = standing.map_or((None, None), |(principal, guard)| {
        (Some(principal), Some(guard))
    });
    BookingPayer {
        principal,
        owner_grade: STALE_BOOKING_KEEPS_OWNER_GRADE && auth.is_owner_grade(),
        guard,
    }
}

/// An ordinary credential's own principal, as its actor class names it.
fn credential_principal(auth: &CoreAuth) -> Option<WriteActor> {
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    auth.principal_ref()
        .and_then(|reference| EntityId::from_hex(reference).ok())
        .map(|actor| WriteActor::new(actor, class))
}
