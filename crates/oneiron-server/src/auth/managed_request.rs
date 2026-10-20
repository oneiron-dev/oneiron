//! The caller of one request a managed vault serves (WILL-PLAN L14 row 01,
//! Engine ruling 10-19).
//!
//! Managed ingress forwards a caller's own slip, its holder proof and its
//! machine claim unchanged. The binding door verifies them and spends the
//! proof's nonce, once; every check after it reads the same slip again
//! without spending anything, but the renewal door, which takes the caller
//! the binding door admitted ([`AdmittedCaller`], FIX 4559). A request that
//! carries a slip is its slip's caller: its own principal, class, scope,
//! exact instrument and live Grant, never the host's root (FIX 2222). A slip
//! that fails is refused, never replaced by the owner's or the root's
//! credential.
//!
//! A request that carries no slip, where its supervisor attested the
//! vault's owner for it (`ManagedOwnerAction`), is that owner himself (FIX
//! 5255): the person, with every owner scope and no host credential behind
//! him, while the vault records him as its live owner. A request with
//! neither is anonymous (FIX 2222, FIX 5255): it names no caller, so a door
//! that needs one refuses it, and only the public doors, whose own
//! capability, signature or provider proof stands alone, serve it; never
//! the host's root or the dev mode. A slip beside an attestation of the same
//! person stays the slip, with its own bounds; beside another person's, the
//! request is refused.
//!
//! At a booking door alone (`BOOKING_PAYER_DOORS`), an attested holder the
//! vault no longer records as its live owner is still that person, as a
//! booking caller and nothing more (FIX 5327): core read and write, never
//! owner grade, no slip and no owner authority. The booking door judges
//! whom he pays as; every other door refuses him as before.

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap, request::Parts};
use oneiron::authority::OwnerDeviceRenewalProof;

use super::{BindingProof, CoreAuth, bearer_token, caller_locality, proved_peer};
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// Framing prefix of a capability slip: the one caller credential managed
/// ingress forwards.
const SLIP_PREFIX: &str = "v2.slip.";

/// The header an MCP connector names its credential in.
const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

/// The header a slip's holder proof rides in.
const BINDING_HEADER: &str = "x-oneiron-binding";

/// The caller the binding door admitted on a managed vault (FIX 4559): the
/// auth its consuming admission of the request's slip returned, and the
/// machine proof the request carries over that same token and the timestamp
/// and nonce of the holder proof it spent, raw, or `None` when the request
/// carries none or a malformed one. Only that door builds one, once it spent
/// the proof's nonce, and it lives on that one request alone: never stored,
/// never sent. It says where the request came from, not that it still
/// stands: the engine's writer judges the slip, the proof's freshness and
/// admission and the machine again.
#[derive(Clone)]
pub(super) struct AdmittedCaller {
    auth: CoreAuth,
    machine: Option<OwnerDeviceRenewalProof>,
}

impl AdmittedCaller {
    /// The caller `auth` the binding door admitted, with the `machine` proof
    /// it read over the same token and holder proof.
    pub(super) fn new(auth: CoreAuth, machine: Option<OwnerDeviceRenewalProof>) -> Self {
        Self { auth, machine }
    }
}

/// The capability slip `headers` carry as their bearer, if any. Any other
/// bearer is not a caller's credential here: managed ingress strips it.
fn caller_slip(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    Ok(bearer_token(headers)?.filter(|token| token.starts_with(SLIP_PREFIX)))
}

/// Whether `headers` carry a caller's capability slip as their bearer.
pub(crate) fn carries_caller_slip(headers: &HeaderMap) -> bool {
    caller_slip(headers).ok().flatten().is_some()
}

/// Managed ingress's forwarding rule: a caller's capability slip, as its
/// bearer or as its MCP connector credential, goes on to the child
/// unchanged, with its holder proof (and its machine claim, which ingress
/// never touches), for the child to verify. Any other bearer or connector
/// credential terminated at the supervisor and is removed, as is a holder
/// proof no slip rides with, so a request without a slip reaches the child
/// with no caller credential at all.
pub(crate) fn forward_caller_credentials(headers: &mut HeaderMap) {
    let bearer = carries_caller_slip(headers);
    let connector = headers
        .get(MCP_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().starts_with(SLIP_PREFIX));
    if !bearer {
        headers.remove(AUTHORIZATION);
    }
    if !connector {
        headers.remove(MCP_CREDENTIAL_HEADER);
    }
    if !bearer && !connector {
        headers.remove(BINDING_HEADER);
    }
}

/// The refusal of a caller slip that did not verify on a managed vault: the
/// slip, or its holder proof, is bad, and nothing stands in for it.
pub(super) fn caller_binding_refused() -> ApiError {
    ApiError::new(
        "request is not authorized: managed_caller_binding: the slip this request carries, or \
         its x-oneiron-binding holder proof, did not verify; a refused slip is never replaced by \
         the owner's or the host's credential",
        ApiErrorDetails::Unauthorized,
        ["Present a live slip with a fresh holder proof, or send the request with no slip."],
    )
}

/// The refusal of an owner attestation managed ingress could not verify
/// over the request it came with: nothing stands in for it, neither the
/// owner nor the host's root.
pub(crate) fn owner_attestation_refused() -> ApiError {
    ApiError::new(
        "request is not authorized: managed_owner_attestation: the owner attestation this \
         request carries did not verify over its method, path, query, placing headers and \
         body; a refused attestation is never replaced by the host's credential",
        ApiErrorDetails::Unauthorized,
        ["Send the request again through the vault's supervisor, which signs it afresh."],
    )
}

/// The refusal of a holder proof a managed vault already took: each request
/// spends its own.
pub(super) fn caller_binding_replayed() -> ApiError {
    ApiError::new(
        "request is not authorized: managed_caller_binding_replayed: this holder proof was \
         already used; a slip's holder proof admits one request",
        ApiErrorDetails::Unauthorized,
        ["Sign a fresh holder proof, with a new nonce and timestamp, and retry."],
    )
}

/// The refusal of a caller slip narrower than a whole-vault door: its own
/// scope or Grant does not reach `door`, and the host's root never stands in
/// for it.
pub(crate) fn caller_slip_too_narrow(door: &str) -> ApiError {
    ApiError::new(
        format!(
            "request is not authorized: managed_caller_scope: the slip this request carries is \
             narrower than {door}'s whole-vault grade (its scope, caveats, records, channels, \
             organization or Grant narrow it); a caller keeps its own slip's reach and is never \
             served as the host"
        ),
        ApiErrorDetails::Forbidden {
            required_scope: Some("owner".to_owned()),
        },
        [
            "Call this act through the scoped /v1 door its slip reaches, or present an \
             unattenuated full-vault slip.",
        ],
    )
}

/// The refusal of a request whose slip names another person than the owner
/// its supervisor attested: one request has one caller.
fn caller_conflicts_with_owner() -> ApiError {
    ApiError::new(
        "request is not authorized: managed_caller_conflict: the slip this request carries \
         names another caller than the owner its supervisor attested",
        ApiErrorDetails::Unauthorized,
        [
            "Send the slip's request without the owner's attestation, or the owner's own \
             request without another caller's slip.",
        ],
    )
}

impl CoreAuth {
    /// The caller `headers` name on a managed vault: the slip they carry,
    /// verified read-only. A slip that does not verify is refused, named.
    /// Headers that carry none name no caller: the request is anonymous and
    /// refused here, never served as the host's root (FIX 2222). The owner
    /// its supervisor attested is [`Self::for_managed_request`]'s, which
    /// reads the request's extensions too.
    pub(super) fn managed_caller(
        headers: &HeaderMap,
        server: &SyncServer,
    ) -> Result<Self, ApiError> {
        let Some(token) = caller_slip(headers)? else {
            return Err(ApiError::unauthorized());
        };
        let proof = BindingProof::from_headers(headers).map_err(|_| caller_binding_refused())?;
        Self::from_slip_token(token, &proof, server.vault().as_ref()).map_err(|refused| {
            if refused == ApiError::proof_clock_ahead() {
                refused
            } else {
                caller_binding_refused()
            }
        })
    }

    /// The vault owner `holder` his supervisor attested: for an attested
    /// request that carries no slip ([`Self::for_managed_request`]), and for
    /// an act no HTTP request carries, a managed voice hello's
    /// `ManagedOwnerAction` once the voice loop verified it (FIX 2391, FIX
    /// 5203). The person himself, as a human, built without reading any
    /// header and without the host's root: every owner scope, set here, and
    /// no slip, instrument, token id or Grant of anyone's. Refused on a
    /// vault no supervisor manages, and unless the vault records `holder` as
    /// its live owner now (`require_live_managed_owner`), so no door that
    /// takes this caller has to check that again.
    pub(crate) fn for_attested_owner(
        holder: oneiron::EntityId,
        server: &SyncServer,
    ) -> Result<Self, ApiError> {
        if server.managed_issuer.is_none() {
            return Err(ApiError::unauthorized());
        }
        let auth = Self::attested(holder, super::CoreScope::owner(), true);
        crate::api::require_live_managed_owner(server, &auth)?;
        Ok(auth)
    }

    /// The person `holder` his supervisor attested, as `scopes` name him,
    /// built without reading any header and without the host's root: a
    /// human, with no slip, instrument, token id or Grant of anyone's. Only
    /// [`Self::for_attested_owner`] makes him the owner (`owner_scopes`,
    /// after it checks he is the live owner), and only
    /// [`Self::for_attested_booking_holder`] a booking caller.
    fn attested(
        holder: oneiron::EntityId,
        scopes: std::collections::BTreeSet<super::CoreScope>,
        owner_scopes: bool,
    ) -> Self {
        Self {
            principal: holder.to_hex(),
            principal_ref: Some(holder.to_hex()),
            scopes,
            implicit_all_scopes: owner_scopes,
            jti: None,
            actor_class: Some("human".to_owned()),
            org_ref: None,
            verified_slip: None,
            invocation_slip: None,
            instrument: None,
            locality: oneiron::claim::CallerLocality::OffDevice,
            peer: oneiron::authority::PeerMachine::Unknown,
            facets_owner_exempt: false,
            off_record_session: None,
            managed_owner: Some(holder),
        }
    }

    /// The holder his supervisor attested, at a booking door (FIX 5327):
    /// the live owner as [`Self::for_attested_owner`] builds him; one the
    /// vault does not record as its live owner now, or whose standing it
    /// cannot read, a booking caller with core read and write only, never
    /// owner grade, still naming him as its managed holder so no other door
    /// takes him and the booking door judges whom he pays as. His
    /// attestation is never verified again here. Only a booking door builds
    /// one ([`Self::for_managed_request`], `api::mcp_gateway::booking_call`).
    pub(crate) fn for_attested_booking_holder(
        holder: oneiron::EntityId,
        server: &SyncServer,
    ) -> Result<Self, ApiError> {
        if server.managed_issuer.is_none() {
            return Err(ApiError::unauthorized());
        }
        Ok(
            Self::for_attested_owner(holder, server).unwrap_or_else(|_| {
                Self::attested(
                    holder,
                    [super::CoreScope::Read, super::CoreScope::Write]
                        .into_iter()
                        .collect(),
                    false,
                )
            }),
        )
    }

    /// Whether this caller is a stale owner sign-in a booking door admitted
    /// ([`Self::for_attested_booking_holder`]): a managed holder at less
    /// than owner grade. He books and pays as the booking door resolves
    /// him, and is nobody's owner.
    pub(crate) fn is_attested_booking_holder(&self) -> bool {
        self.managed_owner.is_some() && !self.implicit_all_scopes
    }

    /// [`Self::for_attested_booking_holder`]'s booking caller, placed where
    /// the request at `path` puts him, or `None` for the live owner, who
    /// keeps his own path: a managed-MCP booking tool's caller
    /// (`api::mcp_gateway::booking_call`, FIX 5327).
    pub(crate) fn for_placed_booking_holder(
        holder: oneiron::EntityId,
        headers: &HeaderMap,
        extensions: &Extensions,
        path: &str,
        server: &SyncServer,
    ) -> Option<Self> {
        Self::for_attested_booking_holder(holder, server)
            .ok()
            .filter(Self::is_attested_booking_holder)
            .map(|auth| auth.placed(headers, extensions, path))
    }

    /// The one caller of a request, from its headers and its extensions
    /// together: on a managed vault [`Self::for_managed_request`]'s, on any
    /// other the credential its headers carry. The caller is then placed
    /// where its connection sits, toward the machine it proved, at the
    /// invitee door its path names and inside the session it names.
    pub(crate) async fn for_request(parts: &Parts, server: &SyncServer) -> Result<Self, ApiError> {
        let path = request_path(parts);
        if let Some(auth) =
            Self::for_managed_request(&parts.headers, &parts.extensions, path, server)
        {
            return auth;
        }
        Ok(Self::for_server_async(&parts.headers, server)
            .await?
            .placed(&parts.headers, &parts.extensions, path))
    }

    /// [`Self::for_request`]'s caller on a managed vault, for a door that
    /// judges its caller without awaiting, from the request's headers,
    /// extensions and path: the slip the request carries, else the owner
    /// managed ingress verified for it ([`Self::for_attested_owner`]), with
    /// no header authenticated first. A request with neither is anonymous
    /// and refused ([`Self::managed_caller`]): no host credential stands in
    /// for a missing one. A slip beside another person's attestation is
    /// refused. A managed vault's callers never reach the account-key door,
    /// so it is the same one caller. `None` on any other vault, whose door
    /// keeps its own header path.
    pub(crate) fn for_managed_request(
        headers: &HeaderMap,
        extensions: &Extensions,
        path: &str,
        server: &SyncServer,
    ) -> Option<Result<Self, ApiError>> {
        server.managed_issuer.as_ref()?;
        let caller = match attested_owner(extensions, server) {
            None => Self::for_server(headers, server),
            // The caller's own slip stays the caller, with its own bounds;
            // the attestation lends it nothing.
            Some(holder) if carries_caller_slip(headers) => Self::for_server(headers, server)
                .and_then(|auth| {
                    if auth.principal_ref() == Some(holder.to_hex().as_str()) {
                        Ok(auth)
                    } else {
                        Err(caller_conflicts_with_owner())
                    }
                }),
            // A booking door takes him even once he is no longer the live
            // owner, as a booking caller alone (FIX 5327).
            Some(holder) if crate::api::is_booking_payer_door(path) => {
                Self::for_attested_booking_holder(holder, server)
            }
            Some(holder) => Self::for_attested_owner(holder, server),
        };
        Some(caller.map(|auth| auth.placed(headers, extensions, path)))
    }

    /// [`Self::for_managed_request`]'s caller for a door that otherwise
    /// judges its caller by its headers alone (git smart HTTP and LFS, the
    /// sync socket's upgrade), on a request managed ingress verified its
    /// supervisor's owner attestation on: the owner himself
    /// ([`Self::for_attested_owner`]), or the slip beside him that names
    /// him. `None` for any other request, which keeps that door's own
    /// header path as it was.
    pub(crate) fn for_attested_request(
        headers: &HeaderMap,
        extensions: &Extensions,
        path: &str,
        server: &SyncServer,
    ) -> Option<Result<Self, ApiError>> {
        attested_owner(extensions, server)?;
        Self::for_managed_request(headers, extensions, path, server)
    }

    /// [`Self::for_managed_request`]'s caller at the device-renewal door
    /// (FIX 4559), with the machine proof that door requires: the caller the
    /// binding door admitted ([`AdmittedCaller`]), as its admission returned
    /// it, and the machine proof it kept, neither read from the headers
    /// again. Beside another person's attestation it is refused, as there. A
    /// request with no admitted slip keeps that door's caller, the attested
    /// owner or anonymous, with no machine proof; a slip the binding door did
    /// not admit is refused, never read from the headers. `None` on any
    /// other vault.
    pub(crate) fn for_managed_renewal(
        headers: &HeaderMap,
        extensions: &Extensions,
        path: &str,
        server: &SyncServer,
    ) -> Option<Result<(Self, Option<OwnerDeviceRenewalProof>), ApiError>> {
        server.managed_issuer.as_ref()?;
        let Some(admitted) = extensions.get::<AdmittedCaller>() else {
            if carries_caller_slip(headers) {
                return Some(Err(caller_binding_refused()));
            }
            return Self::for_managed_request(headers, extensions, path, server)
                .map(|caller| caller.map(|auth| (auth, None)));
        };
        // The caller's own slip stays the caller; the attestation lends it
        // nothing.
        if let Some(holder) = attested_owner(extensions, server)
            && admitted.auth.principal_ref() != Some(holder.to_hex().as_str())
        {
            return Some(Err(caller_conflicts_with_owner()));
        }
        let auth = admitted.auth.clone().placed(headers, extensions, path);
        Some(Ok((auth, admitted.machine.clone())))
    }

    /// This request's one caller ([`Self::for_request`]), placed.
    fn placed(self, headers: &HeaderMap, extensions: &Extensions, path: &str) -> Self {
        self.at(caller_locality(headers, extensions))
            .toward(proved_peer(headers, extensions))
            .at_invitee_door(path)
            .in_off_record_session(crate::api::call_receipt::request_session_ref(headers))
    }
}

/// The path a request named, before any nest took its prefix.
pub(crate) fn request_path(parts: &Parts) -> &str {
    parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map_or_else(|| parts.uri.path(), |uri| uri.0.path())
}

/// The vault owner a supervisor attested this one request for, as managed
/// ingress verified it (`ManagedOwnerAction`), or `None`. Only managed
/// ingress installs it, and only on a verified assertion.
pub(crate) fn attested_owner(
    extensions: &Extensions,
    server: &SyncServer,
) -> Option<oneiron::EntityId> {
    extensions
        .get::<crate::managed::ManagedOwnerHolder>()
        .filter(|_| server.managed_issuer.is_some())
        .map(|holder| holder.0)
}
