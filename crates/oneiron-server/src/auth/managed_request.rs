//! The caller of one request a managed vault serves (WILL-PLAN L14 row 01,
//! Engine ruling 10-19).
//!
//! Managed ingress forwards a caller's own slip, its holder proof and its
//! machine claim unchanged. The binding door verifies them and spends the
//! proof's nonce, once; every check after it reads the same slip again
//! without spending anything. A request that carries a slip is its slip's
//! caller: its own principal, class, scope, exact instrument and live Grant,
//! never the host's root (FIX 2222). A slip that fails is refused, never
//! replaced by the owner's or the root's credential.
//!
//! A request that carries no slip, where its supervisor attested the
//! vault's owner for it (`ManagedOwnerAction`), is that owner himself (FIX
//! 5255): the person, with every owner scope and no host credential behind
//! him, while the vault records him as its live owner. A request with
//! neither is served as it was, as the host's root. A slip beside an
//! attestation of the same person stays the slip, with its own bounds;
//! beside another person's, the request is refused.

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap, request::Parts};

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
/// as it always has.
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
    /// verified read-only, or, with none, the host's root as the supervisor
    /// it serves. A slip that does not verify is refused, named.
    pub(super) fn managed_caller(
        headers: &HeaderMap,
        server: &SyncServer,
        issuer: &oneiron::authority::HostSlipIssuer,
    ) -> Result<Self, ApiError> {
        let Some(token) = caller_slip(headers)? else {
            return Self::managed_supervisor(server, issuer);
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
        let auth = Self {
            principal: holder.to_hex(),
            principal_ref: Some(holder.to_hex()),
            scopes: super::CoreScope::owner(),
            implicit_all_scopes: true,
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
        };
        crate::api::require_live_managed_owner(server, &auth)?;
        Ok(auth)
    }

    /// The host's root on a managed vault, for a request that carries no
    /// caller slip: all scopes, as the supervisor's own.
    fn managed_supervisor(
        server: &SyncServer,
        issuer: &oneiron::authority::HostSlipIssuer,
    ) -> Result<Self, ApiError> {
        let proof = server
            .vault()
            .verified_host_root_slip(issuer)
            .map_err(|_| ApiError::unauthorized())?;
        let mut auth = Self::from_verified(proof, true)?;
        auth.principal = "managed-supervisor".to_owned();
        Ok(auth)
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
    /// no header authenticated first, else the host's own credential as
    /// before. A slip beside another person's attestation is refused. A
    /// managed vault's callers never reach the account-key door, so it is
    /// the same one caller. `None` on any other vault, whose door keeps its
    /// own header path.
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
            Some(holder) => Self::for_attested_owner(holder, server),
        };
        Some(caller.map(|auth| auth.placed(headers, extensions, path)))
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
