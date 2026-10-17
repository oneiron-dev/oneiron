//! Legacy owner-auth gate and scoped-read constructors for both auth flavors.

use crate::auth::CoreAuth;
use crate::auth::require_owner_auth;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::http::HeaderMap;
use oneiron::claim::CallerLocality;

/// Gates the legacy `/api/*` routes on an owner-grade bearer.
///
/// These routes read the whole vault under one actor ref, so they stay a
/// trust-root surface: scoped `/v1` delegation tokens do not reach them.
pub(super) fn check_api_auth(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    if server.managed_issuer.is_some() {
        return CoreAuth::for_server(headers, server);
    }
    require_owner_auth(headers, &server.config, server.vault().as_ref())
}

const LEGACY_SCOPED_READ_ACTOR_REF: &str = "legacy-shared-secret";

/// The read key a verified credential reads under on every `/v1` door. It is
/// the engine's one builder, the one the facade's read lane uses: the owner's
/// live full credential reads as the owner, and any other holder needs a live
/// grant for relationship data. A credential that grants no read is refused.
pub(crate) fn credential_read_key(
    vault: &oneiron::Vault,
    proof: &oneiron::authority::VerifiedSlip,
) -> Result<oneiron::claim::ScopedReadActorKey, ApiError> {
    vault
        .credential_read_key(proof)
        .map_err(|error| super::core_engine_error("credential read key failed", error))?
        .ok_or_else(ApiError::unauthorized)
}

/// A facade handle that reads as `auth`'s credential does: a verified slip
/// binds the handle's reads to the same credential key, so a narrower
/// credential stays bounded by it. A caller with no slip keeps the handle's
/// own lane.
/// Every handle here is a transport caller's, slip or none, and carries the
/// slip the request was admitted on into the work it queues.
pub(crate) fn credential_memory<'a>(
    vault: &'a oneiron::Vault,
    auth: Option<&CoreAuth>,
    actor: oneiron::EntityId,
    class: oneiron::EdgeActorClass,
) -> oneiron::memory::Memory<'a> {
    let memory = vault.memory(actor, class);
    let memory = match auth.and_then(CoreAuth::invocation_slip) {
        Some(binding) => memory
            .with_transport_invocation()
            .with_invocation_slip(binding),
        None => memory.with_transport_invocation(),
    };
    match auth.and_then(CoreAuth::verified_slip) {
        Some(proof) => memory.with_read_proof(proof),
        None => memory,
    }
}

/// The read `auth` makes, where its connection sits: a caller off this
/// device reads no device-local world (DEC-0005).
pub(crate) fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(proof) = auth.verified_slip() {
        return Ok(vault.scoped_read(credential_read_key(vault, proof)?.at(auth.locality())));
    }
    let actor_ref = auth.principal_ref().unwrap_or(auth.principal());
    let mut key = oneiron::claim::ScopedReadActorKey::new(actor_ref)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    if !auth.is_owner_grade() {
        key = key.require_access_grants(
            auth.principal_ref()
                .and_then(|id| oneiron::EntityId::from_hex(id).ok()),
        );
    }
    Ok(vault.scoped_read(key.at(auth.locality())))
}

/// The legacy read lane for the credential [`check_api_auth`] admitted, where
/// its connection sits. A verified slip reads under its own key, through the
/// one builder, so an agent's full-scope slip reads a relationship's rows here
/// only on a grant, as on `/v1`, and every read checks that slip's liveness.
/// A credential that verifies no slip is the server's own secret and reads as
/// the host root.
pub(super) fn scoped_read_for_legacy_api<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(proof) = auth.verified_slip() {
        let vault = server.vault().as_ref();
        return Ok(vault.scoped_read(credential_read_key(vault, proof)?.at(auth.locality())));
    }
    scoped_read_for_host_root(server, auth.locality())
}

/// The host root's read, for a caller whose connection sits at `locality`.
pub(super) fn scoped_read_for_host_root(
    server: &SyncServer,
    locality: CallerLocality,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    let vault = server.vault().as_ref();
    if let Some(issuer) = server.managed_issuer.as_ref() {
        let proof = vault
            .verified_host_root_slip(issuer)
            .map_err(|_| ApiError::unauthorized())?;
        return Ok(vault.scoped_read(credential_read_key(vault, &proof)?.at(locality)));
    }
    if let Some(secret) = server.config.auth_secret.as_deref() {
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())
            .map_err(|_| ApiError::unauthorized())?;
        let proof = vault
            .verified_host_root_slip(&issuer)
            .map_err(|_| ApiError::unauthorized())?;
        return Ok(vault.scoped_read(credential_read_key(vault, &proof)?.at(locality)));
    }
    // Explicit dev mode is not a production root-slip factory.
    let actor_key = oneiron::claim::ScopedReadActorKey::new(LEGACY_SCOPED_READ_ACTOR_REF)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    Ok(vault.scoped_read(actor_key.at(locality)))
}
