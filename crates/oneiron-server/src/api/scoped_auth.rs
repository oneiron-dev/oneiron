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
pub(super) fn check_api_auth(headers: &HeaderMap, server: &SyncServer) -> Result<(), ApiError> {
    if server.managed_issuer.is_some() {
        return CoreAuth::for_server(headers, server).map(drop);
    }
    require_owner_auth(headers, &server.config, server.vault().as_ref()).map(drop)
}

const LEGACY_SCOPED_READ_ACTOR_REF: &str = "legacy-shared-secret";

/// The read `auth` makes, where its connection sits: a caller off this
/// device reads no device-local world (DEC-0005).
pub(crate) fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(proof) = auth.verified_slip() {
        let actor = oneiron::claim::ScopedReadActorKey::from_verified_slip(proof)
            .ok_or_else(ApiError::unauthorized)?;
        return Ok(vault.scoped_read(actor.at(auth.locality())));
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

/// The legacy routes' read, for a caller whose connection sits at
/// `locality`.
pub(super) fn scoped_read_for_legacy_api(
    server: &SyncServer,
    locality: CallerLocality,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    let vault = server.vault().as_ref();
    if let Some(issuer) = server.managed_issuer.as_ref() {
        let proof = vault
            .verified_host_root_slip(issuer)
            .map_err(|_| ApiError::unauthorized())?;
        let actor = oneiron::claim::ScopedReadActorKey::from_verified_slip(&proof)
            .ok_or_else(ApiError::unauthorized)?;
        return Ok(vault.scoped_read(actor.at(locality)));
    }
    if let Some(secret) = server.config.auth_secret.as_deref() {
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())
            .map_err(|_| ApiError::unauthorized())?;
        let proof = vault
            .verified_host_root_slip(&issuer)
            .map_err(|_| ApiError::unauthorized())?;
        let actor = oneiron::claim::ScopedReadActorKey::from_verified_slip(&proof)
            .ok_or_else(ApiError::unauthorized)?;
        return Ok(vault.scoped_read(actor.at(locality)));
    }
    // Explicit dev mode is not a production root-slip factory.
    let actor_key = oneiron::claim::ScopedReadActorKey::new(LEGACY_SCOPED_READ_ACTOR_REF)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    Ok(vault.scoped_read(actor_key.at(locality)))
}
