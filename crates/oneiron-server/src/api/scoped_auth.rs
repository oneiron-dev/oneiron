//! Legacy owner-auth gate and scoped-read constructors for both auth flavors.

use crate::auth::CoreAuth;
use crate::auth::require_owner_auth;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::http::HeaderMap;

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

pub(super) fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(proof) = auth.verified_slip() {
        let actor = oneiron::claim::ScopedReadActorKey::from_verified_slip(proof)
            .ok_or_else(ApiError::unauthorized)?;
        return Ok(vault.scoped_read(actor));
    }
    let actor_ref = auth.principal_ref().unwrap_or(auth.principal());
    scoped_read_for_actor_ref(vault, actor_ref)
}

pub(super) fn scoped_read_for_legacy_api(
    server: &SyncServer,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    let vault = server.vault().as_ref();
    if let Some(issuer) = server.managed_issuer.as_ref() {
        let proof = vault.verified_host_root_slip(issuer)
            .map_err(|_| ApiError::unauthorized())?;
        let actor = oneiron::claim::ScopedReadActorKey::from_verified_slip(&proof)
            .ok_or_else(ApiError::unauthorized)?;
        return Ok(vault.scoped_read(actor));
    }
    if let Some(secret) = server.config.auth_secret.as_deref() {
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())
            .map_err(|_| ApiError::unauthorized())?;
        let proof = vault
            .verified_host_root_slip(&issuer)
            .map_err(|_| ApiError::unauthorized())?;
        let actor = oneiron::claim::ScopedReadActorKey::from_verified_slip(&proof)
            .ok_or_else(ApiError::unauthorized)?;
        return Ok(vault.scoped_read(actor));
    }
    // Explicit dev mode is not a production root-slip factory.
    scoped_read_for_actor_ref(vault, LEGACY_SCOPED_READ_ACTOR_REF)
}

pub(super) fn scoped_read_for_actor_ref<'a>(
    vault: &'a oneiron::Vault,
    actor_ref: &str,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    let actor_key = oneiron::claim::ScopedReadActorKey::new(actor_ref)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    Ok(vault.scoped_read(actor_key))
}
