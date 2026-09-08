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
pub(crate) fn check_api_auth(headers: &HeaderMap, server: &SyncServer) -> Result<(), ApiError> {
    require_owner_auth(headers, &server.config, server.vault().as_ref()).map(drop)
}

const LEGACY_SCOPED_READ_ACTOR_REF: &str = "legacy-shared-secret";

pub(crate) fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    let actor_ref = auth.principal_ref().unwrap_or(auth.principal());
    scoped_read_for_actor_ref(vault, actor_ref)
}

pub(crate) fn scoped_read_for_legacy_api(
    vault: &oneiron::Vault,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    scoped_read_for_actor_ref(vault, LEGACY_SCOPED_READ_ACTOR_REF)
}

pub(crate) fn scoped_read_for_actor_ref<'a>(
    vault: &'a oneiron::Vault,
    actor_ref: &str,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    let actor_key = oneiron::claim::ScopedReadActorKey::new(actor_ref)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    Ok(vault.scoped_read(actor_key))
}
