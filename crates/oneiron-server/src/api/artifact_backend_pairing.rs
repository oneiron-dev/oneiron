//! Owner bootstrap for a published app's own zero-action credential.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::request::Parts;
use oneiron::agent_dispatch::CommReach;
use oneiron::artifact_hosting::ArtifactBackendPairing;
use serde::Deserialize;

use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateBackendPairing {
    artifact: String,
    fork_hash: String,
    lifetime_secs: u64,
    comm: CommReach,
}

pub(super) async fn create(
    parts: Parts,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<CreateBackendPairing>,
) -> Result<Json<ArtifactBackendPairing>, EnvelopedApiError> {
    let auth = super::scoped_auth::check_request_owner_act(&parts, &server)?;
    let owner = super::owner_routes::owner(&auth, &server)?;
    let hash = oneiron::parse_codebase_fork_hash_hex(&request.fork_hash)
        .map_err(|error| ApiError::bad_request(error.to_string(), Some("fork_hash")))?;
    let pairing = super::clock_ingress::run_blocking(move || {
        super::pairing::with_issuer(&server, |issuer| {
            server.vault().create_artifact_backend_pairing(
                &owner,
                issuer,
                &request.artifact,
                &hash,
                request.lifetime_secs,
                request.comm,
            )
        })
    })
    .await
    .map_err(|_| ApiError::internal_server_error("artifact backend pairing task failed"))??;
    Ok(Json(pairing))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MintBackendSlip {
    grant_ref: String,
    holder_key: String,
    expires_at: u64,
    comm: CommReach,
}

#[derive(serde::Serialize)]
pub(super) struct MintedBackendSlip {
    token: String,
    principal_ref: String,
    grant_ref: String,
    expires_at: u64,
}

pub(super) async fn mint_slip(
    parts: Parts,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<MintBackendSlip>,
) -> Result<Json<MintedBackendSlip>, EnvelopedApiError> {
    let auth = super::scoped_auth::check_request_owner_act(&parts, &server)?;
    let owner = super::owner_routes::owner(&auth, &server)?;
    let grant_ref = oneiron::EntityId::from_hex(&request.grant_ref)
        .map_err(|error| ApiError::bad_request(error.to_string(), Some("grant_ref")))?;
    let holder_key = crate::auth::parse_slip_id(&request.holder_key)?;
    let slip = super::clock_ingress::run_blocking(move || {
        super::pairing::with_issuer(&server, |issuer| {
            server.vault().mint_artifact_backend_slip(
                &owner,
                issuer,
                grant_ref,
                holder_key,
                request.expires_at,
                Some(request.comm),
            )
        })
    })
    .await
    .map_err(|_| ApiError::internal_server_error("artifact backend slip task failed"))??;
    let token = slip
        .to_token()
        .map_err(|error| ApiError::bad_request(error.to_string(), None))?;
    Ok(Json(MintedBackendSlip {
        token,
        principal_ref: slip.claims.holder_ref,
        grant_ref: grant_ref.to_hex(),
        expires_at: slip.claims.expires_at,
    }))
}
