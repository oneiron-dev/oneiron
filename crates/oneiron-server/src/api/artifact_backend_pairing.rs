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
