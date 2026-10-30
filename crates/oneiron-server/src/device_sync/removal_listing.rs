//! `POST /v1/shared/removal-archives/received` (FIX 11797): the removal
//! archives this vault holds for the person, each by its receipt id, the
//! shared vault it came from, its term, and whether it was imported from a
//! delivery or is kept as the removal keeps it; never a byte of an archive
//! ([`oneiron::Vault::received_removal_archives`]). The device reads it as
//! it reads the archives themselves at the pull doors
//! (`/v1/shared/removal-export`): the person's slip, revoked or not, in
//! `x-oneiron-left-slip`, and a fresh holder proof in `x-oneiron-binding`,
//! its nonce spent once.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use oneiron::authority::CapabilitySlip;
use oneiron::federation::ReceivedRemovalArchive;
use serde::Serialize;

use crate::auth::{BindingProof, parse_signature};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// The header the person's slip rides in, as at the pull doors.
const LEFT_SLIP_HEADER: &str = "x-oneiron-left-slip";

pub(crate) fn removal_listing_routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/v1/shared/removal-archives/received", post(received))
}

/// The removal archives held here for the person.
#[derive(Debug, Serialize)]
struct Received {
    archives: Vec<ReceivedRemovalArchive>,
}

async fn received(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Received>, EnvelopedApiError> {
    let slip = headers
        .get(LEFT_SLIP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|token| CapabilitySlip::from_token(token.trim()).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let proof = BindingProof::from_headers(&headers)?;
    let signature = parse_signature(&proof.signature)?;
    let archives = tokio::task::spawn_blocking(move || {
        server.vault().received_removal_archives(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(Received { archives }))
}
