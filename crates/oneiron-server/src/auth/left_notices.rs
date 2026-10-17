//! `POST /v1/shared/left-notices` (OF-158 client leave): a device whose
//! person left or was removed from this shared vault learns it, though leave
//! revoked its slips. The request carries that slip in `x-oneiron-left-slip`
//! (never as a bearer token, which the network door would refuse) and the
//! usual holder proof in `x-oneiron-binding`; the engine checks the slip is
//! one this vault minted and the device holds its key, spends the nonce, and
//! answers only the person's own loss-of-access notices.
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use oneiron::authority::CapabilitySlip;
use oneiron::federation::SharedActOutcome;
use serde::Serialize;

use super::{BindingProof, parse_signature};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// The header that carries the revoked slip.
const LEFT_SLIP_HEADER: &str = "x-oneiron-left-slip";

pub(crate) fn left_notice_routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/v1/shared/left-notices", post(left_notices))
}

/// The person's MemberLeft, MemberRemoved and role-losing Owner notices.
#[derive(Debug, Serialize)]
struct LeftNotices {
    notices: Vec<SharedActOutcome>,
}

async fn left_notices(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<LeftNotices>, EnvelopedApiError> {
    let slip = headers
        .get(LEFT_SLIP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|token| CapabilitySlip::from_token(token.trim()).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let proof = BindingProof::from_headers(&headers)?;
    let signature = parse_signature(&proof.signature)?;
    let notices = tokio::task::spawn_blocking(move || {
        server.vault().removed_member_notices(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(LeftNotices { notices }))
}
