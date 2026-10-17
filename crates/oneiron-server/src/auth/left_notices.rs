//! `POST /v1/shared/left-notices` (OF-158 client leave): a device whose
//! person left or was removed from this shared vault learns it, though leave
//! revoked its slips. `POST /v1/shared/removal-export` (OF-150) answers that
//! person, under the same proof, the archive an export-first removal kept
//! for them. The request carries that slip in `x-oneiron-left-slip`
//! (never as a bearer token, which the network door would refuse) and the
//! usual holder proof in `x-oneiron-binding`; the engine checks the slip is
//! one this vault minted and the device holds its key, spends the nonce, and
//! answers only the person's own loss-of-access notices, each signed by this
//! host's root key (FIX 2053). A host holding no signing key answers none.
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{RemovalExportCopy, SignedSharedActOutcome};
use serde::Serialize;

use super::{BindingProof, parse_signature};
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::server::SyncServer;

/// The header that carries the revoked slip.
const LEFT_SLIP_HEADER: &str = "x-oneiron-left-slip";

pub(crate) fn left_notice_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/shared/left-notices", post(left_notices))
        .route("/v1/shared/removal-export", post(removal_exports))
}

/// The person's MemberLeft, MemberRemoved and role-losing Owner notices,
/// and the vault's deletion, each signed by this host's root key.
#[derive(Debug, Serialize)]
struct LeftNotices {
    notices: Vec<SignedSharedActOutcome>,
}

/// The archives export-first removals kept for the person, still within
/// their retention.
#[derive(Debug, Serialize)]
struct RemovalExports {
    exports: Vec<RemovalExportCopy>,
}

/// The revoked slip and the holder proof a removed device presents.
fn left_proof(headers: &HeaderMap) -> Result<(CapabilitySlip, BindingProof, Vec<u8>), ApiError> {
    let slip = headers
        .get(LEFT_SLIP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|token| CapabilitySlip::from_token(token.trim()).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let proof = BindingProof::from_headers(headers)?;
    let signature = parse_signature(&proof.signature)?;
    Ok((slip, proof, signature))
}

async fn removal_exports(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<RemovalExports>, EnvelopedApiError> {
    let (slip, proof, signature) = left_proof(&headers)?;
    let exports = tokio::task::spawn_blocking(move || {
        server.vault().removed_owner_exports(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(RemovalExports { exports }))
}

/// A host with no root key to sign with: it answers no notice, never an
/// unsigned one, and spends no nonce.
fn no_notice_signing_key() -> ApiError {
    ApiError::new(
        "this host holds no signing key for leave notices",
        ApiErrorDetails::NotImplemented,
        ["Every leave notice is signed by the host's root key; this host answers none unsigned."],
    )
}

/// Runs `sign` with this host's root key: the managed issuer, else the one
/// the configured retained secret derives. Neither refuses before the
/// engine is asked, so no nonce is spent.
fn with_notice_issuer<T>(
    server: &SyncServer,
    sign: impl FnOnce(&HostSlipIssuer) -> oneiron::Result<T>,
) -> Result<T, ApiError> {
    if let Some(issuer) = server.managed_issuer.as_ref() {
        return sign(issuer).map_err(|_| ApiError::unauthorized());
    }
    let secret = server
        .config
        .auth_secret
        .as_deref()
        .ok_or_else(no_notice_signing_key)?;
    let issuer =
        HostSlipIssuer::from_secret(secret.as_bytes()).map_err(|_| no_notice_signing_key())?;
    sign(&issuer).map_err(|_| ApiError::unauthorized())
}

async fn left_notices(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<LeftNotices>, EnvelopedApiError> {
    let (slip, proof, signature) = left_proof(&headers)?;
    let notices = tokio::task::spawn_blocking(move || {
        with_notice_issuer(&server, |issuer| {
            server.vault().removed_member_notices_signed(
                issuer,
                &slip,
                proof.timestamp,
                &signature,
                proof.nonce.as_bytes(),
            )
        })
    })
    .await
    .map_err(|_| ApiError::unauthorized())??;
    Ok(Json(LeftNotices { notices }))
}
