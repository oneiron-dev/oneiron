use super::check_api_auth;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Request body for revoking one device lease binding.
#[derive(Deserialize, ToSchema)]
#[schema(example = json!({
    "client_id": "0000000000000042"
}))]
pub(crate) struct LeaseRevokeRequest {
    /// Device lease-binding id to revoke for lost-device or stolen-device recovery. The value is the binding's registry key encoded as 16 lowercase hex chars (`{:016x}`).
    #[schema(example = "0000000000000042")]
    client_id: String,
}

/// Result of a lease revocation request.
#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "revoked": true
}))]
pub(crate) struct LeaseRevokeResponse {
    /// `true` when an active binding was found and marked revoked; `false` when the id was well-formed but no binding existed.
    #[schema(example = true)]
    revoked: bool,
}

/// Revokes a device-lease binding (owner recovery, OD-8 — terminal for the
/// binding; auth = Phase-1 shared secret, same as every API route). The
/// registry change is broadcast to all live connections so replica `ls:`
/// mirrors converge without a reconnect.
#[utoipa::path(
    post,
    path = "/api/lease/revoke",
    request_body(
        content = LeaseRevokeRequest,
        description = "Lease binding to revoke for owner recovery.",
        content_type = "application/json"
    ),
    responses(
        (
            status = 200,
            description = "Lease revocation completed or found no matching binding.",
            body = LeaseRevokeResponse,
            content_type = "application/json",
            example = json!({
                "revoked": true
            })
        ),
        (
            status = 400,
            description = "`client_id` is not exactly 16 lowercase hex characters.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Lease revocation failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn lease_revoke(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(req): Json<LeaseRevokeRequest>,
) -> Result<Json<LeaseRevokeResponse>, ApiError> {
    check_api_auth(&headers, &server)?;

    if req.client_id.len() != 16
        || !req
            .client_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad_request(
            "client_id must be exactly 16 lowercase hex characters",
            Some("client_id"),
        ));
    }
    let client_id = u64::from_str_radix(&req.client_id, 16).map_err(|_| {
        ApiError::bad_request(
            "client_id must be exactly 16 lowercase hex characters",
            Some("client_id"),
        )
    })?;

    match server.revoke_lease(client_id).await {
        Ok(Some(update)) => {
            let msg = crate::protocol::encode_root_update(&update);
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, msg);
            Ok(Json(LeaseRevokeResponse { revoked: true }))
        }
        Ok(None) => Ok(Json(LeaseRevokeResponse { revoked: false })),
        Err(e) => {
            tracing::error!(error = %e, "lease revoke failed");
            Err(ApiError::internal_server_error("lease revoke failed"))
        }
    }
}

/// Fresh-key proof for initial registration or owner-authorized rotation.
#[derive(Deserialize, ToSchema)]
pub(crate) struct LeaseRegisterRequest {
    client_id: u64,
    pubkey: String,
    proof: String,
    old_client_id: Option<u64>,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct LeaseRegisterResponse {
    /// Opaque vault scope, lossless in JavaScript and ready for x-oneiron-vault.
    vault_id: String,
    granted: bool,
    expires_at: u64,
}
#[utoipa::path(post, path = "/api/lease/register", request_body = LeaseRegisterRequest,
    responses((status = 200, body = LeaseRegisterResponse), (status = 401, body = ApiError)))]
pub(crate) async fn lease_register(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(req): Json<LeaseRegisterRequest>,
) -> Result<Json<LeaseRegisterResponse>, ApiError> {
    lease_intake(&headers, &server, req, false).await
}
#[utoipa::path(post, path = "/api/lease/rotate", request_body = LeaseRegisterRequest,
    responses((status = 200, body = LeaseRegisterResponse), (status = 401, body = ApiError)))]
pub(crate) async fn lease_rotate(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(req): Json<LeaseRegisterRequest>,
) -> Result<Json<LeaseRegisterResponse>, ApiError> {
    lease_intake(&headers, &server, req, true).await
}
async fn lease_intake(
    headers: &HeaderMap,
    server: &SyncServer,
    req: LeaseRegisterRequest,
    rotate: bool,
) -> Result<Json<LeaseRegisterResponse>, ApiError> {
    // Owner recovery is independent of the old device's lease (which may be lost).
    check_api_auth(headers, server)?;
    let key =
        crate::server::vault_binding::decode_hex(&req.pubkey).ok_or_else(ApiError::unauthorized)?;
    let proof =
        crate::server::vault_binding::decode_hex(&req.proof).ok_or_else(ApiError::unauthorized)?;
    let decision = if rotate {
        server
            .rotate_lease(
                req.old_client_id.ok_or_else(ApiError::unauthorized)?,
                req.client_id,
                &key,
                &proof,
            )
            .await
    } else {
        server.register_lease(req.client_id, &key, &proof).await
    }
    .map_err(|_| ApiError::internal_server_error("lease registration failed"))?;
    if let Some(update) = decision.root_update {
        let _ = crate::broadcast::broadcast(
            &server.broadcast_tx,
            0,
            crate::protocol::encode_root_update(&update),
        );
    }
    Ok(Json(LeaseRegisterResponse {
        vault_id: format!("{:016x}", server.config.lease_vault_id),
        granted: decision.granted,
        expires_at: decision.expires_at,
    }))
}
