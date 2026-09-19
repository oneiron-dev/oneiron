//! Pairing-only enrollment and unauthenticated liveness discovery.
use crate::{error::ApiError, server::SyncServer};
use axum::{Json, extract::State, http::HeaderMap};
use oneiron::authority::{HostSlipIssuer, PairingDescriptor, PairingPrincipal};
use oneiron::federation::Scope;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(super) async fn descriptor() -> Json<PairingDescriptor> {
    Json(PairingDescriptor::default())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateLink {
    scope: Scope,
    lifetime_secs: u64,
    #[serde(default)]
    principal: PairingPrincipal,
}
pub(super) async fn create_link(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<CreateLink>,
) -> Result<Json<oneiron::authority::PairingLink>, ApiError> {
    super::check_api_auth(&headers, &server)?;
    let issuer = issuer(&server)?;
    let link = server
        .vault()
        .issue_pairing_link_for_principal(
            &issuer,
            request.scope,
            request.lifetime_secs,
            request.principal,
        )
        .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(link))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedeemLink {
    ticket: String,
    holder_ref: String,
    binding_key: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Serialize)]
pub(super) struct Paired {
    token: String,
}
pub(super) async fn redeem(
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<RedeemLink>,
) -> Result<Json<Paired>, ApiError> {
    // Pairing creates a capability for a named existing actor; it never enrolls
    // a roster authority key or manufactures a principal from an arbitrary label.
    let actor =
        oneiron::EntityId::from_hex(&request.holder_ref).map_err(|_| ApiError::unauthorized())?;
    if server
        .vault()
        .get(&actor)
        .map_err(|_| ApiError::unauthorized())?
        .is_none()
    {
        return Err(ApiError::unauthorized());
    }
    let slip = server
        .vault()
        .redeem_pairing_link(
            &issuer(&server)?,
            &request.ticket,
            &request.holder_ref,
            request.binding_key,
            &request.signature,
        )
        .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(Paired {
        token: slip.to_token().map_err(|_| ApiError::unauthorized())?,
    }))
}
fn issuer(server: &SyncServer) -> Result<HostSlipIssuer, ApiError> {
    let secret = server
        .config
        .auth_secret
        .as_deref()
        .ok_or_else(ApiError::unauthorized)?;
    HostSlipIssuer::from_secret(secret.as_bytes()).map_err(|_| ApiError::unauthorized())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevokeSlip {
    slip_id: [u8; 32],
}
pub(super) async fn revoke(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<RevokeSlip>,
) -> Result<Json<serde_json::Value>, ApiError> {
    super::check_api_auth(&headers, &server)?;
    server
        .vault()
        .revoke_capability_slip(&issuer(&server)?, request.slip_id)
        .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(serde_json::json!({"revoked":true})))
}
