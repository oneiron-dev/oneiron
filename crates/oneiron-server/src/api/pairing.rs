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
    let token = slip.to_token().map_err(|_| ApiError::unauthorized())?;
    // The already redeemed/logged slip is the credential. MCP registration
    // only records its immutable adapter ceiling; it creates no authority.
    register_paired_mcp(&server, &slip, &token).await?;
    Ok(Json(Paired { token }))
}
async fn register_paired_mcp(
    server: &SyncServer,
    slip: &oneiron::authority::CapabilitySlip,
    token: &str,
) -> Result<(), ApiError> {
    use oneiron::federation::{ScopeAxis, ScopeId};
    let claims = &slip.claims;
    if claims.org_ref.is_some() || !claims.scope.verbs.contains(&"read".to_owned()) {
        return Ok(());
    }
    let class = match claims.actor_class.as_deref() {
        Some("human") => oneiron::EdgeActorClass::Human,
        Some("agent") => oneiron::EdgeActorClass::Agent,
        Some("system") => oneiron::EdgeActorClass::System,
        _ => return Ok(()),
    };
    // This MCP adapter can represent only all or one id on each legacy axis.
    // Other paired instruments still work on the canonical /v1 read door.
    let axis = |axis: &ScopeAxis<ScopeId>| match axis {
        ScopeAxis::All => Some(None),
        ScopeAxis::Some(ids) if ids.len() == 1 => ids.first().map(|id| Some(id.0)),
        _ => None,
    };
    let (Some(world), Some(facet)) = (axis(&claims.scope.worlds), axis(&claims.scope.facets)) else {
        return Ok(());
    };
    let actor = oneiron::EntityId::from_hex(&claims.holder_ref).map_err(|_| ApiError::unauthorized())?;
    server.mcp_registry.lock().await.register(token,
        crate::mcp::McpConnectorActorRecord::new(actor, class,
            crate::mcp::McpConnectorScope::scoped(world, facet)).with_expiry(claims.expires_at))
        .map_err(|_| ApiError::unauthorized())
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
