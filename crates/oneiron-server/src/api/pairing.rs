//! Pairing-only enrollment and unauthenticated liveness discovery.
use crate::auth::{parse_signature, parse_slip_id};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;
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
) -> Result<Json<oneiron::authority::PairingLink>, EnvelopedApiError> {
    super::check_api_auth(&headers, &server)?;
    let link = with_issuer(&server, |issuer| {
        server.vault().issue_pairing_link_for_principal(
            issuer,
            request.scope,
            request.lifetime_secs,
            request.principal,
        )
    })?;
    Ok(Json(link))
}
/// OAuth identity validation is a bootstrap door only. No JWT can read or
/// propose directly: the host logs a scoped slip and the holder proves its
/// own fresh signing key before the token leaves this door.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OAuthExchange {
    binding_key: String,
    nonce: String,
    signature: String,
}
pub(super) async fn oauth_exchange(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<OAuthExchange>,
) -> Result<Json<Paired>, EnvelopedApiError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use oneiron::federation::{Scope, ScopeAxis};

    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.starts_with("v2.slip."))
        .ok_or_else(ApiError::unauthorized)?;
    let identity = crate::oauth_relay::verify_oauth_relay_identity(raw, &server.config)?;
    let actor =
        oneiron::EntityId::from_hex(&identity.subject).map_err(|_| ApiError::unauthorized())?;
    if server
        .vault()
        .get(&actor)
        .map_err(|_| ApiError::unauthorized())?
        .is_none()
    {
        return Err(ApiError::unauthorized().into());
    }
    let key_bytes = parse_slip_id(&request.binding_key)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| ApiError::unauthorized())?;
    let signature = Signature::from_slice(&parse_signature(&request.signature)?)
        .map_err(|_| ApiError::unauthorized())?;
    let transcript = crate::oauth_relay::oauth_binding_transcript(raw, &key_bytes, &request.nonce)?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| ApiError::unauthorized())?;
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::unauthorized())?
        .as_secs();
    let ttl = identity.expires_at.saturating_sub(wall_now).min(3600);
    if ttl == 0 {
        return Err(ApiError::unauthorized().into());
    }
    let now = server
        .vault()
        .capability_slip_now()
        .map_err(|_| ApiError::unauthorized())?;
    let expires_at = now.saturating_add(ttl);
    let slip = with_issuer(&server, |issuer| {
        let mut claims = server.vault().ensure_host_root_slip(issuer)?.claims;
        let mut seed = Vec::from(blake3::hash(raw.as_bytes()).as_bytes().as_slice());
        seed.extend_from_slice(request.nonce.as_bytes());
        seed.extend_from_slice(&key_bytes);
        claims.slip_id = *blake3::hash(&seed).as_bytes();
        claims.parent_id = None;
        claims.holder_ref = actor.to_hex();
        claims.binding_key = key_bytes;
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(
            identity
                .scopes
                .iter()
                .map(|scope| match scope {
                    crate::auth::CoreScope::Read => "read".to_owned(),
                    crate::auth::CoreScope::Propose => "core:propose".to_owned(),
                    _ => scope.as_str().to_owned(),
                })
                .collect(),
        );
        claims.issued_at = now;
        claims.expires_at = expires_at;
        claims.ttl_secs = ttl;
        server.vault().mint_capability_slip(issuer, claims)
    })?;
    Ok(Json(Paired {
        token: slip.to_token().map_err(|_| ApiError::unauthorized())?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedeemLink {
    code: String,
    holder_ref: String,
    binding_key: String,
    signature: String,
}
#[derive(Serialize)]
pub(super) struct Paired {
    token: String,
}
pub(super) async fn redeem(
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<RedeemLink>,
) -> Result<Json<Paired>, EnvelopedApiError> {
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
        return Err(ApiError::unauthorized().into());
    }
    let binding_key = parse_slip_id(&request.binding_key)?;
    let signature = parse_signature(&request.signature)?;
    let slip = with_issuer(&server, |issuer| {
        server.vault().redeem_pairing_link(
            issuer,
            &request.code,
            &request.holder_ref,
            binding_key,
            &signature,
        )
    })?;
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
    let (Some(world), Some(facet)) = (axis(&claims.scope.worlds), axis(&claims.scope.facets))
    else {
        return Ok(());
    };
    let actor =
        oneiron::EntityId::from_hex(&claims.holder_ref).map_err(|_| ApiError::unauthorized())?;
    server
        .mcp_registry
        .lock()
        .await
        .register(
            token,
            crate::mcp::McpConnectorActorRecord::new(
                actor,
                class,
                crate::mcp::McpConnectorScope::scoped(world, facet),
            )
            .with_expiry(claims.expires_at),
        )
        .map_err(|_| ApiError::unauthorized())
}

fn with_issuer<T>(
    server: &SyncServer,
    operation: impl FnOnce(&HostSlipIssuer) -> oneiron::Result<T>,
) -> Result<T, ApiError> {
    if let Some(issuer) = server.managed_issuer.as_ref() {
        return operation(issuer).map_err(|_| ApiError::unauthorized());
    }
    let secret = server
        .config
        .auth_secret
        .as_deref()
        .ok_or_else(ApiError::unauthorized)?;
    let issuer =
        HostSlipIssuer::from_secret(secret.as_bytes()).map_err(|_| ApiError::unauthorized())?;
    operation(&issuer).map_err(|_| ApiError::unauthorized())
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
) -> Result<Json<serde_json::Value>, EnvelopedApiError> {
    super::check_api_auth(&headers, &server)?;
    with_issuer(&server, |issuer| {
        server
            .vault()
            .revoke_capability_slip(issuer, request.slip_id)
    })?;
    Ok(Json(serde_json::json!({"revoked":true})))
}
