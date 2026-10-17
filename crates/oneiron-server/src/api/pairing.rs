//! Pairing-only enrollment and unauthenticated liveness discovery.
use crate::auth::{parse_signature, parse_slip_id};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;
use axum::{Json, extract::State, http::HeaderMap};
use oneiron::authority::{
    HostSlipIssuer, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    PairingDescriptor, PairingPrincipal,
};
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
    /// The owner's answer for a machine this link adds: `yours`,
    /// `work_school` or `rented`. Only `yours` makes it one of the owner's.
    #[serde(default)]
    machine: Option<MachineOwnership>,
}
pub(super) async fn create_link(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<CreateLink>,
) -> Result<Json<oneiron::authority::PairingLink>, EnvelopedApiError> {
    super::check_api_auth(&headers, &server)?;
    let link = match request.machine {
        None => with_issuer(&server, |issuer| {
            server.vault().issue_pairing_link_for_principal(
                issuer,
                request.scope,
                request.lifetime_secs,
                request.principal,
            )
        })?,
        // Only the owner, in person, answers for a machine.
        Some(ownership) => {
            let auth =
                crate::auth::require_owner_auth(&headers, &server.config, server.vault().as_ref())?;
            let owner = super::owner_routes::owner(&auth, &server)?;
            with_issuer(&server, |issuer| {
                server.vault().issue_machine_pairing_link(
                    issuer,
                    &owner,
                    request.scope,
                    request.lifetime_secs,
                    request.principal,
                    ownership,
                )
            })?
        }
    };
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
    /// Caller narrowing, never an override of the vault/JWT ceiling.
    lifetime_secs: Option<u64>,
}
pub(super) async fn oauth_exchange(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<OAuthExchange>,
) -> Result<Json<Paired>, EnvelopedApiError> {
    use ed25519_dalek::{Signature, VerifyingKey};
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
        .verify_strict(&transcript, &signature)
        .map_err(|_| ApiError::unauthorized())?;
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::unauthorized())?
        .as_secs();
    let jwt_remaining_secs = identity.expires_at.saturating_sub(wall_now);
    if jwt_remaining_secs == 0 {
        return Err(ApiError::unauthorized().into());
    }
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
        server.vault().mint_oauth_capability_slip(
            issuer,
            claims,
            jwt_remaining_secs,
            request.lifetime_secs,
        )
    })?;
    Ok(Json(Paired {
        token: slip.to_token().map_err(|_| ApiError::unauthorized())?,
        pin: None,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedeemLink {
    code: String,
    holder_ref: String,
    binding_key: String,
    signature: String,
    /// The joining machine's enrolment request; required by, and only by, a
    /// link that adds a machine.
    #[serde(default)]
    machine: Option<MachineEnrolment>,
}
/// [`MachineEnrolmentRequest`] on the wire: hex ids and keys, base64 for the
/// 1600-byte encryption key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MachineEnrolment {
    vault_id: String,
    machine: String,
    machine_key: String,
    encryption_suite: u16,
    encryption_key: String,
    machine_proof: String,
}
impl MachineEnrolment {
    fn request(&self) -> Result<MachineEnrolmentRequest, ApiError> {
        use base64::Engine as _;
        let machine_proof = <[u8; 64]>::try_from(parse_signature(&self.machine_proof)?)
            .map_err(|_| ApiError::unauthorized())?;
        Ok(MachineEnrolmentRequest {
            vault_id: parse_slip_id(&self.vault_id)?,
            machine: oneiron::EntityId::from_hex(&self.machine)
                .map_err(|_| ApiError::unauthorized())?,
            machine_key: parse_slip_id(&self.machine_key)?,
            encryption_key: MachineEncryptionKey {
                suite: self.encryption_suite,
                key: base64::engine::general_purpose::STANDARD
                    .decode(&self.encryption_key)
                    .map_err(|_| ApiError::unauthorized())?,
            },
            machine_proof,
        })
    }
}
#[derive(Serialize)]
pub(super) struct Paired {
    token: String,
    /// The checkpoint pin the redeemed link kept (OF-469); the joining client
    /// checks it against the challenge and digest its link carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pin: Option<oneiron::authority::AuthorityCheckpointPin>,
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
    let machine = request
        .machine
        .as_ref()
        .map(MachineEnrolment::request)
        .transpose()?;
    let redeemed = with_issuer(&server, |issuer| {
        server.vault().redeem_pairing_link_pinned(
            issuer,
            &request.code,
            &request.holder_ref,
            binding_key,
            &signature,
            machine.as_ref(),
        )
    })?;
    let slip = redeemed.slip;
    let token = slip.to_token().map_err(|_| ApiError::unauthorized())?;
    // The already redeemed/logged slip is the credential. MCP registration
    // only records its immutable adapter ceiling; it creates no authority.
    if let Some(record) = paired_mcp_record(server.vault(), &slip.claims)? {
        server
            .mcp_registry
            .lock()
            .await
            .register(&token, record)
            .map_err(|_| ApiError::unauthorized())?;
    }
    Ok(Json(Paired {
        token,
        pin: redeemed.pin,
    }))
}

/// The MCP adapter record a paired slip's claims map to, or `None` for a slip
/// the adapter cannot represent. The one rule for redeem and for a slip the
/// registry learns later ([`register_live_paired_mcp`]). A connector that
/// reads several facets writes in the one the owner named on the link, kept
/// beside the slip's id, or in the smallest.
fn paired_mcp_record(
    vault: &oneiron::Vault,
    claims: &oneiron::authority::SlipClaims,
) -> Result<Option<crate::mcp::McpConnectorActorRecord>, ApiError> {
    use oneiron::federation::ScopeAxis;
    // `read` and `core:read` are one scope on every other door
    // (`CoreAuth::from_verified`); this one reads both spellings too.
    let reads = ["read", crate::auth::CoreScope::Read.as_str()]
        .into_iter()
        .any(|verb| claims.scope.verbs.contains(&verb.to_owned()));
    if claims.org_ref.is_some() || !reads {
        return Ok(None);
    }
    let class = match claims.actor_class.as_deref() {
        Some("human") => oneiron::EdgeActorClass::Human,
        Some("agent") => oneiron::EdgeActorClass::Agent,
        Some("system") => oneiron::EdgeActorClass::System,
        _ => return Ok(None),
    };
    // This MCP adapter holds all or one world, and all or a set of facets
    // (owner ruling FACET-READ). Other paired instruments still work on the
    // canonical /v1 read door.
    let world = match &claims.scope.worlds {
        ScopeAxis::All => None,
        ScopeAxis::Some(ids) if ids.len() == 1 => ids.first().map(|id| id.0),
        _ => return Ok(None),
    };
    let scope = match &claims.scope.facets {
        ScopeAxis::All => crate::mcp::McpConnectorScope::scoped(world, None),
        ScopeAxis::Some(ids) => {
            let write_facet = vault
                .paired_write_facet(&claims.slip_id)
                .map_err(|_| ApiError::unauthorized())?;
            let Some(scope) = crate::mcp::McpConnectorScope::with_facets(
                world,
                ids.iter().map(|id| id.0).collect(),
                write_facet,
            ) else {
                return Ok(None);
            };
            scope
        }
        ScopeAxis::Bottom => return Ok(None),
    };
    let actor =
        oneiron::EntityId::from_hex(&claims.holder_ref).map_err(|_| ApiError::unauthorized())?;
    Ok(Some(
        crate::mcp::McpConnectorActorRecord::new(actor, class, scope)
            .with_expiry(claims.expires_at),
    ))
}

/// Records a live paired slip the in-memory registry has not seen: one
/// redeemed before this process started, or minted on the stopped vault
/// (`token agent`, `token read`). The slip must verify with its holder proof
/// first, against the log and its revocations, exactly as every request's
/// does; then it gets the record redeem would have written. Returns whether
/// it recorded one.
///
/// Only the slip as redeem minted it: a holder's caveated copy has its own
/// token, and a fresh record for it would drop whatever the registry holds
/// against the original.
pub(super) fn register_live_paired_mcp(
    registry: &mut crate::mcp::McpConnectorActorRegistry,
    credential: &str,
    headers: &HeaderMap,
    server: &SyncServer,
) -> bool {
    let uncaveated = oneiron::authority::CapabilitySlip::from_token(credential)
        .is_ok_and(|slip| slip.caveats.is_empty());
    if !credential.starts_with("v2.slip.") || !uncaveated {
        return false;
    }
    let verified = crate::auth::BindingProof::from_headers(headers).and_then(|proof| {
        crate::auth::CoreAuth::from_slip_token(credential, &proof, server.vault().as_ref())
    });
    let Some(slip) = verified.as_ref().ok().and_then(|auth| auth.verified_slip()) else {
        return false;
    };
    // Redeem pairs only a holder that exists; neither does this.
    let holder_exists = oneiron::EntityId::from_hex(&slip.claims().holder_ref)
        .ok()
        .and_then(|holder| server.vault().get(&holder).ok().flatten())
        .is_some();
    if !holder_exists {
        return false;
    }
    match paired_mcp_record(server.vault(), slip.claims()) {
        Ok(Some(record)) => registry.register(credential, record).is_ok(),
        _ => false,
    }
}

pub(super) fn with_issuer<T>(
    server: &SyncServer,
    operation: impl FnOnce(&HostSlipIssuer) -> oneiron::Result<T>,
) -> Result<T, ApiError> {
    // A scope the vault refuses on a link says why; every other failure
    // stays an unexplained 401.
    let refusal = |error: oneiron::Error| match error.kind() {
        oneiron::ErrorKind::InvalidPairingScope => {
            ApiError::bad_request(error.to_string(), Some("scope.facets"))
        }
        _ => ApiError::unauthorized(),
    };
    if let Some(issuer) = server.managed_issuer.as_ref() {
        return operation(issuer).map_err(refusal);
    }
    let secret = server
        .config
        .auth_secret
        .as_deref()
        .ok_or_else(ApiError::unauthorized)?;
    let issuer =
        HostSlipIssuer::from_secret(secret.as_bytes()).map_err(|_| ApiError::unauthorized())?;
    operation(&issuer).map_err(refusal)
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
