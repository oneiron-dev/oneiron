//! Companion access-grant routes and DTOs.

use super::super::json_payload;
use super::super::parse_entity_id_param;
use super::super::parse_optional_entity_id;
use super::super::unix_seconds_now;
use super::auth::require_companion_access_grant_write_for_principal;
use super::errors::companion_create_error;
use super::errors::companion_engine_error;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Scope payload for companion AccessGrant control-plane records.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "companion_profile",
    "person_ref": "11111111111111111111111111111111",
    "persona_ref": "22222222222222222222222222222222"
}))]
pub(crate) struct CompanionAccessGrantScopePayload {
    /// Scope discriminator. Currently only `companion_profile` is accepted.
    #[schema(example = "companion_profile")]
    kind: String,
    /// Person scope for the companion profile.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: String,
    /// Persona/profile entity receiving scoped access.
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: String,
}

/// Request body for creating a companion AccessGrant.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "principal_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "scope": {
        "kind": "companion_profile",
        "person_ref": "11111111111111111111111111111111",
        "persona_ref": "22222222222222222222222222222222"
    },
    "created_at": 1700000000
}))]
pub(crate) struct CompanionCreateAccessGrantRequest {
    /// Optional grant entity id. Defaults to a new UUIDv7 entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: Option<String>,
    /// Principal receiving access.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact companion profile scope.
    scope: CompanionAccessGrantScopePayload,
    /// Creation timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000000)]
    created_at: Option<u64>,
}

/// Request body for revoking a companion AccessGrant.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "revoked_at": 1700000300 }))]
pub(crate) struct CompanionRevokeAccessGrantRequest {
    /// Revocation timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000300)]
    revoked_at: Option<u64>,
}

/// AccessGrant response body.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionAccessGrantResponse {
    /// Grant entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: String,
    /// Principal receiving access.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact companion profile scope.
    scope: CompanionAccessGrantScopePayload,
    /// Granted capability.
    #[schema(example = "companion_profile.read")]
    capability: String,
    /// Grant status.
    #[schema(example = "active")]
    status: String,
    /// Creation timestamp in Unix seconds.
    #[schema(example = 1700000000)]
    created_at: u64,
    /// Revocation timestamp when status is `revoked`.
    #[schema(example = 1700000300)]
    revoked_at: Option<u64>,
}

/// Create a scoped companion AccessGrant.
#[utoipa::path(
    post,
    path = "/v1/companion/access-grants",
    request_body(content = CompanionCreateAccessGrantRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "AccessGrant created.", body = CompanionAccessGrantResponse, content_type = "application/json"),
        (status = 400, description = "Malformed grant request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:access-grant:write or core:auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "AccessGrant id already exists.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn create_companion_access_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CompanionCreateAccessGrantRequest>, JsonRejection>,
) -> Result<Json<CompanionAccessGrantResponse>, EnvelopedApiError> {
    let req = json_payload(payload)?;
    let grant_id = parse_optional_entity_id(req.id.as_deref(), "id")?;
    let principal_ref = parse_entity_id_param(&req.principal_ref, "principal_ref")?;
    require_companion_access_grant_write_for_principal(&auth, &principal_ref)?;
    let (person_ref, persona_ref) = companion_scope_entity_refs(&req.scope)?;
    let created_at = req.created_at.unwrap_or_else(unix_seconds_now);
    let grant = oneiron::AccessGrant::companion_profile_read(
        principal_ref,
        person_ref,
        persona_ref,
        created_at,
    );

    server
        .vault
        .create_access_grant(&grant_id, &grant)
        .map_err(|error| {
        tracing::error!(error = %error, id = %grant_id.to_hex(), "companion access grant create failed");
            companion_create_error(error)
        })?;

    Ok(Json(companion_access_grant_response(&grant_id, &grant)))
}

/// Revoke a scoped companion AccessGrant.
#[utoipa::path(
    post,
    path = "/v1/companion/access-grants/{grant_id}/revoke",
    params(("grant_id" = String, Path, description = "AccessGrant entity id.")),
    request_body(content = CompanionRevokeAccessGrantRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "AccessGrant revoked.", body = CompanionAccessGrantResponse, content_type = "application/json"),
        (status = 400, description = "Malformed grant id or request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:access-grant:write or core:auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "AccessGrant was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant revoke failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn revoke_companion_access_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(grant_id): Path<String>,
    payload: Result<Json<CompanionRevokeAccessGrantRequest>, JsonRejection>,
) -> Result<Json<CompanionAccessGrantResponse>, EnvelopedApiError> {
    let grant_id = parse_entity_id_param(&grant_id, "grant_id")?;
    let req = json_payload(payload)?;
    let revoked_at = req.revoked_at.unwrap_or_else(unix_seconds_now);

    let existing = server
        .vault
        .get_access_grant(&grant_id)
        .map_err(|error| {
            tracing::error!(error = %error, id = %grant_id.to_hex(), "companion access grant read failed");
            companion_engine_error("companion access grant read failed", error)
        })?
        .ok_or_else(|| ApiError::not_found("access_grant", None))?;
    require_companion_access_grant_write_for_principal(&auth, &existing.principal_ref)?;

    let grant = server
        .vault
        .revoke_access_grant(&grant_id, revoked_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %grant_id.to_hex(), "companion access grant revoke failed");
            companion_engine_error("companion access grant revoke failed", error)
        })?;

    Ok(Json(companion_access_grant_response(&grant_id, &grant)))
}

pub(crate) fn companion_scope_entity_refs(
    scope: &CompanionAccessGrantScopePayload,
) -> Result<(oneiron::EntityId, oneiron::EntityId), ApiError> {
    if scope.kind != "companion_profile" {
        return Err(ApiError::bad_request(
            "scope.kind must be companion_profile",
            Some("scope.kind"),
        ));
    }
    let person_ref = parse_entity_id_param(&scope.person_ref, "scope.person_ref")?;
    let persona_ref = parse_entity_id_param(&scope.persona_ref, "scope.persona_ref")?;
    Ok((person_ref, persona_ref))
}

pub(crate) fn companion_access_grant_response(
    id: &oneiron::EntityId,
    grant: &oneiron::AccessGrant,
) -> CompanionAccessGrantResponse {
    let (person_ref, persona_ref) = grant
        .scope
        .companion_profile_refs()
        .expect("companion access grants only expose companion_profile scopes");
    CompanionAccessGrantResponse {
        id: id.to_hex(),
        principal_ref: grant.principal_ref.to_hex(),
        scope: companion_scope_response(&person_ref, &persona_ref),
        capability: grant.capability.as_str().to_owned(),
        status: grant.status.as_str().to_owned(),
        created_at: grant.created_at,
        revoked_at: grant.revoked_at,
    }
}

pub(crate) fn companion_scope_response(
    person_ref: &oneiron::EntityId,
    persona_ref: &oneiron::EntityId,
) -> CompanionAccessGrantScopePayload {
    CompanionAccessGrantScopePayload {
        kind: "companion_profile".to_owned(),
        person_ref: person_ref.to_hex(),
        persona_ref: persona_ref.to_hex(),
    }
}
