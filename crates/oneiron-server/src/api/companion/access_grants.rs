//! Companion access-grant routes and DTOs.

use super::super::json_payload;
use super::super::parse_entity_id_param;
use super::super::parse_optional_entity_id;
use super::super::unix_seconds_now;
use super::auth::auth_bound_principal_ref;
use super::auth::require_companion_access_grant_write;
use super::auth::require_companion_access_grant_write_for_principal;
use super::errors::companion_create_error;
use super::errors::companion_engine_error;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::Json;
use oneiron::access_grant::{CompanionGrantIssuer, CompanionGrantOutcome};
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Scope payload for companion AccessGrant control-plane records.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "companion_profile",
    "person_ref": "11111111111111111111111111111111",
    "facet_ref": "22222222222222222222222222222222"
}))]
pub(crate) struct CompanionAccessGrantScopePayload {
    /// Scope discriminator. Currently only `companion_profile` is accepted.
    #[schema(example = "companion_profile")]
    kind: String,
    /// PERSON whose companion profile the grant covers.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: String,
    /// FACET the grant is bounded to. Absent or null covers the PERSON at
    /// every facet; a named facet covers that facet only.
    #[serde(default)]
    #[schema(example = "22222222222222222222222222222222")]
    facet_ref: Option<String>,
}

/// Request body for creating a companion AccessGrant.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "principal_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "scope": {
        "kind": "companion_profile",
        "person_ref": "11111111111111111111111111111111",
        "facet_ref": "22222222222222222222222222222222"
    },
    "created_at": 1700000000
}))]
pub(crate) struct CompanionCreateAccessGrantRequest {
    /// Optional grant entity id. Defaults to a new opaque ULID entity id.
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
    /// Optional expiry in Unix seconds; expired grants authorize no reads.
    expires_at: Option<u64>,
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
    /// Expiry in Unix seconds, when bounded.
    expires_at: Option<u64>,
}

/// A companion grant asked past its issuer's bounds, kept whole as a pending
/// access request for the owner (FIX 8140). It authorizes nothing.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionAccessRequestPendingResponse {
    /// Request id; an approval creates the grant at this id.
    #[schema(example = "33333333333333333333333333333333")]
    request_id: String,
    /// Principal the requested grant names.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact companion profile scope requested.
    scope: CompanionAccessGrantScopePayload,
    /// Requested capability.
    #[schema(example = "companion_profile.read")]
    capability: String,
    /// Always `pending`.
    #[schema(example = "pending")]
    status: String,
}

/// A companion grant write's answer: the active grant, or the pending request.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub(crate) enum CompanionAccessGrantCreated {
    Grant(CompanionAccessGrantResponse),
    Request(CompanionAccessRequestPendingResponse),
}

/// HTTP status of a companion grant write that stands active (CALLS
/// "OF-8140 companion grant statuses", open).
const COMPANION_GRANT_ACTIVE_HTTP_STATUS: StatusCode = StatusCode::OK;

/// HTTP status of a companion grant write kept as a pending request (CALLS
/// "OF-8140 companion grant statuses", open).
const COMPANION_GRANT_PENDING_HTTP_STATUS: StatusCode = StatusCode::ACCEPTED;

/// The hosted operator's root acts as nobody (FIX 8139, FIX 2222): it gets
/// the typed support-grant refusal before any body, actor or lookup. Every
/// other answer of the host resolver, and every other credential, keeps its
/// own path.
fn refuse_hosted_root(server: &SyncServer, auth: &CoreAuth) -> Result<(), ApiError> {
    match crate::api::host_action::host_action_of(server.vault(), auth) {
        Some(Err(error @ oneiron::Error::HostActionRequiresSupportGrant)) => {
            Err(crate::api::host_action::host_action_refusal(error))
        }
        _ => Ok(()),
    }
}

/// Who issues a companion grant (FIX 8140): a self-hosted root or the dev
/// mode acting as the owner, and a managed vault's attested owner, carry no
/// record bounds; a verified slip's bounds are the grant's ceiling, judged
/// by the engine in the writing transaction; a credential with no slip
/// carries no bounds to carry.
fn companion_grant_issuer<'a>(server: &SyncServer, auth: &'a CoreAuth) -> CompanionGrantIssuer<'a> {
    if auth.managed_owner().is_some()
        || matches!(
            crate::api::host_action::host_action_of(server.vault(), auth),
            Some(Ok(_))
        )
    {
        return CompanionGrantIssuer::Unbounded;
    }
    auth.verified_slip()
        .map_or(CompanionGrantIssuer::Unbounded, CompanionGrantIssuer::Slip)
}

/// Create a scoped companion AccessGrant.
#[utoipa::path(
    post,
    path = "/v1/companion/access-grants",
    request_body(content = CompanionCreateAccessGrantRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "AccessGrant created, carrying its issuer's bounds.", body = CompanionAccessGrantResponse, content_type = "application/json"),
        (status = 202, description = "The grant asked past its issuer's bounds; it is kept whole as a pending access request.", body = CompanionAccessRequestPendingResponse, content_type = "application/json"),
        (status = 400, description = "Malformed grant request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:access-grant:write or core:auth, or is a hosted operator's root.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "AccessGrant id already exists.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn create_companion_access_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CompanionCreateAccessGrantRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CompanionAccessGrantCreated>), EnvelopedApiError> {
    refuse_hosted_root(&server, &auth)?;
    let req = json_payload(payload)?;
    let grant_id = parse_optional_entity_id(req.id.as_deref(), "id")?;
    let principal_ref = parse_entity_id_param(&req.principal_ref, "principal_ref")?;
    require_companion_access_grant_write_for_principal(&auth, &principal_ref)?;
    let (person_ref, facet_ref) = companion_scope_entity_refs(&req.scope)?;
    let created_at = req.created_at.unwrap_or_else(unix_seconds_now);
    let mut grant = oneiron::AccessGrant::companion_profile_read(
        principal_ref,
        person_ref,
        facet_ref,
        created_at,
    );
    grant.expires_at = req.expires_at;

    let outcome = server
        .vault
        .create_companion_access_grant_admitted(
            &grant_id,
            &grant,
            companion_grant_issuer(&server, &auth),
        )
        .map_err(|error| {
        tracing::error!(kind = ?error.kind(), id = %grant_id.to_hex(), "companion access grant create failed");
            companion_create_error(error)
        })?;

    Ok(match outcome {
        CompanionGrantOutcome::Active(grant) => (
            COMPANION_GRANT_ACTIVE_HTTP_STATUS,
            Json(CompanionAccessGrantCreated::Grant(
                companion_access_grant_response(&grant_id, &grant),
            )),
        ),
        CompanionGrantOutcome::Pending(request) => (
            COMPANION_GRANT_PENDING_HTTP_STATUS,
            Json(CompanionAccessGrantCreated::Request(
                CompanionAccessRequestPendingResponse {
                    request_id: request.id.to_hex(),
                    principal_ref: request.grant.principal_ref.to_hex(),
                    scope: companion_scope_response(&person_ref, facet_ref.as_ref()),
                    capability: request.grant.capability.as_str().to_owned(),
                    status: "pending".to_owned(),
                },
            )),
        ),
    })
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
        (status = 403, description = "Token lacks companion:access-grant:write or core:auth, carries record caveats, or is a hosted operator's root.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "AccessGrant was not found, or is not a companion grant this caller may revoke.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant revoke failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn revoke_companion_access_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(grant_id): Path<String>,
    payload: Result<Json<CompanionRevokeAccessGrantRequest>, JsonRejection>,
) -> Result<Json<CompanionAccessGrantResponse>, EnvelopedApiError> {
    refuse_hosted_root(&server, &auth)?;
    let grant_id = parse_entity_id_param(&grant_id, "grant_id")?;
    let req = json_payload(payload)?;
    let revoked_at = req.revoked_at.unwrap_or_else(unix_seconds_now);

    // The verb and the credential's record bounds are checked before any
    // lookup, and the engine admits the grant in the write that revokes it.
    // A grant the caller may not revoke reads as one that does not exist: no
    // status tells a missing or deleted grant, another principal's grant, a
    // grant of another scope or a row of another type apart.
    require_companion_access_grant_write(&auth)?;
    auth.require_unrestricted_record_scope()?;
    let absent = || ApiError::not_found("access_grant", None);
    let principal = if auth.has_scope(CoreScope::Auth) {
        None
    } else {
        Some(auth_bound_principal_ref(&auth)?.ok_or_else(absent)?)
    };
    let grant = match server
        .vault
        .revoke_companion_access_grant(&grant_id, revoked_at, principal)
    {
        Ok(grant) => grant,
        Err(error)
            if matches!(
                error.kind(),
                oneiron::ErrorKind::EntityNotFound | oneiron::ErrorKind::InvalidEntityType
            ) =>
        {
            return Err(absent().into());
        }
        Err(error) => {
            tracing::error!(kind = ?error.kind(), id = %grant_id.to_hex(), "companion access grant revoke failed");
            return Err(companion_engine_error(
                "companion access grant revoke failed",
                error,
            ));
        }
    };

    Ok(Json(companion_access_grant_response(&grant_id, &grant)))
}

pub(crate) fn companion_scope_entity_refs(
    scope: &CompanionAccessGrantScopePayload,
) -> Result<(oneiron::EntityId, Option<oneiron::EntityId>), ApiError> {
    if scope.kind != "companion_profile" {
        return Err(ApiError::bad_request(
            "scope.kind must be companion_profile",
            Some("scope.kind"),
        ));
    }
    let person_ref = parse_entity_id_param(&scope.person_ref, "scope.person_ref")?;
    let facet_ref = scope
        .facet_ref
        .as_deref()
        .map(|facet_ref| parse_entity_id_param(facet_ref, "scope.facet_ref"))
        .transpose()?;
    Ok((person_ref, facet_ref))
}

pub(crate) fn companion_access_grant_response(
    id: &oneiron::EntityId,
    grant: &oneiron::AccessGrant,
) -> CompanionAccessGrantResponse {
    let (person_ref, facet_ref) = grant
        .scope
        .companion_profile_refs()
        .expect("companion access grants only expose companion_profile scopes");
    CompanionAccessGrantResponse {
        id: id.to_hex(),
        principal_ref: grant.principal_ref.to_hex(),
        scope: companion_scope_response(&person_ref, facet_ref.as_ref()),
        capability: grant.capability.as_str().to_owned(),
        status: grant
            .effective_status_at(unix_seconds_now())
            .as_str()
            .to_owned(),
        created_at: grant.created_at,
        revoked_at: grant.revoked_at,
        expires_at: grant.expires_at,
    }
}

pub(crate) fn companion_scope_response(
    person_ref: &oneiron::EntityId,
    facet_ref: Option<&oneiron::EntityId>,
) -> CompanionAccessGrantScopePayload {
    CompanionAccessGrantScopePayload {
        kind: "companion_profile".to_owned(),
        person_ref: person_ref.to_hex(),
        facet_ref: facet_ref.map(|facet_ref| facet_ref.to_hex()),
    }
}
