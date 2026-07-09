use super::has_json_content_type;
use super::hex_bytes;
use super::json_payload;
use super::parse_entity_id_param;
use super::parse_optional_entity_id;
use super::query_params;
use super::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::ErrorKind;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

pub(crate) fn optional_companion_profile_refresh_request(
    headers: &HeaderMap,
    payload: Result<Bytes, BytesRejection>,
) -> Result<CompanionProfileRefreshRequest, ApiError> {
    let payload = payload.map_err(|_| ApiError::bad_request("invalid JSON request body", None))?;
    if payload.is_empty() {
        return Ok(CompanionProfileRefreshRequest::default());
    }

    if !has_json_content_type(headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None));
    }

    serde_json::from_slice(&payload)
        .map_err(|_| ApiError::bad_request("invalid JSON request body", None))
}

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

/// Query parameters for companion profile reads.
#[derive(Clone, Debug, Deserialize, IntoParams)]
pub(crate) struct CompanionProfileQuery {
    /// Principal requesting profile access. Optional for bearer tokens that
    /// bind `principal_ref`; arbitrary overrides require admin auth.
    #[param(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: Option<String>,
    /// Person scope for the companion profile.
    #[param(example = "11111111111111111111111111111111")]
    person_ref: String,
    /// Optional comma-separated source revisions to check freshness against.
    #[serde(rename = "sourceRevisionIds", alias = "source_revision_ids")]
    #[param(example = "cccccccccccccccccccccccccccccccc,dddddddddddddddddddddddddddddddd")]
    source_revision_ids: Option<String>,
}

/// Access evidence returned with a companion profile response.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfileAccess {
    /// Grant entity id that authorized the response.
    #[schema(example = "33333333333333333333333333333333")]
    grant_id: String,
    /// Principal authorized by the grant.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact scope authorized by the grant.
    scope: CompanionAccessGrantScopePayload,
}

/// Psych mirror tier payload backed by one persisted PsychProfile record.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfilePayload {
    /// Entity the profile describes.
    #[schema(example = "22222222222222222222222222222222")]
    subject_ref: String,
    /// Compact tier optimized for cheap profile display.
    #[schema(example = "warm, concise profile")]
    compact: String,
    /// Text tier optimized for retrieval/context assembly.
    #[schema(example = "retrieval-friendly psych mirror text")]
    text: String,
    /// Narrative tier optimized for companion mirror rendering.
    #[schema(example = "A warm narrative profile for the companion.")]
    narrative: String,
    /// Persisted source revisions used to build this profile.
    #[serde(rename = "sourceRevisionIds")]
    #[schema(example = json!(["cccccccccccccccccccccccccccccccc"]))]
    source_revision_ids: Vec<String>,
    /// Per-tier confidence metadata.
    confidence: CompanionProfileConfidencePayload,
    /// Stored snapshot status.
    #[schema(example = "fresh")]
    status: String,
}

/// Per-tier confidence metadata returned with a profile payload.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfileConfidencePayload {
    /// Confidence for the compact tier.
    #[schema(example = 0.8)]
    compact: f32,
    /// Confidence for the text tier.
    #[schema(example = 0.7)]
    text: f32,
    /// Confidence for the narrative tier.
    #[schema(example = 0.6)]
    narrative: f32,
}

/// Typed stale reason for a companion profile read.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfileStaleReasonPayload {
    /// Stable reason code.
    #[schema(example = "source_revision_mismatch")]
    kind: String,
    /// Source revisions requested by the caller when they differ from storage.
    #[serde(rename = "expectedSourceRevisionIds")]
    #[schema(example = json!(["dddddddddddddddddddddddddddddddd"]))]
    expected_source_revision_ids: Option<Vec<String>>,
    /// Source revisions persisted on the profile when they differ.
    #[serde(rename = "actualSourceRevisionIds")]
    #[schema(example = json!(["cccccccccccccccccccccccccccccccc"]))]
    actual_source_revision_ids: Option<Vec<String>>,
}

/// Drift-anchor bookkeeping emitted during refresh planning.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfileDriftAnchor {
    /// Anchor state: `keep`, `revert`, or `tune`.
    #[schema(example = "keep")]
    state: String,
    /// Source revision this anchor applies to.
    #[serde(rename = "sourceRevisionRef")]
    #[schema(example = "cccccccccccccccccccccccccccccccc")]
    source_revision_ref: String,
}

/// Next action metadata for missing or stale profile states.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfileNextAction {
    /// Action code the caller should take.
    #[schema(example = "refresh")]
    kind: String,
    /// Why the action is recommended.
    #[schema(example = "source_revision_mismatch")]
    reason: String,
    /// Source revisions to use for the next refresh when known.
    #[serde(rename = "sourceRevisionIds")]
    #[schema(example = json!(["dddddddddddddddddddddddddddddddd"]))]
    source_revision_ids: Option<Vec<String>>,
    /// Drift anchors to carry into refresh bookkeeping.
    drift_anchors: Vec<CompanionProfileDriftAnchor>,
}

/// Request body for refresh planning over a persisted PsychProfile.
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[schema(example = json!({
    "sourceRevisionIds": ["cccccccccccccccccccccccccccccccc"]
}))]
pub(crate) struct CompanionProfileRefreshRequest {
    /// Currently selected source revisions for the next profile refresh.
    #[serde(rename = "sourceRevisionIds", alias = "source_revision_ids")]
    source_revision_ids: Option<Vec<String>>,
}

/// Companion profile access response.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionProfileResponse {
    /// Persona/profile entity id.
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: String,
    /// Person scope for this profile.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: String,
    /// Grant evidence for the access decision.
    access: CompanionProfileAccess,
    /// Typed profile state: `missing`, `fresh`, or `stale`.
    #[schema(example = "fresh")]
    state: String,
    /// Profile payload when a persisted PsychProfile exists.
    #[schema(inline)]
    profile: Option<CompanionProfilePayload>,
    /// Typed stale reason when `state = stale`.
    #[schema(inline)]
    stale_reason: Option<CompanionProfileStaleReasonPayload>,
    /// Next action metadata for missing/stale profiles.
    #[schema(inline)]
    next_action: Option<CompanionProfileNextAction>,
    /// Drift-anchor events derived from persisted and selected source revisions.
    drift_anchors: Vec<CompanionProfileDriftAnchor>,
}

/// Scope boundary for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "personal",
    "person_ref": "11111111111111111111111111111111"
}))]
pub(crate) struct CompanionRegisterScopePayload {
    /// Scope discriminator: `neutral`, `personal`, or `shared_vault`.
    #[schema(example = "personal")]
    kind: String,
    /// Person scope for `personal` records.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: Option<String>,
    /// Shared-vault id for `shared_vault` records.
    #[schema(example = 7)]
    vault_id: Option<u64>,
}

/// Relationship subject reference for companion register records.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "source_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "target_ref": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}))]
pub(crate) struct CompanionRegisterRelationshipRefPayload {
    /// Source entity in the companion relationship.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    source_ref: String,
    /// Target entity in the companion relationship.
    #[schema(example = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    target_ref: String,
}

/// Persona or relationship subject for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "persona",
    "persona_ref": "22222222222222222222222222222222"
}))]
pub(crate) struct CompanionRegisterSubjectPayload {
    /// Subject discriminator: `persona` or `relationship`.
    #[schema(example = "persona")]
    kind: String,
    /// Persona entity for `persona` records.
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: Option<String>,
    /// Source/target pair for `relationship` records.
    relationship_ref: Option<CompanionRegisterRelationshipRefPayload>,
}

/// Provenance stamp for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "actor_class": 1,
    "source": "user_stated",
    "approval": "approved",
    "value": { "source": "settings" }
}))]
pub(crate) struct CompanionRegisterProvenancePayload {
    /// Actor entity responsible for the write.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    actor_ref: String,
    /// Actor class: 0 human, 1 agent, 2 system.
    #[schema(example = 1)]
    actor_class: u8,
    /// Provenance source.
    #[schema(example = "user_stated")]
    source: String,
    /// Approval status for this write.
    #[schema(example = "approved")]
    approval: String,
    /// Opaque provenance payload.
    value: Value,
}

/// Typed companion register record envelope.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "persona",
    "scope": { "kind": "personal", "person_ref": "11111111111111111111111111111111" },
    "subject": { "kind": "persona", "persona_ref": "22222222222222222222222222222222" },
    "value": { "note": "private relationship tuning" },
    "provenance": {
        "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "actor_class": 1,
        "source": "user_stated",
        "approval": "approved",
        "value": { "source": "settings" }
    },
    "lifecycle": "active",
    "export": "local_only"
}))]
pub(crate) struct CompanionRegisterRecordPayload {
    /// Record discriminator: `persona` or `relationship`.
    #[schema(example = "persona")]
    kind: String,
    /// Visibility/privacy scope.
    scope: CompanionRegisterScopePayload,
    /// Persona or relationship subject.
    subject: CompanionRegisterSubjectPayload,
    /// Opaque companion tuning/private note payload.
    value: Value,
    /// Provenance stamp for this record.
    provenance: CompanionRegisterProvenancePayload,
    /// Lifecycle status. Defaults to `active` on create/update when omitted.
    #[schema(example = "active")]
    lifecycle: Option<String>,
    /// Export classification: `local_only`, `portable`, or `shared_vault`.
    #[serde(rename = "export")]
    #[schema(example = "local_only")]
    export_classification: String,
}

/// Create companion register record request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "33333333333333333333333333333333",
    "learned_at": 1700000000,
    "record": {
        "kind": "persona",
        "scope": { "kind": "neutral" },
        "subject": { "kind": "persona", "persona_ref": "22222222222222222222222222222222" },
        "value": { "style": "warm" },
        "provenance": {
            "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "actor_class": 1,
            "source": "user_stated",
            "approval": "approved",
            "value": { "source": "settings" }
        },
        "export": "portable"
    }
}))]
pub(crate) struct CompanionRegisterCreateRecordRequest {
    /// Optional companion record entity id. Defaults to a new UUIDv7 entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: Option<String>,
    /// Write timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000000)]
    learned_at: Option<u64>,
    /// Typed companion record envelope.
    record: CompanionRegisterRecordPayload,
}

/// Update companion register record request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "learned_at": 1700000300,
    "record": {
        "kind": "persona",
        "scope": { "kind": "personal", "person_ref": "11111111111111111111111111111111" },
        "subject": { "kind": "persona", "persona_ref": "22222222222222222222222222222222" },
        "value": { "note": "updated private tuning" },
        "provenance": {
            "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "actor_class": 1,
            "source": "user_stated",
            "approval": "approved",
            "value": { "source": "settings" }
        },
        "export": "local_only"
    }
}))]
pub(crate) struct CompanionRegisterUpdateRecordRequest {
    /// Write timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000300)]
    learned_at: Option<u64>,
    /// Replacement record envelope. Scope and subject must match the existing record.
    record: CompanionRegisterRecordPayload,
}

/// Retire companion register record request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "retired_at": 1700000600 }))]
pub(crate) struct CompanionRegisterRetireRecordRequest {
    /// Retirement timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000600)]
    retired_at: Option<u64>,
}

/// End companion relationship request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "ended_at": 1700000600,
    "ended_badly": false,
    "run_id": "eiri-goodbye-artifact-1700000600"
}))]
pub(crate) struct CompanionEndRelationshipRequest {
    /// Ending timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000600)]
    ended_at: Option<u64>,
    /// When true, teardown skips the goodbye-artifact generation hook.
    #[serde(default)]
    #[schema(example = false)]
    ended_badly: bool,
    /// Optional run id stamped onto the goodbye-artifact task.
    #[schema(example = "eiri-goodbye-artifact-1700000600")]
    run_id: Option<String>,
}

/// Goodbye-artifact hook status returned by relationship teardown.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionGoodbyeArtifactHookPayload {
    /// Hook state: `enqueued`, `existing`, `skipped_bad_end`, or `skipped`.
    #[schema(example = "enqueued")]
    status: String,
    /// Companion task kind for the goodbye-artifact hook.
    #[schema(example = "goodbye_artifact")]
    task: String,
    /// Durable job id when the hook enqueued or found an existing task.
    #[schema(example = "018f0000000000000000000000000000")]
    job_id: Option<String>,
    /// Optional run id stamped onto the durable job row.
    #[schema(example = "eiri-goodbye-artifact-1700000600")]
    run_id: Option<String>,
}

/// End companion relationship response envelope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionEndRelationshipResponse {
    /// Companion register entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: String,
    /// Scrubbed and retired companion relationship record.
    record: CompanionRegisterRecordPayload,
    /// Goodbye-artifact hook status.
    goodbye_artifact: CompanionGoodbyeArtifactHookPayload,
}

/// Companion register response envelope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionRegisterRecordResponse {
    /// Companion register entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: String,
    /// Typed companion register record.
    record: CompanionRegisterRecordPayload,
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

/// Read a companion profile when an active matching AccessGrant exists.
#[utoipa::path(
    get,
    path = "/v1/companion/profiles/{persona_ref}",
    params(
        ("persona_ref" = String, Path, description = "Persona/profile entity id."),
        CompanionProfileQuery
    ),
    responses(
        (status = 200, description = "Companion profile access authorized.", body = CompanionProfileResponse, content_type = "application/json"),
        (status = 400, description = "Malformed profile request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "No active AccessGrant authorizes this profile.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion profile state lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_companion_profile(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(persona_ref): Path<String>,
    query: Result<Query<CompanionProfileQuery>, QueryRejection>,
) -> Result<Json<CompanionProfileResponse>, EnvelopedApiError> {
    require_companion_profile_read(&auth)?;
    let params = query_params(query)?;
    let persona_ref = parse_entity_id_param(&persona_ref, "persona_ref")?;
    let selected_source_revision_ids =
        parse_source_revision_ids_query(params.source_revision_ids.as_deref())?;
    let requested_principal_ref = params
        .principal_ref
        .as_deref()
        .map(|principal_ref| parse_entity_id_param(principal_ref, "principal_ref"))
        .transpose()?;
    let principal_ref = companion_profile_principal_ref(&auth, requested_principal_ref)?;
    let person_ref = parse_entity_id_param(&params.person_ref, "person_ref")?;

    let access = companion_profile_access(&server, &principal_ref, &person_ref, &persona_ref)?;
    let state = companion_profile_response_state(
        &server,
        &persona_ref,
        &person_ref,
        access,
        selected_source_revision_ids.as_deref(),
    )?;
    Ok(Json(state))
}

/// Plan a companion profile refresh while preserving persisted sourceRevisionIds.
#[utoipa::path(
    post,
    path = "/v1/companion/profiles/{persona_ref}",
    params(
        ("persona_ref" = String, Path, description = "Persona/profile entity id."),
        CompanionProfileQuery
    ),
    request_body(content = CompanionProfileRefreshRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion profile refresh state.", body = CompanionProfileResponse, content_type = "application/json"),
        (status = 400, description = "Malformed profile refresh request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "No active AccessGrant authorizes this profile.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion profile refresh lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn refresh_companion_profile(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(persona_ref): Path<String>,
    query: Result<Query<CompanionProfileQuery>, QueryRejection>,
    headers: HeaderMap,
    payload: Result<Bytes, BytesRejection>,
) -> Result<Json<CompanionProfileResponse>, EnvelopedApiError> {
    require_companion_profile_read(&auth)?;
    let params = query_params(query)?;
    let req = optional_companion_profile_refresh_request(&headers, payload)?;
    let persona_ref = parse_entity_id_param(&persona_ref, "persona_ref")?;
    let query_source_revision_ids =
        parse_source_revision_ids_query(params.source_revision_ids.as_deref())?;
    let body_source_revision_ids = parse_source_revision_ids_body(req.source_revision_ids)?;
    let selected_source_revision_ids =
        select_refresh_source_revision_ids(body_source_revision_ids, query_source_revision_ids)?;
    let requested_principal_ref = params
        .principal_ref
        .as_deref()
        .map(|principal_ref| parse_entity_id_param(principal_ref, "principal_ref"))
        .transpose()?;
    let principal_ref = companion_profile_principal_ref(&auth, requested_principal_ref)?;
    let person_ref = parse_entity_id_param(&params.person_ref, "person_ref")?;

    let access = companion_profile_access(&server, &principal_ref, &person_ref, &persona_ref)?;
    let state = companion_profile_response_state(
        &server,
        &persona_ref,
        &person_ref,
        access,
        selected_source_revision_ids.as_deref(),
    )?;
    Ok(Json(state))
}

pub(crate) fn companion_profile_access(
    server: &SyncServer,
    principal_ref: &oneiron::EntityId,
    person_ref: &oneiron::EntityId,
    persona_ref: &oneiron::EntityId,
) -> Result<CompanionProfileAccess, EnvelopedApiError> {
    let grant_id = server
        .vault
        .companion_profile_access_grant(principal_ref, person_ref, persona_ref)
        .map_err(|error| {
            tracing::error!(
                error = %error,
                principal_ref = %principal_ref.to_hex(),
                person_ref = %person_ref.to_hex(),
                persona_ref = %persona_ref.to_hex(),
                "companion profile grant lookup failed"
            );
            companion_engine_error("companion profile grant lookup failed", error)
        })?
        .ok_or_else(companion_access_denied)?;

    let scope = companion_scope_response(person_ref, persona_ref);
    Ok(CompanionProfileAccess {
        grant_id: grant_id.to_hex(),
        principal_ref: principal_ref.to_hex(),
        scope,
    })
}

pub(crate) fn companion_profile_response_state(
    server: &SyncServer,
    persona_ref: &oneiron::EntityId,
    person_ref: &oneiron::EntityId,
    access: CompanionProfileAccess,
    selected_source_revision_ids: Option<&[oneiron::EntityId]>,
) -> Result<CompanionProfileResponse, EnvelopedApiError> {
    let state = match server
        .vault
        .psych_profile_state(persona_ref, selected_source_revision_ids)
    {
        Ok(state) => state,
        Err(error) if error.kind() == ErrorKind::InvalidEntityType => {
            oneiron::PsychProfileState::Missing
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                persona_ref = %persona_ref.to_hex(),
                "psych profile lookup failed"
            );
            return Err(companion_engine_error("psych profile lookup failed", error));
        }
    };

    let selected_hex = selected_source_revision_ids.map(entity_ids_hex);
    let response = match state {
        oneiron::PsychProfileState::Missing => {
            let drift_anchors = selected_source_revision_ids
                .map(|selected| companion_profile_drift_anchors(&[], selected))
                .unwrap_or_default();
            let next_action = Some(CompanionProfileNextAction {
                kind: "refresh".to_owned(),
                reason: "missing".to_owned(),
                source_revision_ids: selected_hex,
                drift_anchors: drift_anchors.clone(),
            });
            CompanionProfileResponse {
                persona_ref: persona_ref.to_hex(),
                person_ref: person_ref.to_hex(),
                access,
                state: "missing".to_owned(),
                profile: None,
                stale_reason: None,
                next_action,
                drift_anchors,
            }
        }
        oneiron::PsychProfileState::Fresh(profile) => {
            let drift_anchors = selected_source_revision_ids
                .map(|selected| {
                    companion_profile_drift_anchors(&profile.source_revision_ids, selected)
                })
                .unwrap_or_default();
            CompanionProfileResponse {
                persona_ref: persona_ref.to_hex(),
                person_ref: person_ref.to_hex(),
                access,
                state: "fresh".to_owned(),
                profile: Some(companion_profile_payload(&profile)),
                stale_reason: None,
                next_action: None,
                drift_anchors,
            }
        }
        oneiron::PsychProfileState::Stale { profile, reason } => {
            let stale_reason = companion_profile_stale_reason(&reason);
            let action_source_revision_ids = stale_reason
                .expected_source_revision_ids
                .clone()
                .or_else(|| selected_hex.clone())
                .or_else(|| Some(entity_ids_hex(&profile.source_revision_ids)));
            let drift_anchors = companion_profile_drift_anchors(
                &profile.source_revision_ids,
                selected_source_revision_ids.unwrap_or(&profile.source_revision_ids),
            );
            let next_action = Some(CompanionProfileNextAction {
                kind: "refresh".to_owned(),
                reason: stale_reason.kind.clone(),
                source_revision_ids: action_source_revision_ids,
                drift_anchors: drift_anchors.clone(),
            });
            CompanionProfileResponse {
                persona_ref: persona_ref.to_hex(),
                person_ref: person_ref.to_hex(),
                access,
                state: "stale".to_owned(),
                profile: Some(companion_profile_payload(&profile)),
                stale_reason: Some(stale_reason),
                next_action,
                drift_anchors,
            }
        }
    };
    Ok(response)
}

pub(crate) fn companion_profile_payload(
    profile: &oneiron::PsychProfile,
) -> CompanionProfilePayload {
    CompanionProfilePayload {
        subject_ref: profile.subject_ref.to_hex(),
        compact: profile.compact.clone(),
        text: profile.text.clone(),
        narrative: profile.narrative.clone(),
        source_revision_ids: entity_ids_hex(&profile.source_revision_ids),
        confidence: CompanionProfileConfidencePayload {
            compact: profile.confidence.compact,
            text: profile.confidence.text,
            narrative: profile.confidence.narrative,
        },
        status: match profile.status {
            oneiron::PsychProfileSnapshotStatus::Fresh => "fresh",
            oneiron::PsychProfileSnapshotStatus::Stale => "stale",
        }
        .to_owned(),
    }
}

pub(crate) fn companion_profile_stale_reason(
    reason: &oneiron::PsychProfileStaleReason,
) -> CompanionProfileStaleReasonPayload {
    match reason {
        oneiron::PsychProfileStaleReason::MarkedStale => CompanionProfileStaleReasonPayload {
            kind: "marked_stale".to_owned(),
            expected_source_revision_ids: None,
            actual_source_revision_ids: None,
        },
        oneiron::PsychProfileStaleReason::SourceRevisionMismatch { expected, actual } => {
            CompanionProfileStaleReasonPayload {
                kind: "source_revision_mismatch".to_owned(),
                expected_source_revision_ids: Some(entity_ids_hex(expected)),
                actual_source_revision_ids: Some(entity_ids_hex(actual)),
            }
        }
    }
}

pub(crate) fn companion_profile_drift_anchors(
    previous_source_revision_ids: &[oneiron::EntityId],
    selected_source_revision_ids: &[oneiron::EntityId],
) -> Vec<CompanionProfileDriftAnchor> {
    oneiron::psych_profile::psych_mirror_drift_anchor_events(
        previous_source_revision_ids,
        selected_source_revision_ids,
    )
    .into_iter()
    .map(|event| CompanionProfileDriftAnchor {
        state: event.state.as_str().to_owned(),
        source_revision_ref: event.source_revision_ref.to_hex(),
    })
    .collect()
}

pub(crate) fn parse_source_revision_ids_query(
    raw: Option<&str>,
) -> Result<Option<Vec<oneiron::EntityId>>, ApiError> {
    raw.map(|value| parse_source_revision_ids(value.split(',')))
        .transpose()
        .map(|ids| ids.and_then(non_empty_source_revision_ids))
}

pub(crate) fn parse_source_revision_ids_body(
    raw: Option<Vec<String>>,
) -> Result<Option<Vec<oneiron::EntityId>>, ApiError> {
    raw.map(|values| parse_source_revision_ids(values.iter().map(String::as_str)))
        .transpose()
        .map(|ids| ids.and_then(non_empty_source_revision_ids))
}

pub(crate) fn parse_source_revision_ids<T>(
    values: impl IntoIterator<Item = T>,
) -> Result<Vec<oneiron::EntityId>, ApiError>
where
    T: AsRef<str>,
{
    let mut ids = Vec::new();
    for value in values {
        let value = value.as_ref().trim();
        if value.is_empty() {
            continue;
        }
        let id = parse_entity_id_param(value, "sourceRevisionIds")?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

pub(crate) fn entity_ids_hex(ids: &[oneiron::EntityId]) -> Vec<String> {
    ids.iter().map(oneiron::EntityId::to_hex).collect()
}

pub(crate) fn non_empty_source_revision_ids(
    ids: Vec<oneiron::EntityId>,
) -> Option<Vec<oneiron::EntityId>> {
    (!ids.is_empty()).then_some(ids)
}

pub(crate) fn select_refresh_source_revision_ids(
    body_source_revision_ids: Option<Vec<oneiron::EntityId>>,
    query_source_revision_ids: Option<Vec<oneiron::EntityId>>,
) -> Result<Option<Vec<oneiron::EntityId>>, ApiError> {
    match (body_source_revision_ids, query_source_revision_ids) {
        (Some(body), Some(query)) if !same_source_revision_selection(&body, &query) => {
            Err(ApiError::bad_request(
                "sourceRevisionIds query and body values must match when both are provided",
                Some("sourceRevisionIds"),
            ))
        }
        (Some(body), _) => Ok(Some(body)),
        (None, query) => Ok(query),
    }
}

pub(crate) fn same_source_revision_selection(
    left: &[oneiron::EntityId],
    right: &[oneiron::EntityId],
) -> bool {
    let mut left = entity_ids_hex(left);
    let mut right = entity_ids_hex(right);
    left.sort_unstable();
    left.dedup();
    right.sort_unstable();
    right.dedup();
    left == right
}

pub(crate) fn require_companion_profile_read(auth: &CoreAuth) -> Result<(), ApiError> {
    if auth.has_scope(CoreScope::CompanionProfileRead) || auth.has_scope(CoreScope::Read) {
        Ok(())
    } else {
        Err(ApiError::forbidden_scope(
            CoreScope::CompanionProfileRead.as_str(),
        ))
    }
}

pub(crate) fn require_companion_access_grant_write(auth: &CoreAuth) -> Result<(), ApiError> {
    if auth.has_scope(CoreScope::CompanionAccessGrantWrite) || auth.has_scope(CoreScope::Auth) {
        Ok(())
    } else {
        Err(ApiError::forbidden_scope(
            CoreScope::CompanionAccessGrantWrite.as_str(),
        ))
    }
}

pub(crate) fn require_companion_access_grant_write_for_principal(
    auth: &CoreAuth,
    principal_ref: &oneiron::EntityId,
) -> Result<(), ApiError> {
    require_companion_access_grant_write(auth)?;
    if auth.has_scope(CoreScope::Auth) {
        return Ok(());
    }
    match auth_bound_principal_ref(auth)? {
        Some(bound) if bound == *principal_ref => Ok(()),
        _ => Err(ApiError::forbidden_scope(CoreScope::Auth.as_str())),
    }
}

pub(crate) fn auth_bound_principal_ref(
    auth: &CoreAuth,
) -> Result<Option<oneiron::EntityId>, ApiError> {
    auth.principal_ref()
        .map(|principal_ref| parse_entity_id_param(principal_ref, "principal_ref"))
        .transpose()
}

pub(crate) fn companion_profile_principal_ref(
    auth: &CoreAuth,
    requested: Option<oneiron::EntityId>,
) -> Result<oneiron::EntityId, ApiError> {
    let bound = auth_bound_principal_ref(auth)?;

    match (requested, bound) {
        (Some(requested), Some(bound)) if requested == bound => Ok(requested),
        (Some(requested), _) => {
            auth.require(CoreScope::Auth)?;
            Ok(requested)
        }
        (None, Some(bound)) => Ok(bound),
        (None, None) => Err(ApiError::bad_request(
            "principal_ref is required unless bearer auth binds principal_ref",
            Some("principal_ref"),
        )),
    }
}

/// Create a typed companion register record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records",
    request_body(content = CompanionRegisterCreateRecordRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion register record created.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:register:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "Companion register id or key already exists.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn create_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CompanionRegisterCreateRecordRequest>, JsonRejection>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let req = json_payload(payload)?;
    let id = parse_optional_entity_id(req.id.as_deref(), "id")?;
    let learned_at = req.learned_at.unwrap_or_else(unix_seconds_now);
    let record = companion_register_record_from_payload(&req.record)?;

    server
        .vault
        .create_companion_record(&id, &record, learned_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register create failed");
            companion_register_engine_error("companion register create failed", error)
        })?;

    Ok(Json(companion_register_record_response(&id, &record)))
}

/// Read a typed companion register record.
#[utoipa::path(
    get,
    path = "/v1/companion/register/records/{record_id}",
    params(("record_id" = String, Path, description = "Companion register entity id.")),
    responses(
        (status = 200, description = "Companion register record read.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:register:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion register record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterRead)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let record = server
        .vault
        .get_companion_record(&id)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register read failed");
            companion_register_engine_error("companion register read failed", error)
        })?
        .ok_or_else(|| ApiError::not_found("companion_record", None))?;

    Ok(Json(companion_register_record_response(&id, &record)))
}

/// Update a typed companion register record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records/{record_id}",
    params(("record_id" = String, Path, description = "Companion register entity id.")),
    request_body(content = CompanionRegisterUpdateRecordRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion register record updated.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:register:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion register record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register update failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn update_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
    payload: Result<Json<CompanionRegisterUpdateRecordRequest>, JsonRejection>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let req = json_payload(payload)?;
    let learned_at = req.learned_at.unwrap_or_else(unix_seconds_now);
    let record = companion_register_record_from_payload(&req.record)?;

    let updated = server
        .vault
        .update_companion_record(&id, &record, learned_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register update failed");
            companion_register_engine_error("companion register update failed", error)
        })?;

    Ok(Json(companion_register_record_response(&id, &updated)))
}

/// Retire a typed companion register record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records/{record_id}/retire",
    params(("record_id" = String, Path, description = "Companion register entity id.")),
    request_body(content = CompanionRegisterRetireRecordRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion register record retired.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register id or request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:register:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion register record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register retire failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn retire_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
    payload: Result<Json<CompanionRegisterRetireRecordRequest>, JsonRejection>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let req = json_payload(payload)?;
    let retired_at = req.retired_at.unwrap_or_else(unix_seconds_now);

    let retired = server
        .vault
        .retire_companion_record(&id, retired_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register retire failed");
            companion_register_engine_error("companion register retire failed", error)
        })?;

    Ok(Json(companion_register_record_response(&id, &retired)))
}

/// End a typed companion relationship record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records/{record_id}/end-relationship",
    params(("record_id" = String, Path, description = "Companion relationship record entity id.")),
    request_body(content = CompanionEndRelationshipRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion relationship ended.", body = CompanionEndRelationshipResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion relationship end request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks companion:register:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion relationship record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion relationship end failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn end_companion_register_relationship(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
    payload: Result<Json<CompanionEndRelationshipRequest>, JsonRejection>,
) -> Result<Json<CompanionEndRelationshipResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let req = json_payload(payload)?;
    let ended_at = req.ended_at.unwrap_or_else(unix_seconds_now);
    let ended_badly = req.ended_badly;

    let outcome = server
        .vault
        .end_companion_relationship(
            &id,
            oneiron::EndCompanionRelationship {
                ended_at,
                ended_badly,
                run_id: req.run_id,
            },
        )
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion relationship end failed");
            companion_register_engine_error("companion relationship end failed", error)
        })?;

    Ok(Json(CompanionEndRelationshipResponse {
        id: id.to_hex(),
        record: companion_register_record_payload(&outcome.record),
        goodbye_artifact: companion_goodbye_artifact_hook_payload(
            outcome.goodbye_artifact,
            ended_badly,
            outcome.already_ended,
        ),
    }))
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

pub(crate) fn companion_register_record_from_payload(
    payload: &CompanionRegisterRecordPayload,
) -> Result<oneiron::CompanionRecord, ApiError> {
    let scope = companion_register_scope_from_payload(&payload.scope)?;
    let subject = companion_register_subject_from_payload(&payload.subject)?;
    let kind = companion_register_kind_from_wire(&payload.kind, "record.kind")?;
    if kind != subject.kind() {
        return Err(ApiError::bad_request(
            "record.kind must match subject.kind",
            Some("record.kind"),
        ));
    }
    let value = oneiron::companion_value_from_json(&payload.value)
        .map_err(|error| ApiError::bad_request(error.to_string(), Some("record.value")))?;
    let provenance = companion_register_provenance_from_payload(&payload.provenance)?;
    let lifecycle = payload
        .lifecycle
        .as_deref()
        .map(companion_register_lifecycle_from_wire)
        .transpose()?
        .unwrap_or(oneiron::ClaimLifecycleStatus::Active);
    if lifecycle != oneiron::ClaimLifecycleStatus::Active {
        return Err(ApiError::bad_request(
            "companion register create/update lifecycle must be active",
            Some("record.lifecycle"),
        ));
    }
    let export_classification =
        companion_register_export_from_wire(&payload.export_classification)?;
    validate_companion_register_scope_export(&scope, export_classification)?;

    Ok(oneiron::CompanionRecord::new(
        scope,
        subject,
        value,
        provenance,
        lifecycle,
        export_classification,
    ))
}

pub(crate) fn validate_companion_register_scope_export(
    scope: &oneiron::CompanionScope,
    export: oneiron::CompanionExportClassification,
) -> Result<(), ApiError> {
    match (scope, export) {
        (
            oneiron::CompanionScope::SharedVault { .. },
            oneiron::CompanionExportClassification::SharedVault,
        ) => Ok(()),
        (oneiron::CompanionScope::SharedVault { .. }, _) => Err(ApiError::bad_request(
            "shared_vault scope requires shared_vault export",
            Some("record.export"),
        )),
        (_, oneiron::CompanionExportClassification::SharedVault) => Err(ApiError::bad_request(
            "shared_vault export requires shared_vault scope",
            Some("record.export"),
        )),
        _ => Ok(()),
    }
}

pub(crate) fn companion_register_scope_from_payload(
    payload: &CompanionRegisterScopePayload,
) -> Result<oneiron::CompanionScope, ApiError> {
    match payload.kind.as_str() {
        "neutral" if payload.person_ref.is_none() && payload.vault_id.is_none() => {
            Ok(oneiron::CompanionScope::neutral())
        }
        "personal" if payload.vault_id.is_none() => {
            let Some(person_ref) = payload.person_ref.as_deref() else {
                return Err(ApiError::bad_request(
                    "personal scope requires person_ref",
                    Some("record.scope.person_ref"),
                ));
            };
            Ok(oneiron::CompanionScope::personal(parse_entity_id_param(
                person_ref,
                "record.scope.person_ref",
            )?))
        }
        "shared_vault" if payload.person_ref.is_none() => {
            let Some(vault_id) = payload.vault_id else {
                return Err(ApiError::bad_request(
                    "shared_vault scope requires vault_id",
                    Some("record.scope.vault_id"),
                ));
            };
            if vault_id == 0 {
                return Err(ApiError::bad_request(
                    "shared_vault scope requires nonzero vault_id",
                    Some("record.scope.vault_id"),
                ));
            }
            Ok(oneiron::CompanionScope::shared_vault(vault_id))
        }
        _ => Err(ApiError::bad_request(
            "scope shape must match scope.kind",
            Some("record.scope.kind"),
        )),
    }
}

pub(crate) fn companion_register_subject_from_payload(
    payload: &CompanionRegisterSubjectPayload,
) -> Result<oneiron::CompanionSubject, ApiError> {
    match payload.kind.as_str() {
        "persona" if payload.relationship_ref.is_none() => {
            let Some(persona_ref) = payload.persona_ref.as_deref() else {
                return Err(ApiError::bad_request(
                    "persona subject requires persona_ref",
                    Some("record.subject.persona_ref"),
                ));
            };
            Ok(oneiron::CompanionSubject::persona(parse_entity_id_param(
                persona_ref,
                "record.subject.persona_ref",
            )?))
        }
        "relationship" if payload.persona_ref.is_none() => {
            let Some(relationship_ref) = payload.relationship_ref.as_ref() else {
                return Err(ApiError::bad_request(
                    "relationship subject requires relationship_ref",
                    Some("record.subject.relationship_ref"),
                ));
            };
            Ok(oneiron::CompanionSubject::relationship(
                parse_entity_id_param(
                    &relationship_ref.source_ref,
                    "record.subject.relationship_ref.source_ref",
                )?,
                parse_entity_id_param(
                    &relationship_ref.target_ref,
                    "record.subject.relationship_ref.target_ref",
                )?,
            ))
        }
        _ => Err(ApiError::bad_request(
            "subject shape must match subject.kind",
            Some("record.subject.kind"),
        )),
    }
}

pub(crate) fn companion_register_provenance_from_payload(
    payload: &CompanionRegisterProvenancePayload,
) -> Result<oneiron::CompanionProvenance, ApiError> {
    let value = oneiron::companion_value_from_json(&payload.value).map_err(|error| {
        ApiError::bad_request(error.to_string(), Some("record.provenance.value"))
    })?;
    Ok(oneiron::CompanionProvenance::new(
        parse_entity_id_param(&payload.actor_ref, "record.provenance.actor_ref")?,
        companion_register_actor_class(payload.actor_class)?,
        companion_register_source_from_wire(&payload.source)?,
        companion_register_approval_from_wire(&payload.approval)?,
        value,
    ))
}

pub(crate) fn companion_register_record_response(
    id: &oneiron::EntityId,
    record: &oneiron::CompanionRecord,
) -> CompanionRegisterRecordResponse {
    CompanionRegisterRecordResponse {
        id: id.to_hex(),
        record: companion_register_record_payload(record),
    }
}

pub(crate) fn companion_goodbye_artifact_hook_payload(
    outcome: Option<oneiron::EnqueueCompanionTaskOutcome>,
    ended_badly: bool,
    already_ended: bool,
) -> CompanionGoodbyeArtifactHookPayload {
    let skipped = |status: &'static str| CompanionGoodbyeArtifactHookPayload {
        status: status.to_owned(),
        task: oneiron::CompanionTaskKind::GoodbyeArtifact
            .as_str()
            .to_owned(),
        job_id: None,
        run_id: None,
    };

    let Some(outcome) = outcome else {
        return if already_ended {
            skipped("already_ended")
        } else if ended_badly {
            skipped("skipped_bad_end")
        } else {
            skipped("skipped")
        };
    };

    let (status, task_status) = match outcome {
        oneiron::EnqueueCompanionTaskOutcome::Enqueued(status) => ("enqueued", status),
        oneiron::EnqueueCompanionTaskOutcome::Existing(status) => ("existing", status),
        _ => return skipped("unknown"),
    };
    CompanionGoodbyeArtifactHookPayload {
        status: status.to_owned(),
        task: task_status.task.kind.as_str().to_owned(),
        job_id: Some(hex_bytes(task_status.job.id.as_bytes())),
        run_id: task_status.job.run_id,
    }
}

pub(crate) fn companion_register_record_payload(
    record: &oneiron::CompanionRecord,
) -> CompanionRegisterRecordPayload {
    CompanionRegisterRecordPayload {
        kind: record.kind().as_str().to_owned(),
        scope: companion_register_scope_payload(&record.scope),
        subject: companion_register_subject_payload(&record.subject),
        value: oneiron::companion_value_to_json(&record.value),
        provenance: CompanionRegisterProvenancePayload {
            actor_ref: record.provenance.actor_ref.to_hex(),
            actor_class: record.provenance.actor_class as u8,
            source: record.provenance.source.as_str().to_owned(),
            approval: record.provenance.approval.as_str().to_owned(),
            value: oneiron::companion_value_to_json(&record.provenance.value),
        },
        lifecycle: Some(record.lifecycle.as_str().to_owned()),
        export_classification: record.export_classification.as_str().to_owned(),
    }
}

pub(crate) fn companion_register_scope_payload(
    scope: &oneiron::CompanionScope,
) -> CompanionRegisterScopePayload {
    match scope {
        oneiron::CompanionScope::Neutral => CompanionRegisterScopePayload {
            kind: "neutral".to_owned(),
            person_ref: None,
            vault_id: None,
        },
        oneiron::CompanionScope::Personal { person_ref } => CompanionRegisterScopePayload {
            kind: "personal".to_owned(),
            person_ref: Some(person_ref.to_hex()),
            vault_id: None,
        },
        oneiron::CompanionScope::SharedVault { vault_id } => CompanionRegisterScopePayload {
            kind: "shared_vault".to_owned(),
            person_ref: None,
            vault_id: Some(*vault_id),
        },
        _ => {
            tracing::warn!("unknown companion register scope variant in API response");
            CompanionRegisterScopePayload {
                kind: "unknown".to_owned(),
                person_ref: None,
                vault_id: None,
            }
        }
    }
}

pub(crate) fn companion_register_subject_payload(
    subject: &oneiron::CompanionSubject,
) -> CompanionRegisterSubjectPayload {
    match subject {
        oneiron::CompanionSubject::Persona { persona_ref } => CompanionRegisterSubjectPayload {
            kind: "persona".to_owned(),
            persona_ref: Some(persona_ref.to_hex()),
            relationship_ref: None,
        },
        oneiron::CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => CompanionRegisterSubjectPayload {
            kind: "relationship".to_owned(),
            persona_ref: None,
            relationship_ref: Some(CompanionRegisterRelationshipRefPayload {
                source_ref: source_ref.to_hex(),
                target_ref: target_ref.to_hex(),
            }),
        },
        _ => {
            tracing::warn!("unknown companion register subject variant in API response");
            CompanionRegisterSubjectPayload {
                kind: "unknown".to_owned(),
                persona_ref: None,
                relationship_ref: None,
            }
        }
    }
}

pub(crate) fn companion_register_kind_from_wire(
    value: &str,
    field: &'static str,
) -> Result<oneiron::CompanionRecordKind, ApiError> {
    match value {
        "persona" => Ok(oneiron::CompanionRecordKind::Persona),
        "relationship" => Ok(oneiron::CompanionRecordKind::Relationship),
        _ => Err(ApiError::bad_request(
            "kind must be persona or relationship",
            Some(field),
        )),
    }
}

pub(crate) fn companion_register_lifecycle_from_wire(
    value: &str,
) -> Result<oneiron::ClaimLifecycleStatus, ApiError> {
    match value {
        "active" => Ok(oneiron::ClaimLifecycleStatus::Active),
        "superseded" => Ok(oneiron::ClaimLifecycleStatus::Superseded),
        "retracted" => Ok(oneiron::ClaimLifecycleStatus::Retracted),
        _ => Err(ApiError::bad_request(
            "lifecycle must be active, superseded, or retracted",
            Some("record.lifecycle"),
        )),
    }
}

pub(crate) fn companion_register_export_from_wire(
    value: &str,
) -> Result<oneiron::CompanionExportClassification, ApiError> {
    match value {
        "local_only" => Ok(oneiron::CompanionExportClassification::LocalOnly),
        "portable" => Ok(oneiron::CompanionExportClassification::Portable),
        "shared_vault" => Ok(oneiron::CompanionExportClassification::SharedVault),
        _ => Err(ApiError::bad_request(
            "export must be local_only, portable, or shared_vault",
            Some("record.export"),
        )),
    }
}

pub(crate) fn companion_register_actor_class(
    value: u8,
) -> Result<oneiron::EdgeActorClass, ApiError> {
    match value {
        0 => Ok(oneiron::EdgeActorClass::Human),
        1 => Ok(oneiron::EdgeActorClass::Agent),
        2 => Ok(oneiron::EdgeActorClass::System),
        _ => Err(ApiError::bad_request(
            "actor_class must be 0, 1, or 2",
            Some("record.provenance.actor_class"),
        )),
    }
}

pub(crate) fn companion_register_source_from_wire(
    value: &str,
) -> Result<oneiron::ClaimSource, ApiError> {
    match value {
        "user_stated" => Ok(oneiron::ClaimSource::UserStated),
        "observed" => Ok(oneiron::ClaimSource::Observed),
        "inferred" => Ok(oneiron::ClaimSource::Inferred),
        "imported" => Ok(oneiron::ClaimSource::Imported),
        "tool_output" => Ok(oneiron::ClaimSource::ToolOutput),
        "generated" => Ok(oneiron::ClaimSource::Generated),
        _ => Err(ApiError::bad_request(
            "source is not recognized",
            Some("record.provenance.source"),
        )),
    }
}

pub(crate) fn companion_register_approval_from_wire(
    value: &str,
) -> Result<oneiron::ClaimApprovalStatus, ApiError> {
    match value {
        "auto" => Ok(oneiron::ClaimApprovalStatus::Auto),
        "proposed" => Ok(oneiron::ClaimApprovalStatus::Proposed),
        "approved" => Ok(oneiron::ClaimApprovalStatus::Approved),
        "rejected" => Ok(oneiron::ClaimApprovalStatus::Rejected),
        _ => Err(ApiError::bad_request(
            "approval is not recognized",
            Some("record.provenance.approval"),
        )),
    }
}

pub(crate) fn companion_access_denied() -> EnvelopedApiError {
    ApiError::new(
        "companion profile access is not granted",
        ApiErrorDetails::Forbidden {
            required_scope: Some("companion_profile.read".to_owned()),
        },
        ["Create an active AccessGrant for this principal and profile before retrying."],
    )
    .into()
}

pub(crate) fn companion_create_error(error: oneiron::Error) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::AccessGrantAlreadyExists => {
            ApiError::invalid_state(Some("access_grant_exists")).into()
        }
        _ => companion_engine_error("companion access grant create failed", error),
    }
}

pub(crate) fn companion_register_engine_error(
    message: &'static str,
    error: oneiron::Error,
) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::CompanionRecordAlreadyExists => {
            ApiError::invalid_state(Some("companion_record_exists")).into()
        }
        ErrorKind::EntityNotFound => ApiError::not_found("companion_record", None).into(),
        ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange
        | ErrorKind::StructuralKindBandViolation
        | ErrorKind::StructuralKindCollision
        | ErrorKind::InvalidStructuralKindRegistration => {
            ApiError::bad_request(error.to_string(), None).into()
        }
        _ => ApiError::internal_server_error(message).into(),
    }
}

pub(crate) fn companion_engine_error(
    message: &'static str,
    error: oneiron::Error,
) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::InvalidKey
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange => ApiError::bad_request(error.to_string(), None).into(),
        ErrorKind::EntityNotFound => ApiError::not_found("access_grant", None).into(),
        _ => ApiError::internal_server_error(message).into(),
    }
}
