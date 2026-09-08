//! Companion profile routes, DTOs, and state builders.

use super::super::has_json_content_type;
use super::super::parse_entity_id_param;
use super::super::query_params;
use super::access_grants::CompanionAccessGrantScopePayload;
use super::access_grants::companion_scope_response;
use super::auth::companion_profile_principal_ref;
use super::auth::require_companion_profile_read;
use super::errors::companion_access_denied;
use super::errors::companion_engine_error;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::ErrorKind;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

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
