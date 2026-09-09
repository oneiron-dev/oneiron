//! Companion register record routes and DTOs.

use super::super::json_payload;
use super::super::parse_entity_id_param;
use super::super::parse_optional_entity_id;
use super::super::unix_seconds_now;
use super::errors::companion_register_engine_error;
use super::register_wire::CompanionEndRelationshipResponse;
use super::register_wire::CompanionRegisterRecordResponse;
use super::register_wire::companion_goodbye_artifact_hook_payload;
use super::register_wire::companion_register_actor_class;
use super::register_wire::companion_register_approval_from_wire;
use super::register_wire::companion_register_export_from_wire;
use super::register_wire::companion_register_kind_from_wire;
use super::register_wire::companion_register_lifecycle_from_wire;
use super::register_wire::companion_register_record_payload;
use super::register_wire::companion_register_record_response;
use super::register_wire::companion_register_source_from_wire;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
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
use serde_json::Value;
use std::sync::Arc;
use utoipa::ToSchema;

/// Scope boundary for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "personal",
    "person_ref": "11111111111111111111111111111111"
}))]
pub(crate) struct CompanionRegisterScopePayload {
    /// Scope discriminator: `neutral`, `personal`, or `shared_vault`.
    #[schema(example = "personal")]
    pub(super) kind: String,
    /// Person scope for `personal` records.
    #[schema(example = "11111111111111111111111111111111")]
    pub(super) person_ref: Option<String>,
    /// Shared-vault id for `shared_vault` records.
    #[schema(example = 7)]
    pub(super) vault_id: Option<u64>,
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
    pub(super) source_ref: String,
    /// Target entity in the companion relationship.
    #[schema(example = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    pub(super) target_ref: String,
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
    pub(super) kind: String,
    /// Persona entity for `persona` records.
    #[schema(example = "22222222222222222222222222222222")]
    pub(super) persona_ref: Option<String>,
    /// Source/target pair for `relationship` records.
    pub(super) relationship_ref: Option<CompanionRegisterRelationshipRefPayload>,
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
    pub(super) actor_ref: String,
    /// Actor class: 0 human, 1 agent, 2 system.
    #[schema(example = 1)]
    pub(super) actor_class: u8,
    /// Provenance source.
    #[schema(example = "user_stated")]
    pub(super) source: String,
    /// Approval status for this write.
    #[schema(example = "approved")]
    pub(super) approval: String,
    /// Opaque provenance payload.
    pub(super) value: Value,
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
    pub(super) kind: String,
    /// Visibility/privacy scope.
    pub(super) scope: CompanionRegisterScopePayload,
    /// Persona or relationship subject.
    pub(super) subject: CompanionRegisterSubjectPayload,
    /// Opaque companion tuning/private note payload.
    pub(super) value: Value,
    /// Provenance stamp for this record.
    pub(super) provenance: CompanionRegisterProvenancePayload,
    /// Lifecycle status. Defaults to `active` on create/update when omitted.
    #[schema(example = "active")]
    pub(super) lifecycle: Option<String>,
    /// Export classification: `local_only`, `portable`, or `shared_vault`.
    #[serde(rename = "export")]
    #[schema(example = "local_only")]
    pub(super) export_classification: String,
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
    "run_id": "companion-goodbye-artifact-1700000600"
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
    #[schema(example = "companion-goodbye-artifact-1700000600")]
    run_id: Option<String>,
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
