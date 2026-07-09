use super::CoreBatchEntityInput;
use super::CoreBatchEntityResult;
use super::CoreHydrateDeletionMetadata;
use super::ViewQuery;
use super::core_engine_error;
use super::core_entity_timestamps;
use super::core_hydrate_deletion_metadata;
use super::hex_bytes;
use super::json_payload;
use super::parse_entity_id_param;
use super::parse_optional_entity_id;
use super::query_params;
use super::scoped_read_for_core_auth;
use super::stage_core_entity_put;
use super::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use utoipa::ToSchema;

/// Supersession timeline response for one memory anchor.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreMemoryTimelineResponse {
    /// Requested anchor entity id.
    #[serde(rename = "anchor_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    anchor_id: String,
    /// Stable ordered timeline records, oldest bitemporal start first.
    records: Vec<CoreMemoryTimelineRecord>,
}

/// One renderer-ready record in a supersession timeline.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreMemoryTimelineRecord {
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Explicit lifecycle/deletion state for this timeline row.
    state: CoreMemoryTimelineRecordState,
    /// Numeric entity type byte when the record is still locally present.
    #[serde(skip_serializing_if = "Option::is_none", rename = "entity_type")]
    #[schema(example = 0)]
    entity_type: Option<u8>,
    /// Entity occurrence start timestamp.
    #[serde(skip_serializing_if = "Option::is_none", rename = "occurred_start")]
    #[schema(example = 1782357600_u64)]
    occurred_start: Option<u64>,
    /// Entity occurrence end timestamp.
    #[serde(skip_serializing_if = "Option::is_none", rename = "occurred_end")]
    #[schema(example = 1782357635_u64)]
    occurred_end: Option<u64>,
    /// Entity learned-at timestamp.
    #[serde(skip_serializing_if = "Option::is_none", rename = "learned_at")]
    #[schema(example = 1782357635_u64)]
    learned_at: Option<u64>,
    /// Stored body byte length for present records, including zero-byte live bodies.
    #[serde(skip_serializing_if = "Option::is_none", rename = "body_bytes")]
    #[schema(example = 48)]
    body_bytes: Option<usize>,
    /// Deletion metadata for deleted-shell rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<CoreHydrateDeletionMetadata>,
    /// Older records this record supersedes.
    supersedes: Vec<String>,
    /// Newer records that supersede this record.
    #[serde(rename = "superseded_by")]
    superseded_by: Vec<String>,
    /// Projected entity payload for non-deleted present records.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    item: Option<Value>,
}

/// Stable row state in a memory timeline.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreMemoryTimelineRecordState {
    Live,
    Superseded,
    Retracted,
    Deleted,
    Missing,
}

/// Payload for the named memory verb route.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "new_id": "22222222222222222222222222222222",
    "old_id": "11111111111111111111111111111111",
    "at": 1782357700_u64
}))]
pub(crate) struct CoreMemoryVerbRequest {
    /// Entity payload for the `remember` verb.
    #[serde(default)]
    entity: Option<CoreBatchEntityInput>,
    /// Target entity id for `retract`, `delete`, and `hard_delete`.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// New claim id for `supersede`.
    #[serde(default, rename = "new_id", alias = "newId")]
    #[schema(example = "22222222222222222222222222222222")]
    new_id: Option<String>,
    /// Old claim id for `supersede`.
    #[serde(default, rename = "old_id", alias = "oldId")]
    #[schema(example = "11111111111111111111111111111111")]
    old_id: Option<String>,
    /// Operation timestamp for supersede/retract verbs. Defaults to server time.
    /// Delete verbs reject this field because the vault owns deletion time.
    #[serde(default, alias = "now")]
    #[schema(example = 1782357700_u64)]
    at: Option<u64>,
    /// Delete reason override for delete verbs.
    #[serde(default)]
    reason: Option<CoreMemoryVerbDeleteReason>,
}

/// Named delete reason accepted by the memory verb route.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreMemoryVerbDeleteReason {
    #[serde(rename = "user_delete")]
    User,
    #[serde(rename = "user_hard_delete")]
    UserHard,
    #[serde(rename = "gdpr_delete")]
    Gdpr,
    #[serde(rename = "policy_delete")]
    Policy,
}

/// Named memory verb response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreMemoryVerbResponse {
    /// Canonical verb name selected after alias resolution.
    #[schema(example = "supersede")]
    verb: String,
    /// Typed operation family selected by the verb.
    operation: CoreMemoryOperationKind,
    /// Operation timestamp used by supersede/retract verbs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1782357700_u64)]
    at: Option<u64>,
    /// Target id for single-target verbs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// New claim id for supersession.
    #[serde(skip_serializing_if = "Option::is_none", rename = "new_id")]
    #[schema(example = "22222222222222222222222222222222")]
    new_id: Option<String>,
    /// Old claim id for supersession.
    #[serde(skip_serializing_if = "Option::is_none", rename = "old_id")]
    #[schema(example = "11111111111111111111111111111111")]
    old_id: Option<String>,
    /// Entity written by `remember`.
    #[serde(skip_serializing_if = "Option::is_none")]
    entity: Option<CoreBatchEntityResult>,
    /// Delete outcome for delete verbs.
    #[serde(skip_serializing_if = "Option::is_none")]
    delete: Option<CoreMemoryVerbDeleteOutcome>,
}

/// Delete operation result returned by named delete verbs.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreMemoryVerbDeleteOutcome {
    /// Whether the delete found active local state to erase.
    existed: bool,
    /// Reason applied by the delete operation.
    reason: CoreMemoryVerbDeleteReason,
    /// Whether the reason has hard-delete semantics.
    hard: bool,
    /// Redaction receipt entity id for hard-delete classes.
    #[serde(skip_serializing_if = "Option::is_none", rename = "receipt_id")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    receipt_id: Option<String>,
    /// Hex-encoded hard-erasure sweep key when one was queued.
    #[serde(skip_serializing_if = "Option::is_none", rename = "sweep_key")]
    #[schema(example = "686172646572617365")]
    sweep_key: Option<String>,
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreMemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

/// Return renderer-ready supersession timeline data for one memory record.
#[utoipa::path(
    get,
    path = "/v1/core/memory/{id}/timeline",
    params(
        (
            "id" = String,
            Path,
            description = "Hex entity id whose supersession chain should be rendered.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (status = 200, description = "Stable ordered memory supersession timeline.", body = CoreMemoryTimelineResponse, content_type = "application/json"),
        (status = 400, description = "Malformed entity id or view.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Anchor entity was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Timeline lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_memory_timeline(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Json<CoreMemoryTimelineResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&id_hex, "id")?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let timeline = scoped_read.memory_timeline(&id).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core memory timeline failed");
        core_engine_error("core memory timeline failed", error)
    })?;

    if timeline.records.is_empty()
        || (timeline.records.len() == 1
            && timeline.records[0].state == oneiron::MemoryTimelineRecordState::Missing)
    {
        return Err(ApiError::not_found("entity", Some(&id.to_hex())).into());
    }

    Ok(Json(core_memory_timeline_response(
        &server.vault,
        timeline,
        view,
    )?))
}

/// Execute a named memory verb after resolving it to a typed vault operation.
#[utoipa::path(
    post,
    path = "/v1/core/memory/verbs/{verb}",
    params(
        (
            "verb" = String,
            Path,
            description = "Named memory verb: remember, supersede, retract, delete/forget, or hard_delete/erase.",
            example = "supersede"
        )
    ),
    request_body(content = CoreMemoryVerbRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Named verb resolved and executed as a typed operation.", body = CoreMemoryVerbResponse, content_type = "application/json"),
        (status = 400, description = "Malformed verb request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Referenced entity was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Memory verb failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_memory_verb(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(verb_name): Path<String>,
    payload: Result<Json<CoreMemoryVerbRequest>, JsonRejection>,
) -> Result<Json<CoreMemoryVerbResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let verb = oneiron::NamedMemoryVerb::parse(&verb_name).ok_or_else(|| {
        ApiError::bad_request(
            "verb must be one of remember (put), supersede (replace/revise), retract (withdraw), delete (forget), hard_delete (erase/purge)",
            Some("verb"),
        )
    })?;
    let req = json_payload(payload)?;
    let operation = core_memory_operation_kind(verb.operation_kind());

    match verb {
        oneiron::NamedMemoryVerb::Remember => {
            let entity = req.entity.ok_or_else(|| {
                ApiError::bad_request("entity is required for remember", Some("entity"))
            })?;
            let id = parse_optional_entity_id(entity.id.as_deref(), "entity.id")?;
            let timestamps = core_entity_timestamps(
                entity.occurred_start,
                entity.occurred_end,
                entity.learned_at,
            )?;
            let batch = server.vault.batch();
            stage_core_entity_put(
                batch,
                &id,
                entity.entity_type,
                timestamps,
                &entity.body,
                entity.text.as_deref(),
            )?
            .commit()
            .map_err(|error| {
                tracing::error!(error = %error, id = %id.to_hex(), "core memory remember failed");
                core_engine_error("core memory remember failed", error)
            })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: None,
                id: Some(id.to_hex()),
                new_id: None,
                old_id: None,
                entity: Some(CoreBatchEntityResult {
                    id: id.to_hex(),
                    entity_type: entity.entity_type,
                }),
                delete: None,
            }))
        }
        oneiron::NamedMemoryVerb::Supersede => {
            let new_id = parse_required_entity_id(req.new_id.as_deref(), "new_id")?;
            let old_id = parse_required_entity_id(req.old_id.as_deref(), "old_id")?;
            let at = req.at.unwrap_or_else(unix_seconds_now);
            server
                .vault
                .supersede_claim(&new_id, &old_id, at)
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        new_id = %new_id.to_hex(),
                        old_id = %old_id.to_hex(),
                        "core memory supersede failed"
                    );
                    core_engine_error("core memory supersede failed", error)
                })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: Some(at),
                id: None,
                new_id: Some(new_id.to_hex()),
                old_id: Some(old_id.to_hex()),
                entity: None,
                delete: None,
            }))
        }
        oneiron::NamedMemoryVerb::Retract => {
            let id = parse_required_entity_id(req.id.as_deref(), "id")?;
            let at = req.at.unwrap_or_else(unix_seconds_now);
            server.vault.retract_claim(&id, at).map_err(|error| {
                tracing::error!(error = %error, id = %id.to_hex(), "core memory retract failed");
                core_engine_error("core memory retract failed", error)
            })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: Some(at),
                id: Some(id.to_hex()),
                new_id: None,
                old_id: None,
                entity: None,
                delete: None,
            }))
        }
        oneiron::NamedMemoryVerb::Delete | oneiron::NamedMemoryVerb::HardDelete => {
            if req.at.is_some() {
                return Err(ApiError::bad_request(
                    "at is not supported for delete verbs; deletion time is recorded by the vault",
                    Some("at"),
                )
                .into());
            }
            let id = parse_required_entity_id(req.id.as_deref(), "id")?;
            let (reason, response_reason) = core_memory_delete_reason(verb, req.reason)?;
            let outcome = server
                .vault
                .delete_entity_with_reason(&id, reason)
                .map_err(|error| {
                    tracing::error!(error = %error, id = %id.to_hex(), "core memory delete failed");
                    core_engine_error("core memory delete failed", error)
                })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: None,
                id: Some(id.to_hex()),
                new_id: None,
                old_id: None,
                entity: None,
                delete: Some(CoreMemoryVerbDeleteOutcome {
                    existed: outcome.existed,
                    reason: response_reason,
                    hard: matches!(
                        reason,
                        oneiron::DeleteReason::UserHardDelete
                            | oneiron::DeleteReason::GdprDelete
                            | oneiron::DeleteReason::PolicyDelete
                    ),
                    receipt_id: outcome.receipt_id.map(|id| id.to_hex()),
                    sweep_key: outcome.sweep_key.as_deref().map(hex_bytes),
                }),
            }))
        }
    }
}

pub(crate) fn core_memory_timeline_response(
    vault: &oneiron::Vault,
    timeline: oneiron::MemoryTimeline,
    view: View,
) -> Result<CoreMemoryTimelineResponse, ApiError> {
    let mut records = Vec::with_capacity(timeline.records.len());
    for record in timeline.records {
        let item = if matches!(
            record.state,
            oneiron::MemoryTimelineRecordState::Live
                | oneiron::MemoryTimelineRecordState::Superseded
                | oneiron::MemoryTimelineRecordState::Retracted
        ) {
            projection::project_entity(vault, &record.id, view).map_err(|error| {
                tracing::error!(error = %error, id = %record.id.to_hex(), "core memory timeline projection failed");
                core_engine_error("core memory timeline projection failed", error)
            })?
        } else {
            None
        };

        records.push(CoreMemoryTimelineRecord {
            id: record.id.to_hex(),
            state: core_memory_timeline_state(record.state),
            entity_type: record.entity_type,
            occurred_start: record.occurred_start,
            occurred_end: record.occurred_end,
            learned_at: record.learned_at,
            body_bytes: record.body_bytes,
            deletion: record.deletion.map(core_hydrate_deletion_metadata),
            supersedes: record
                .supersedes
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
            superseded_by: record
                .superseded_by
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
            item,
        });
    }

    Ok(CoreMemoryTimelineResponse {
        anchor_id: timeline.anchor.to_hex(),
        records,
    })
}

pub(crate) fn core_memory_timeline_state(
    state: oneiron::MemoryTimelineRecordState,
) -> CoreMemoryTimelineRecordState {
    match state {
        oneiron::MemoryTimelineRecordState::Live => CoreMemoryTimelineRecordState::Live,
        oneiron::MemoryTimelineRecordState::Superseded => CoreMemoryTimelineRecordState::Superseded,
        oneiron::MemoryTimelineRecordState::Retracted => CoreMemoryTimelineRecordState::Retracted,
        oneiron::MemoryTimelineRecordState::Deleted => CoreMemoryTimelineRecordState::Deleted,
        oneiron::MemoryTimelineRecordState::Missing => CoreMemoryTimelineRecordState::Missing,
    }
}

pub(crate) fn core_memory_operation_kind(
    kind: oneiron::MemoryOperationKind,
) -> CoreMemoryOperationKind {
    match kind {
        oneiron::MemoryOperationKind::PutEntity => CoreMemoryOperationKind::PutEntity,
        oneiron::MemoryOperationKind::SupersedeClaim => CoreMemoryOperationKind::SupersedeClaim,
        oneiron::MemoryOperationKind::RetractClaim => CoreMemoryOperationKind::RetractClaim,
        oneiron::MemoryOperationKind::DeleteEntity => CoreMemoryOperationKind::DeleteEntity,
    }
}

pub(crate) fn parse_required_entity_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<oneiron::EntityId, ApiError> {
    let Some(value) = value else {
        return Err(ApiError::bad_request(
            format!("{field} is required"),
            Some(field),
        ));
    };
    parse_entity_id_param(value, field)
}

pub(crate) fn core_memory_delete_reason(
    verb: oneiron::NamedMemoryVerb,
    requested: Option<CoreMemoryVerbDeleteReason>,
) -> Result<(oneiron::DeleteReason, CoreMemoryVerbDeleteReason), ApiError> {
    let response_reason = requested.unwrap_or(match verb {
        oneiron::NamedMemoryVerb::HardDelete => CoreMemoryVerbDeleteReason::UserHard,
        _ => CoreMemoryVerbDeleteReason::User,
    });
    let reason = match response_reason {
        CoreMemoryVerbDeleteReason::User => oneiron::DeleteReason::UserDelete,
        CoreMemoryVerbDeleteReason::UserHard => oneiron::DeleteReason::UserHardDelete,
        CoreMemoryVerbDeleteReason::Gdpr => oneiron::DeleteReason::GdprDelete,
        CoreMemoryVerbDeleteReason::Policy => oneiron::DeleteReason::PolicyDelete,
    };
    match (verb, response_reason) {
        (oneiron::NamedMemoryVerb::Delete, CoreMemoryVerbDeleteReason::User) => {}
        (oneiron::NamedMemoryVerb::Delete, _) => {
            return Err(ApiError::bad_request(
                "delete only accepts user_delete; use hard_delete for hard-delete reasons",
                Some("reason"),
            ));
        }
        (
            oneiron::NamedMemoryVerb::HardDelete,
            CoreMemoryVerbDeleteReason::UserHard
            | CoreMemoryVerbDeleteReason::Gdpr
            | CoreMemoryVerbDeleteReason::Policy,
        ) => {}
        (oneiron::NamedMemoryVerb::HardDelete, CoreMemoryVerbDeleteReason::User) => {
            return Err(ApiError::bad_request(
                "hard_delete requires user_hard_delete, gdpr_delete, or policy_delete",
                Some("reason"),
            ));
        }
        _ => {}
    }
    Ok((reason, response_reason))
}
