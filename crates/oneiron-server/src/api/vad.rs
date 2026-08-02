use super::json_payload;
use super::parse_entity_id_param;
use super::query_params;
use super::require_entity_type;
use super::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::response::Json;
use oneiron::EdgeKind;
use oneiron::ErrorKind;
use oneiron::Vad;
use oneiron::VadAnnotation;
use oneiron::VadAnnotationSource;
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::registry::ENTITY_TYPE_TURN;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

/// Valence/arousal/dominance annotation payload.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "valence": 0.25,
    "arousal": 0.5,
    "dominance": 0.75
}))]
pub(crate) struct VadPayload {
    /// Valence in the same range as edge VAD: `[-1, 1]`.
    #[schema(example = 0.25)]
    valence: f32,
    /// Arousal in the same range as edge VAD: `[0, 1]`.
    #[schema(example = 0.5)]
    arousal: f32,
    /// Dominance in the same range as edge VAD: `[0, 1]`.
    #[schema(example = 0.75)]
    dominance: f32,
}

impl VadPayload {
    fn into_vad(self) -> Result<Vad, ApiError> {
        let vad = Vad {
            valence: self.valence,
            arousal: self.arousal,
            dominance: self.dominance,
        };
        vad.validate()
            .map_err(|error| ApiError::bad_request(error.to_string(), Some("vad")))?;
        Ok(vad)
    }
}

impl From<Vad> for VadPayload {
    fn from(vad: Vad) -> Self {
        Self {
            valence: vad.valence,
            arousal: vad.arousal,
            dominance: vad.dominance,
        }
    }
}

/// Source that produced a turn/message VAD annotation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TurnVadAnnotationSource {
    /// VAD inferred by a model or upstream inference service.
    ModelInference,
    /// VAD reported directly by the user.
    UserSelfReport,
}

impl From<TurnVadAnnotationSource> for VadAnnotationSource {
    fn from(source: TurnVadAnnotationSource) -> Self {
        match source {
            TurnVadAnnotationSource::ModelInference => Self::ModelInference,
            TurnVadAnnotationSource::UserSelfReport => Self::UserSelfReport,
        }
    }
}

impl From<VadAnnotationSource> for TurnVadAnnotationSource {
    fn from(source: VadAnnotationSource) -> Self {
        match source {
            VadAnnotationSource::ModelInference => Self::ModelInference,
            VadAnnotationSource::UserSelfReport => Self::UserSelfReport,
        }
    }
}

/// Request body for writing VAD metadata to a turn or one message in a turn.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "turn_id": "0123456789abcdef0123456789abcdef",
    "source": "model_inference",
    "vad": {
        "valence": 0.25,
        "arousal": 0.5,
        "dominance": 0.75
    },
    "annotated_at": 1782357635_u64
}))]
pub(crate) struct TurnVadAnnotateRequest {
    /// Hex-encoded TURN entity id anchoring the annotation request.
    #[serde(rename = "turn_id", alias = "turnId")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    turn_id: String,
    /// Optional hex-encoded MESSAGE entity id; omit to annotate the turn itself.
    #[serde(default, rename = "message_id", alias = "messageId")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    message_id: Option<String>,
    /// VAD values to persist.
    vad: VadPayload,
    /// Source that produced the VAD values.
    source: TurnVadAnnotationSource,
    /// Unix seconds timestamp for the annotation. Defaults to server time.
    #[serde(default, rename = "annotated_at", alias = "annotatedAt")]
    #[schema(example = 1782357635_u64)]
    annotated_at: Option<u64>,
}

/// Query parameters for reading VAD metadata from a turn or message.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct TurnVadAnnotateQuery {
    /// Hex-encoded TURN entity id anchoring the annotation lookup.
    #[serde(rename = "turn_id", alias = "turnId")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    #[param(example = "0123456789abcdef0123456789abcdef")]
    turn_id: String,
    /// Optional hex-encoded MESSAGE entity id; omit to read the turn annotation.
    #[serde(default, rename = "message_id", alias = "messageId")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    #[param(example = "fedcba9876543210fedcba9876543210")]
    message_id: Option<String>,
}

/// Persisted VAD metadata returned by the turn annotation endpoint.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "turn_id": "0123456789abcdef0123456789abcdef",
    "message_id": null,
    "source": "model_inference",
    "vad": {
        "valence": 0.25,
        "arousal": 0.5,
        "dominance": 0.75
    },
    "annotated_at": 1782357635_u64
}))]
pub(crate) struct TurnVadAnnotateResponse {
    /// Hex-encoded TURN entity id anchoring the annotation.
    #[serde(rename = "turn_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    turn_id: String,
    /// Hex-encoded MESSAGE entity id when the annotation targets a message.
    #[serde(rename = "message_id")]
    #[schema(nullable = true, example = "fedcba9876543210fedcba9876543210")]
    message_id: Option<String>,
    /// Persisted VAD values.
    vad: VadPayload,
    /// Persisted source for the VAD values.
    source: TurnVadAnnotationSource,
    /// Unix seconds timestamp persisted with the annotation.
    #[serde(rename = "annotated_at")]
    #[schema(example = 1782357635_u64)]
    annotated_at: u64,
}

impl TurnVadAnnotateResponse {
    fn new(turn_id: &str, message_id: Option<&str>, annotation: VadAnnotation) -> Self {
        Self {
            turn_id: turn_id.to_owned(),
            message_id: message_id.map(str::to_owned),
            vad: annotation.vad.into(),
            source: annotation.source.into(),
            annotated_at: annotation.annotated_at,
        }
    }
}

/// Write VAD metadata for a turn or one message in a turn.
#[utoipa::path(
    post,
    path = "/v1/core/turns/annotate",
    request_body(
        content = TurnVadAnnotateRequest,
        description = "VAD metadata annotation for a turn, or for a message when `message_id` is supplied.",
        content_type = "application/json"
    ),
    responses(
        (
            status = 200,
            description = "VAD annotation persisted and returned.",
            body = TurnVadAnnotateResponse,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Malformed id, invalid target type, message outside turn, or VAD outside the contract ranges.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 403,
            description = "Bearer token is valid but lacks the required `core:write` scope.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 409,
            description = "Active Gate policy rejected the VAD annotation write; response uses INVALID_STATE with Gate outcome and reason codes.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "Turn or message entity was not found.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "VAD annotation persistence failed.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn annotate_turn_vad(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<TurnVadAnnotateRequest>, JsonRejection>,
) -> Result<Json<TurnVadAnnotateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    let turn_id = parse_entity_id_param(&req.turn_id, "turn_id")?;
    require_entity_type(&server, &turn_id, ENTITY_TYPE_TURN, "turn")?;

    let vad = req.vad.into_vad()?;
    let annotated_at = req.annotated_at.unwrap_or_else(unix_seconds_now);
    let annotation = VadAnnotation::new(vad, req.source.into(), annotated_at)
        .map_err(vad_annotation_core_error)?;

    let stored = if let Some(message_id_hex) = &req.message_id {
        let message_id = parse_entity_id_param(message_id_hex, "message_id")?;
        require_entity_type(&server, &message_id, ENTITY_TYPE_MESSAGE, "message")?;
        require_message_in_turn(&server, &turn_id, &message_id)?;
        server
            .vault
            .annotate_message_vad(&message_id, annotation)
            .map_err(vad_annotation_core_error)?
    } else {
        server
            .vault
            .annotate_turn_vad(&turn_id, annotation)
            .map_err(vad_annotation_core_error)?
    };

    Ok(Json(TurnVadAnnotateResponse::new(
        &req.turn_id,
        req.message_id.as_deref(),
        stored,
    )))
}

/// Read VAD metadata for a turn or one message in a turn.
#[utoipa::path(
    get,
    path = "/v1/core/turns/annotate",
    params(TurnVadAnnotateQuery),
    responses(
        (
            status = 200,
            description = "Persisted VAD annotation for the requested turn or message.",
            body = TurnVadAnnotateResponse,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Malformed id, invalid target type, or message outside turn.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 403,
            description = "Bearer token is valid but lacks the required `core:read` scope.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "Turn/message entity or VAD annotation was not found.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "VAD annotation read failed.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn read_turn_vad_annotation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TurnVadAnnotateQuery>, QueryRejection>,
) -> Result<Json<TurnVadAnnotateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let params = query_params(query)?;
    let turn_id = parse_entity_id_param(&params.turn_id, "turn_id")?;
    require_entity_type(&server, &turn_id, ENTITY_TYPE_TURN, "turn")?;

    let annotation = if let Some(message_id_hex) = &params.message_id {
        let message_id = parse_entity_id_param(message_id_hex, "message_id")?;
        require_entity_type(&server, &message_id, ENTITY_TYPE_MESSAGE, "message")?;
        require_message_in_turn(&server, &turn_id, &message_id)?;
        server
            .vault
            .get_message_vad_annotation(&message_id)
            .map_err(vad_annotation_core_error)?
    } else {
        server
            .vault
            .get_turn_vad_annotation(&turn_id)
            .map_err(vad_annotation_core_error)?
    };

    let Some(annotation) = annotation else {
        let id = params.message_id.as_deref().unwrap_or(&params.turn_id);
        return Err(ApiError::not_found("vad_annotation", Some(id)).into());
    };

    Ok(Json(TurnVadAnnotateResponse::new(
        &params.turn_id,
        params.message_id.as_deref(),
        annotation,
    )))
}

pub(crate) fn require_message_in_turn(
    server: &SyncServer,
    turn_id: &oneiron::EntityId,
    message_id: &oneiron::EntityId,
) -> Result<(), ApiError> {
    match server
        .vault
        .edge_exists(message_id, EdgeKind::ChildOf, turn_id)
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::bad_request(
            "message_id does not belong to turn_id",
            Some("message_id"),
        )),
        Err(error) => {
            tracing::error!(error = %error, "message turn relationship lookup failed");
            Err(ApiError::internal_server_error(
                "message turn relationship lookup failed",
            ))
        }
    }
}

pub(crate) fn vad_annotation_core_error(error: oneiron::Error) -> ApiError {
    match error {
        oneiron::Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            let reason_codes = reason_codes.join(",");
            ApiError::new(
                format!(
                    "VAD annotation rejected by Gate: outcome={outcome}, reasons={reason_codes}"
                ),
                ApiErrorDetails::InvalidState {
                    state: Some(format!("gate_write_rejected:{outcome}:{reason_codes}")),
                },
                [
                    "Route the annotation through policy review or adjust the active Gate policy before retrying.",
                ],
            )
        }
        error => match error.kind() {
            ErrorKind::InvalidVad => ApiError::bad_request(error.to_string(), Some("vad")),
            ErrorKind::InvalidEntityType => {
                ApiError::bad_request(error.to_string(), Some("entity"))
            }
            ErrorKind::EntityNotFound => ApiError::not_found("entity", None),
            _ => {
                tracing::error!(error = %error, "VAD annotation operation failed");
                ApiError::internal_server_error("VAD annotation operation failed")
            }
        },
    }
}
