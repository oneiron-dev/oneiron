//! `GET /v1/core/conversations/{conversation_id}/transcript`: one
//! conversation's turns and their messages in order, read as the credential's
//! principal on the read lane recall uses (ARCH-0006a), so it returns exactly
//! the messages recall may quote to that reader, with the read's receipt.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::claim::ScopedReadReceipt;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError, TranscriptPage,
};
use oneiron::{EdgeActorClass, EntityId};
use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

use super::facade::ROOM_TURN_HEADER;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorDetails, ApiErrorEnvelope, EnvelopedApiError};
use crate::server::SyncServer;

/// Turns a transcript page returns when the request names no limit.
const DEFAULT_TRANSCRIPT_TURNS: usize = 50;

/// Transcript page query.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct TranscriptQuery {
    /// Turns per page, 1 to 200. Defaults to 50.
    #[serde(default)]
    limit: Option<usize>,
    /// The `next` cursor of the previous page.
    #[serde(default)]
    after: Option<String>,
}

/// One transcript page and the receipt of the read that produced it.
#[derive(Debug, Serialize)]
pub(crate) struct TranscriptResponse {
    #[serde(flatten)]
    page: TranscriptPage,
    narrowing: ScopedReadReceipt,
}

/// Read one conversation's turns and their messages in order.
#[utoipa::path(
    get,
    path = "/v1/core/conversations/{conversation_id}/transcript",
    params(
        ("conversation_id" = String, Path, description = "Hex conversation id."),
        TranscriptQuery
    ),
    responses(
        (status = 200, description = "One page of turns, each with the messages the reader may read (role, time and text), and the read's `narrowing` receipt.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed conversation id, limit or cursor, or a room turn header.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read, or names no principal and actor class.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "No conversation the reader may read has this id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The conversation's turns kept moving in time while the page was read; read it again.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Transcript read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_core_conversation_transcript(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    Path(conversation_id): Path<String>,
    query: Result<Query<TranscriptQuery>, QueryRejection>,
) -> Result<Json<TranscriptResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    // The read is not bounded by a room's ceiling, so a request made inside a
    // room turn is refused rather than read outside it.
    if headers.contains_key(ROOM_TURN_HEADER) {
        return Err(ApiError::bad_request(
            "transcript is not served inside a room turn",
            Some(ROOM_TURN_HEADER),
        )
        .into());
    }
    let conversation = super::parse_entity_id_param(&conversation_id, "conversation_id")?;
    let query = super::query_params(query)?;
    let (actor, class) = reader(&auth)?;
    let proof = auth.verified_slip().cloned();
    let read = tokio::task::spawn_blocking(move || {
        let memory = server.vault.memory(actor, class);
        let memory = match &proof {
            Some(proof) => memory.with_read_proof(proof),
            None => memory,
        };
        memory.conversation_transcript(
            &conversation,
            query.after.as_deref(),
            query.limit.unwrap_or(DEFAULT_TRANSCRIPT_TURNS),
        )
    })
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(%error, "transcript read failed to join");
        Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "the transcript read did not finish",
            &["Retry the call."],
        ))
    })
    .map_err(refusal)?;
    Ok(Json(TranscriptResponse {
        page: read.value,
        narrowing: read.receipt,
    }))
}

/// The principal and actor class the credential binds: the reader recall
/// reads as.
fn reader(auth: &CoreAuth) -> Result<(EntityId, EdgeActorClass), ApiError> {
    let actor = auth
        .principal_ref()
        .and_then(|principal| EntityId::from_hex(principal).ok());
    let class = match auth.actor_class() {
        Some("human") => Some(EdgeActorClass::Human),
        Some("agent") => Some(EdgeActorClass::Agent),
        Some("system") => Some(EdgeActorClass::System),
        _ => None,
    };
    actor
        .zip(class)
        .ok_or_else(|| ApiError::forbidden_scope("core:read+principal_ref+actor_class"))
}

/// The engine's refusal in the core error envelope, with the receipt of the
/// read that refused.
fn refusal(error: MemoryError) -> EnvelopedApiError {
    let receipt = error.read_receipt.clone();
    let api = match error.code.as_str() {
        MEMORY_CODE_NOT_FOUND => ApiError::not_found("conversation", None),
        MEMORY_CODE_BAD_REQUEST => ApiError::bad_request(error.message, None),
        MEMORY_CODE_INVALID_STATE => ApiError::new(
            error.message,
            ApiErrorDetails::InvalidState {
                state: Some("transcript_turns_moved".to_owned()),
            },
            error.suggestions,
        ),
        MEMORY_CODE_FORBIDDEN | MEMORY_CODE_OWNER_BINDING_REQUIRED => ApiError::new(
            error.message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            error.suggestions,
        ),
        _ => {
            tracing::error!(code = %error.code, error = %error.message, "transcript read failed");
            ApiError::internal_server_error("transcript read failed")
        }
    };
    let enveloped = EnvelopedApiError::from(api);
    match receipt {
        Some(receipt) => enveloped.with_read_receipt(*receipt),
        None => enveloped,
    }
}

#[cfg(test)]
mod tests;
