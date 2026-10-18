//! `POST /v1/core/messages/{message}/result`: the result a MESSAGE carries in
//! place of an answer too large to say (FIX 365), read as the credential's
//! principal on the read lane its transcript is read on: the result's card,
//! or a `slice`, `search`, `query` or `chunks` page of its body. Only the
//! body the MESSAGE's own hold backs resolves, and the answer leaves this
//! device as the MCP `read_result` door's does.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::code_run::ResultFacet;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_NOT_FOUND,
    MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError,
};
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

use super::conversation_transcript::reader;
use super::facade::ROOM_TURN_HEADER;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorDetails, ApiErrorEnvelope, EnvelopedApiError};
use crate::server::SyncServer;

/// One read of a MESSAGE's result.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageResultReadRequest {
    /// `slice`, `search`, `query` or `chunks`; absent for the result's card.
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "search")]
    facet: Option<ResultFacet>,
    /// The facet's input, as MCP `read_result` takes it. `ref`, a range ref
    /// of this result (`<handle>#<start>-<end>`, as a `chunks` page names
    /// one), narrows the read to that range.
    #[serde(default)]
    #[schema(value_type = Object)]
    input: Value,
}

/// Read the result one MESSAGE carries.
#[utoipa::path(
    post,
    path = "/v1/core/messages/{message}/result",
    params(("message" = String, Path, description = "Hex MESSAGE id.")),
    request_body = MessageResultReadRequest,
    responses(
        (status = 200, description = "`{\"output\": ...}`: the result's card (its preview withheld while the body is not clean for the reader) or the facet's page; or the read's `denied` refusal (`result_withheld`, `unknown_handle`, `invalid_range`, `invalid_result_input`).", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed MESSAGE id or request body, or a room turn header.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read, or names no principal and actor class.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "No MESSAGE the reader may read has this id, or it carries no result its own hold backs.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Result read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn read_core_message_result(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    Path(message): Path<String>,
    payload: Result<Json<MessageResultReadRequest>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_lane_record_scope()?;
    // The read is not bounded by a room's ceiling, so a request made inside a
    // room turn is refused rather than read outside it.
    if headers.contains_key(ROOM_TURN_HEADER) {
        return Err(ApiError::bad_request(
            "a message result is not served inside a room turn",
            Some(ROOM_TURN_HEADER),
        )
        .into());
    }
    let message = super::parse_entity_id_param(&message, "message")?;
    let request = super::json_payload(payload)?;
    let (actor, class) = reader(&auth)?;
    let proof = auth.verified_slip().cloned();
    let locality = auth.locality();
    // A search or a table query scans up to its bound from disk, so it runs
    // off the reactor.
    let read = tokio::task::spawn_blocking(move || -> Result<Value, MemoryError> {
        let memory = server.vault.memory(actor, class).at(locality);
        let memory = match &proof {
            Some(proof) => memory.with_read_proof(proof),
            None => memory,
        };
        let reply = memory.read_message_result(&message, request.facet, request.input)?;
        // A row the answer names that a device-local world keeps from the
        // caller withholds it, as it does a run's answer.
        let named = reply.to_string();
        if crate::device_local::withholds_retained(&server.vault, locality, &[], named.as_bytes())
            .map_err(MemoryError::from)?
        {
            return Ok(json!({"denied": "result_withheld", "reasonCodes": ["result_withheld"]}));
        }
        Ok(reply)
    })
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(
            panicked = error.is_panic(),
            "message result read failed to join"
        );
        Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "the message result read did not finish",
            &["Retry the call."],
        ))
    })
    .map_err(refusal)?;
    Ok(Json(read))
}

/// The engine's refusal in the core error envelope, with the receipt of the
/// read that refused.
fn refusal(error: MemoryError) -> EnvelopedApiError {
    let receipt = error.read_receipt.clone();
    let api = match error.code.as_str() {
        MEMORY_CODE_NOT_FOUND => ApiError::not_found("message_result", None),
        MEMORY_CODE_BAD_REQUEST => ApiError::bad_request(error.message, None),
        MEMORY_CODE_FORBIDDEN | MEMORY_CODE_OWNER_BINDING_REQUIRED => ApiError::new(
            error.message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            error.suggestions,
        ),
        _ => {
            tracing::error!(code = %error.code, "message result read failed");
            ApiError::internal_server_error("message result read failed")
        }
    };
    let enveloped = EnvelopedApiError::from(api);
    match receipt {
        Some(receipt) => enveloped.with_read_receipt(*receipt),
        None => enveloped,
    }
}
