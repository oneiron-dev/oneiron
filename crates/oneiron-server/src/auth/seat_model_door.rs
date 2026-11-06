//! `POST /v1/seat/model/{slot}/v1/chat/completions` and
//! `POST /v1/seat/model/{slot}/v1/messages` (FIX 15702 slice 1; ARCH-0069
//! `#door-sign-loopback`, OSH p6): the loopback T0 door an official CLI
//! seat's model calls go through, its provider key never in the seat.
//!
//! The seat's SDK presents the run's reference to the slot, as the API key
//! its protocol sends (`x-api-key` or a bearer token), from this device.
//! The door finds the open registration whose slot that reference is,
//! under the run's claim; the provider the slot was bound to, still sending
//! with the same key; and the run's seat-child credential the host admitted.
//! It then sends the request's bytes through the vault's credential broker:
//! the body must name one of the slot's models and ask for no stream, and
//! the key is read at the custody door only while that credential holds and
//! names it, and once the run's registration has recorded its taint. The
//! provider's status and its body, the key stripped, go back `no-store`.
//!
//! Loopback is not process identity: any process on this device that holds
//! the reference can spend it while the run's registration and claim stand.
//! Every refusal before the send reads as unauthorized and names nothing.
//! This slice relays buffered replies only: a streamed request is refused.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::claim::CallerLocality;
use oneiron::{FatalLlmError, LlmError, RetryableLlmError};

use super::caller_locality;
use crate::error::{ApiError, EnvelopedApiError};
use crate::models::{KeyDoor, SeatKeyDoor, send_seat_model};
use crate::runtime::{SEAT_MODEL_PATH, SEAT_MODEL_REFERENCE_PREFIX, SeatModelProtocol};
use crate::server::SyncServer;

/// The Anthropic API key header an Anthropic SDK sends its key in.
const ANTHROPIC_KEY_HEADER: &str = "x-api-key";

pub(crate) fn seat_model_door_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(
            &format!("{SEAT_MODEL_PATH}/{{slot}}/v1/chat/completions"),
            post(chat_completions),
        )
        .route(
            &format!("{SEAT_MODEL_PATH}/{{slot}}/v1/messages"),
            post(messages),
        )
}

async fn chat_completions(
    State(server): State<Arc<SyncServer>>,
    Path(slot): Path<String>,
    request: Request,
) -> Result<Response, EnvelopedApiError> {
    model_door(server, slot, SeatModelProtocol::OpenAiChat, request).await
}

async fn messages(
    State(server): State<Arc<SyncServer>>,
    Path(slot): Path<String>,
    request: Request,
) -> Result<Response, EnvelopedApiError> {
    model_door(server, slot, SeatModelProtocol::AnthropicMessages, request).await
}

async fn model_door(
    server: Arc<SyncServer>,
    slot: String,
    protocol: SeatModelProtocol,
    request: Request,
) -> Result<Response, EnvelopedApiError> {
    let (parts, body) = request.into_parts();
    if caller_locality(&parts.headers, &parts.extensions) != CallerLocality::OnDevice {
        return Err(ApiError::unauthorized().into());
    }
    let reference = presented_reference(&parts.headers).ok_or_else(ApiError::unauthorized)?;
    let door = server
        .seat_helpers
        .model_door(&slot, &reference)
        .filter(|door| door.slot.protocol == protocol)
        .ok_or_else(ApiError::unauthorized)?;
    drop(reference);
    let context = server
        .broker_context()
        .cloned()
        .ok_or_else(ApiError::unauthorized)?;
    // The slot sends only through the provider it was bound to, while that
    // provider still sends with the same key and protocol.
    let provider = context
        .seat_model_provider(&door.slot.provider)
        .filter(|provider| provider.secret == door.slot.secret && provider.protocol == protocol)
        .cloned()
        .ok_or_else(ApiError::unauthorized)?;
    // One request is sent whole, as the broker carries a buffered body.
    let bytes = axum::body::to_bytes(body, oneiron_broker::MAX_BODY)
        .await
        .map_err(|_| {
            ApiError::bad_request(
                "the model request is not one readable body within 16 MiB",
                Some("body"),
            )
        })?;
    // Only an Anthropic SDK's own headers may ride on; the reference never
    // leaves the door.
    let asked: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(name, _)| name.as_str().starts_with("anthropic-"))
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    let keys: Arc<dyn KeyDoor> = Arc::new(SeatKeyDoor::new(
        Arc::clone(server.vault()),
        door.credential,
        door.run,
    ));
    let answered = send_seat_model(
        &context,
        &provider,
        &door.slot.models,
        &asked,
        &bytes,
        &keys,
    )
    .await;
    let mut response = match answered {
        Ok(mut answer) => {
            let status = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::new(Body::from(std::mem::take(&mut *answer.body)));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(error) => refused(&error),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// The reference the request presents: in `x-api-key`, as an Anthropic SDK
/// sends its key, or as a bearer token, as an OpenAI SDK does. Two that
/// disagree present none.
fn presented_reference(headers: &HeaderMap) -> Option<zeroize::Zeroizing<String>> {
    let api_key = headers
        .get(ANTHROPIC_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim);
    let reference = match (api_key, bearer) {
        (Some(api_key), Some(bearer)) if api_key != bearer => return None,
        (Some(reference), _) | (None, Some(reference)) => reference,
        (None, None) => return None,
    };
    reference
        .starts_with(SEAT_MODEL_REFERENCE_PREFIX)
        .then(|| zeroize::Zeroizing::new(reference.to_owned()))
}

/// A request the door or its broker refused, or one that got no answer:
/// its status and a code, naming no key, slot or provider.
fn refused(error: &LlmError) -> Response {
    let (status, code) = match error {
        LlmError::Fatal(FatalLlmError::Auth) => (StatusCode::UNAUTHORIZED, "unauthorized"),
        LlmError::Fatal(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        LlmError::Retryable(RetryableLlmError::Timeout) => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        _ => (StatusCode::BAD_GATEWAY, "no_answer"),
    };
    (status, Json(serde_json::json!({"error": {"code": code}}))).into_response()
}
