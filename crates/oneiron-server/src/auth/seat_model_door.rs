//! `POST /v1/seat/model/{slot}/v1/chat/completions` and
//! `POST /v1/seat/model/{slot}/v1/messages` (FIX 15702; ARCH-0069
//! `#door-sign-loopback`, OSH p6): the loopback T0 door an official CLI
//! seat's model calls go through, its provider key never in the seat.
//!
//! The seat's SDK presents the run's reference to the slot, as the API key
//! its protocol sends (`x-api-key` or a bearer token), from this device.
//! The door finds the open registration whose slot that reference is,
//! under the run's claim; the provider the slot was bound to, still sending
//! with the same key; and the run's seat-child credential the host admitted.
//! It then sends the request's bytes through the vault's credential broker:
//! the body must name one of the slot's models, and the key is read at the
//! custody door only while that credential holds and names it, and once the
//! run's registration has recorded its taint. The provider's status and its
//! body, the key stripped, go back `no-store`. A request with `stream: true`
//! gets the provider's server-sent events as the broker clears them (slice
//! 2), and Messages may carry Claude Code's `?beta=true`; no other query is
//! taken.
//!
//! Loopback is not process identity: any process on this device that holds
//! the reference can spend it while the run's registration and claim stand.
//! Every refusal before the send reads as unauthorized and names nothing.
//! A relayed stream the broker cuts ends with a body error: what was relayed
//! before the cut cannot be taken back.
//!
//! Each request is a paid call of the run's claim (slice 3): the claim's run
//! admits it before the key is read, and it settles on what its reply
//! reports as the reply goes back, or on its reservation. A refused
//! admission sends nothing and reads as `budget_exhausted` (429),
//! `admission_denied` (403) or `admission_unavailable` (503), naming no
//! key, slot, provider, balance or reference.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::claim::CallerLocality;
use oneiron::llm::run_admission::RunDenied;
use oneiron::{FatalLlmError, LlmError, RetryableLlmError};

use super::caller_locality;
use crate::error::{ApiError, EnvelopedApiError};
use crate::models::{
    KeyDoor, SeatKeyDoor, SeatModelAnswer, SeatModelCall, SeatModelRefusal, send_seat_model,
};
use crate::runtime::{SEAT_MODEL_PATH, SEAT_MODEL_REFERENCE_PREFIX, SeatModelProtocol};
use crate::server::SyncServer;

/// The Anthropic API key header an Anthropic SDK sends its key in.
const ANTHROPIC_KEY_HEADER: &str = "x-api-key";

/// The one query the door takes, on Messages alone, exactly as Claude Code
/// sends it.
const ANTHROPIC_BETA_QUERY: &str = "beta=true";

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
    let beta = match (protocol, parts.uri.query()) {
        (_, None) => false,
        (SeatModelProtocol::AnthropicMessages, Some(ANTHROPIC_BETA_QUERY)) => true,
        _ => {
            return Err(ApiError::bad_request(
                "the model door takes no query but Messages' beta=true",
                Some("query"),
            )
            .into());
        }
    };
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
        beta,
        &bytes,
        &keys,
        &door.meter,
    )
    .await;
    let mut response = match answered {
        Ok(SeatModelAnswer::Whole(mut answer)) => {
            let status = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::new(Body::from(std::mem::take(&mut *answer.body)));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Ok(SeatModelAnswer::Events {
            status,
            event_stream,
            reply,
            call,
        }) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            // A success that is not an event stream is not relayed as one;
            // a provider's refusal goes back as the JSON it is.
            if status.is_success() && !event_stream {
                refused(&LlmError::from(RetryableLlmError::ServerError))
            } else {
                let content_type = if event_stream {
                    "text/event-stream"
                } else {
                    "application/json"
                };
                let mut response = Response::new(relayed(reply, call));
                *response.status_mut() = status;
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
                response
            }
        }
        Err(SeatModelRefusal::Llm(error)) => refused(&error),
        Err(SeatModelRefusal::Denied(denied)) => admission_refused(&denied),
        // The claim's payer cannot be billed yet: the owners' payer-needed
        // ask stands, and nothing was sent.
        Err(SeatModelRefusal::Unfunded(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": {"code": "admission_unavailable"}})),
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// The reply's body as the broker clears it, chunk by chunk, owning the
/// broker's stream and the call it settles: a client that stops reading
/// drops both, so the broker drops the provider's call and the call settles
/// on what had come back. Each chunk is read for the reply's usage as it
/// goes back, unchanged. A cut ends the body with an error, never as a
/// clean end.
fn relayed(reply: oneiron_broker::BrokerStream, call: SeatModelCall) -> Body {
    let chunks = futures_util::stream::unfold(Some((reply, call)), |state| async move {
        let (mut reply, mut call) = state?;
        match reply.next().await {
            Ok(oneiron_broker::StreamPart::Chunk(mut chunk)) => {
                call.relayed(&chunk);
                Some((
                    Ok(axum::body::Bytes::from(std::mem::take(&mut *chunk))),
                    Some((reply, call)),
                ))
            }
            Ok(oneiron_broker::StreamPart::End) => {
                call.end_stream();
                None
            }
            Ok(oneiron_broker::StreamPart::Cut(_)) | Err(_) => {
                call.end();
                Some((
                    Err(std::io::Error::other("the provider's stream was cut")),
                    None,
                ))
            }
        }
    });
    Body::from_stream(chunks)
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

/// A request the claim's run admission refused, before any key was read:
/// a spent line or allocation, a refused admission, or one the host cannot
/// make now. It names no key, slot, provider, balance or reference.
fn admission_refused(denied: &RunDenied) -> Response {
    let (status, code) = match denied {
        RunDenied::Budget { .. }
        | RunDenied::AllocationExhausted
        | RunDenied::ResidentShareSpent { .. } => {
            (StatusCode::TOO_MANY_REQUESTS, "budget_exhausted")
        }
        RunDenied::NoAllocation | RunDenied::AllocationRefused { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "admission_unavailable")
        }
        _ => (StatusCode::FORBIDDEN, "admission_denied"),
    };
    (status, Json(serde_json::json!({"error": {"code": code}}))).into_response()
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
