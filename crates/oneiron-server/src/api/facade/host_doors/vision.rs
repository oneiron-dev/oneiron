//! `ai.ask_image`: one question about an image's pixels to the host's Local-vision seat (FIX 679).
//! `ai_ask_image` is its call surface.
//! `crate::api::ai` answers it on the one path `POST /v1/ai/ask_image` takes.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use oneiron::EntityId;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND, MemoryError,
};
use oneiron::task_verb::sdk::{AskImageAnswer, AskImageRequest};
use oneiron::{LlmError, RetryableLlmError};
use serde::Deserialize as _;

use super::support::Listed;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "ai.ask_image";
/// The most bytes of a refusal's body read for its code and words: the
/// answering path's refusals are one small JSON object.
const REFUSAL_BODY_BYTES: usize = 64 * 1024;

/// `ai.ask_image`: the caller's question about one image it can read, asked
/// as `POST /v1/ai/ask_image` asks it: its pixels pulled through the
/// caller's own lane, the call admitted through the Local-vision role and
/// spent on the caller's budget line. Beside an answer, the ASSET its
/// pixels were read from; a refusal lists none.
pub(crate) async fn ai_ask_image(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AskImageRequest,
) -> Listed<AskImageAnswer> {
    match crate::api::ai::ask_image_answered(server, auth, input).await {
        Ok(answer) => {
            let listed = EntityId::from_hex(&answer.asset_ref).into_iter().collect();
            (Ok(answer), listed)
        }
        Err(refused) => (Err(refusal_error(refused).await), Vec::new()),
    }
}

/// The HTTP status `POST /v1/ai/ask_image` answers each of its own refusal
/// codes with (`api/ai/vision.rs`, and its provider failures in
/// `api/ai/media.rs` `failure`), so the facade answers the door's refusal
/// under the same code with the same status.
pub(crate) fn ask_image_refusal_status(code: &str) -> Option<StatusCode> {
    Some(match code {
        "empty_question"
        | "box_reads_whole_image"
        | "contract_not_answered"
        | "invalid_question"
        | "invalid_request" => StatusCode::BAD_REQUEST,
        "principal_required" => StatusCode::FORBIDDEN,
        "call_not_admitted" | "budget_denied" => StatusCode::PAYMENT_REQUIRED,
        "kept_on_device" => StatusCode::CONFLICT,
        "content_filtered" => StatusCode::UNPROCESSABLE_ENTITY,
        "rate_limited" | "quota_spent" => StatusCode::TOO_MANY_REQUESTS,
        "pixels_missing" => StatusCode::INTERNAL_SERVER_ERROR,
        "decision_failed" | "provider_auth" | "empty_response" | "provider_unavailable" => {
            StatusCode::BAD_GATEWAY
        }
        "no_model_configured" | "model_route_not_served" => StatusCode::SERVICE_UNAVAILABLE,
        _ => return None,
    })
}

/// The facade's error for one refusal of the shared answering path. A
/// route code [`ask_image_refusal_status`] answers with the refusal's own
/// status stays the code, so the facade answers both alike; any other
/// refusal (a read lane's, a credential's) takes the facade code its status
/// maps back to, with its own code kept in the message. A provider failure's
/// retry hints keep their fields, and its whole detail rides in the message
/// as its JSON, as the sibling media doors carry it.
async fn refusal_error(refused: Response) -> MemoryError {
    let status = refused.status();
    let body = axum::body::to_bytes(refused.into_body(), REFUSAL_BODY_BYTES)
        .await
        .unwrap_or_default();
    let error = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("error").cloned())
        .unwrap_or_default();
    let reason = error
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("refused"))
        .to_owned();
    let words = match (error.get("message"), error.get("llm")) {
        (Some(serde_json::Value::String(message)), _) => message.clone(),
        (_, Some(llm)) => llm.to_string(),
        _ => String::from_utf8_lossy(&body).into_owned(),
    };
    let (code, suggestion) = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => (
            MEMORY_CODE_BAD_REQUEST,
            "Change the call as its message asks.",
        ),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
            MEMORY_CODE_FORBIDDEN,
            "Present a credential with a principal that can read the image.",
        ),
        StatusCode::NOT_FOUND => (
            MEMORY_CODE_NOT_FOUND,
            "Name a view handle the caller was served.",
        ),
        StatusCode::PAYMENT_REQUIRED => (
            MEMORY_CODE_BUDGET_SPENT,
            "The caller's budget line is spent.",
        ),
        StatusCode::TOO_MANY_REQUESTS if reason == "quota_spent" => (
            MEMORY_CODE_BUDGET_SPENT,
            "A usage window or prepaid credit is spent: answer the quota question in GET /v1/ai/status at POST /v1/ai/quota/{question}.",
        ),
        StatusCode::CONFLICT => (
            MEMORY_CODE_INVALID_STATE,
            "The image's pixels are kept on their device.",
        ),
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE => (
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "Retry later, or bind a [models.roles.local_vision] seat.",
        ),
        _ => (MEMORY_CODE_INTERNAL, "This is an Oneiron server bug; please report it."),
    };
    let mut refusal = if ask_image_refusal_status(&reason) == Some(status) {
        MemoryError::new(&reason, format!("{VERB}: {words}"), &[suggestion])
    } else {
        MemoryError::new(code, format!("{VERB}: {reason}: {words}"), &[suggestion])
    };
    (refusal.retry_after, refusal.resets_at) = retry_hints(error.get("llm"));
    refusal
}

/// When to call again, and each time the limit resets, as a provider
/// failure's structured detail says them (`error.llm`); none for any other
/// refusal.
fn retry_hints(llm: Option<&serde_json::Value>) -> (Option<u64>, Vec<u64>) {
    match llm.and_then(|llm| LlmError::deserialize(llm).ok()) {
        Some(LlmError::Retryable(
            RetryableLlmError::RateLimited {
                retry_after,
                resets_at,
            }
            | RetryableLlmError::QuotaSpent {
                retry_after,
                resets_at,
                ..
            }
            | RetryableLlmError::KeptOnDevice {
                retry_after,
                resets_at,
                ..
            },
        )) => (retry_after, resets_at),
        _ => (None, Vec::new()),
    }
}
