//! OpenAI memory-proxy response conversion and refusal mapping (OF-445).
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oneiron::task_verb::sdk::{
    ChatCompletionChoice, ChatCompletionMemory, ChatCompletionMessage, ChatCompletionObject,
    ChatCompletionResponse, ChatCompletionRole, ChatCompletionUsage,
};
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, LlmError, LlmMessage, LlmResponse, RetryableLlmError,
};
use serde_json::{Value, json};

/// The answer's text parts, joined; reasoning stays out of the reply.
pub(super) fn answer_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// The `chat.completion` object for one settled answer. `oneiron` says what
/// the proxy recalled and proposed; an OpenAI client ignores it.
pub(super) fn completion(
    id: &str,
    created: u64,
    model: &str,
    response: &LlmResponse,
    oneiron: ChatCompletionMemory,
) -> ChatCompletionResponse {
    let prompt = response.usage.input.total;
    let completion = response.usage.output.total;
    ChatCompletionResponse {
        id: id.to_owned(),
        object: ChatCompletionObject::ChatCompletion,
        created,
        model: model.to_owned(),
        choices: vec![ChatCompletionChoice {
            index: 0,
            message: ChatCompletionMessage {
                role: ChatCompletionRole::Assistant,
                content: answer_text(&response.message),
            },
            finish_reason: finish_reason(&response.finish_reason).to_owned(),
        }],
        usage: ChatCompletionUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt.saturating_add(completion),
        },
        oneiron,
    }
}

fn finish_reason(reason: &FinishReason) -> &str {
    match reason {
        FinishReason::Stop => "stop",
        FinishReason::Length => "length",
        FinishReason::ToolCalls => "tool_calls",
        FinishReason::ContentFiltered => "content_filter",
        FinishReason::Cancelled => "cancelled",
        FinishReason::Other { name } => name,
        // An answer cut short of its terminal (FIX 8617) is never a `stop`;
        // OpenAI's wire names an answer that did not finish `length`.
        FinishReason::Incomplete { .. } => "length",
    }
}

/// A refusal's own code and message, carried on its reply for the call's
/// receipt (FIX 3389) and never written to the wire.
#[derive(Clone, Debug)]
pub(super) struct Refusal {
    pub(super) code: String,
    pub(super) message: String,
}

/// An OpenAI error body: `{"error": {"message", "type", "param", "code"}}`.
pub(super) fn error(
    status: StatusCode,
    kind: &str,
    code: &str,
    message: impl Into<String>,
) -> Response {
    let message = message.into();
    let body = envelope(kind, code, &message);
    let mut response = (status, Json(body)).into_response();
    response.extensions_mut().insert(Refusal {
        code: code.to_owned(),
        message,
    });
    response
}

/// [`error`]'s body, before it is sent.
pub(super) fn envelope(kind: &str, code: &str, message: &str) -> Value {
    json!({"error": {
        "message": message,
        "type": kind,
        "param": null,
        "code": code,
    }})
}

pub(super) fn invalid(code: &str, message: impl Into<String>) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_request_error",
        code,
        message,
    )
}

/// A forwarded call that failed, as an OpenAI client reads one. The model's
/// own key is the host's: a refusal of it is an upstream fault, never the
/// caller's credential.
pub(super) fn upstream_error(failure: LlmError) -> Response {
    let (status, kind, code) = match &failure {
        LlmError::BudgetDenied(_) => (
            StatusCode::PAYMENT_REQUIRED,
            "insufficient_quota",
            "budget_denied",
        ),
        LlmError::Fatal(FatalLlmError::Auth) => {
            (StatusCode::BAD_GATEWAY, "api_error", "upstream_auth")
        }
        LlmError::Fatal(FatalLlmError::LabelRead(_)) => {
            (StatusCode::BAD_GATEWAY, "api_error", "label_read")
        }
        LlmError::Fatal(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "invalid_request",
        ),
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "rate_limited",
        ),
        LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => (
            StatusCode::TOO_MANY_REQUESTS,
            "insufficient_quota",
            "quota_spent",
        ),
        LlmError::Retryable(RetryableLlmError::Timeout) => {
            (StatusCode::GATEWAY_TIMEOUT, "api_error", "timeout")
        }
        LlmError::Retryable(RetryableLlmError::KeptOnDevice { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "kept_on_device",
        ),
        LlmError::Retryable(_) => (StatusCode::BAD_GATEWAY, "api_error", "upstream_error"),
    };
    let timing = super::timing::RetryTiming::of(&failure);
    super::timing::timed_error(status, kind, code, failure.to_string(), &timing)
}

/// Preserve the raw door's refusal code, and when to call again (FIX 8190),
/// on the typed facade's error envelope.
pub(super) async fn facade_error(response: Response) -> oneiron::memory::MemoryError {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    let value: Value = bytes
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    let refusal = oneiron::memory::MemoryError::new(
        value["error"]["code"]
            .as_str()
            .unwrap_or(oneiron::memory::MEMORY_CODE_INTERNAL),
        value["error"]["message"]
            .as_str()
            .unwrap_or("the memory proxy did not finish"),
        &["Use a live paired proxy credential and a supported buffered request."],
    );
    super::timing::carried(&value["error"], refusal)
}
