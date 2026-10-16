//! The OpenAI chat-completions wire the proxy speaks (OF-445): a closed
//! request body, and the reply built from a typed [`LlmResponse`].
use std::collections::BTreeMap;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, LlmError, LlmMessage, LlmMessageRole, LlmResponse,
    RetryableLlmError,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// `POST /v1/chat/completions`'s body. A field the proxy cannot honour
/// (tools, images, logprobs, a response format, ...) is refused by name,
/// never dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChatCompletionRequest {
    pub(super) model: String,
    pub(super) messages: Vec<ChatMessage>,
    #[serde(default)]
    pub(super) stream: Option<bool>,
    #[serde(default)]
    pub(super) n: Option<u32>,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    top_p: Option<f64>,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    max_completion_tokens: Option<u64>,
    #[serde(default)]
    stop: Option<Stop>,
    #[serde(default)]
    presence_penalty: Option<f64>,
    #[serde(default)]
    frequency_penalty: Option<f64>,
    #[serde(default)]
    seed: Option<i64>,
    /// Read and ignored: the credential names who calls, never a body field.
    #[serde(default, rename = "user")]
    _user: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Stop {
    One(String),
    Many(Vec<String>),
}

impl ChatCompletionRequest {
    /// The sampling and output params the body sets, by their OpenAI names.
    pub(super) fn params(&self) -> BTreeMap<String, Value> {
        let stop = self.stop.clone().map(|stop| match stop {
            Stop::One(stop) => json!(stop),
            Stop::Many(stops) => json!(stops),
        });
        [
            ("temperature", self.temperature.map(Value::from)),
            ("top_p", self.top_p.map(Value::from)),
            ("max_tokens", self.max_tokens.map(Value::from)),
            (
                "max_completion_tokens",
                self.max_completion_tokens.map(Value::from),
            ),
            ("stop", stop),
            ("presence_penalty", self.presence_penalty.map(Value::from)),
            ("frequency_penalty", self.frequency_penalty.map(Value::from)),
            ("seed", self.seed.map(Value::from)),
        ]
        .into_iter()
        .filter_map(|(key, value)| Some((key.to_owned(), value?)))
        .collect()
    }
}

/// One history message. Its role says where the text sits in the
/// conversation; it never names an author.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChatMessage {
    role: ChatRole,
    content: ChatContent,
    /// A participant's display name: read and ignored, never an identity.
    #[serde(default, rename = "name")]
    _name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChatRole {
    System,
    Developer,
    User,
    Assistant,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ChatContent {
    Text(String),
    Parts(Vec<ChatPart>),
}

/// Text parts only: an image or audio part is refused, not dropped.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ChatPart {
    Text { text: String },
}

impl ChatMessage {
    pub(super) fn is_user(&self) -> bool {
        self.role == ChatRole::User
    }

    pub(super) fn text(&self) -> String {
        match &self.content {
            ChatContent::Text(text) => text.clone(),
            ChatContent::Parts(parts) => parts
                .iter()
                .map(|ChatPart::Text { text }| text.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    pub(super) fn to_llm(&self) -> LlmMessage {
        let role = match self.role {
            ChatRole::System | ChatRole::Developer => LlmMessageRole::System,
            ChatRole::User => LlmMessageRole::User,
            ChatRole::Assistant => LlmMessageRole::Assistant,
        };
        LlmMessage {
            role,
            content: vec![ContentPart::Text { text: self.text() }],
        }
    }
}

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
    oneiron: Value,
) -> Value {
    let prompt = response.usage.input.total;
    let completion = response.usage.output.total;
    json!({
        "id": id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": answer_text(&response.message)},
            "finish_reason": finish_reason(&response.finish_reason),
        }],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt.saturating_add(completion),
        },
        "oneiron": oneiron,
    })
}

fn finish_reason(reason: &FinishReason) -> &str {
    match reason {
        FinishReason::Stop => "stop",
        FinishReason::Length => "length",
        FinishReason::ToolCalls => "tool_calls",
        FinishReason::ContentFiltered => "content_filter",
        FinishReason::Cancelled => "cancelled",
        FinishReason::Other { name } => name,
    }
}

/// An OpenAI error body: `{"error": {"message", "type", "param", "code"}}`.
pub(super) fn error(
    status: StatusCode,
    kind: &str,
    code: &str,
    message: impl Into<String>,
) -> Response {
    let body = json!({"error": {
        "message": message.into(),
        "type": kind,
        "param": null,
        "code": code,
    }});
    (status, Json(body)).into_response()
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
    error(status, kind, code, failure.to_string())
}
