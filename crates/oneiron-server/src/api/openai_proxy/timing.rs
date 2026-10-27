//! FIX 8190: when a refused model call may be sent again, as its source error
//! said it. A rate limit, a spent usage window and a call kept on this device
//! can each name the seconds to wait and the times their limit resets; the
//! raw reply states both beside its code (`retry_after`, `resets_at`) and the
//! wait as `Retry-After`, and the typed facade carries them on its error. A
//! time the source did not say is never made up.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use oneiron::{LlmError, RetryableLlmError};
use serde_json::{Value, json};

/// When a refused call may go again: the seconds its source said to wait,
/// and each time it said its limit resets, as Unix seconds in its order.
#[derive(Debug, Default)]
pub(super) struct RetryTiming {
    retry_after: Option<u64>,
    resets_at: Vec<u64>,
}

impl RetryTiming {
    /// What `failure` says of when to send again; nothing for a failure that
    /// names no time.
    pub(super) fn of(failure: &LlmError) -> Self {
        match failure {
            LlmError::Retryable(
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
            ) => Self {
                retry_after: *retry_after,
                resets_at: resets_at.clone(),
            },
            _ => Self::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.retry_after.is_none() && self.resets_at.is_empty()
    }
}

/// [`super::wire::error`] for a refusal whose source said when to send again:
/// the same status, body and refusal extension (the call receipt's code,
/// FIX 3389), with `retry_after` and `resets_at` beside the code and the wait
/// as `Retry-After`. A refusal that names no time is `wire::error` exactly.
pub(super) fn timed_error(
    status: StatusCode,
    kind: &str,
    code: &str,
    message: String,
    timing: &RetryTiming,
) -> Response {
    if timing.is_empty() {
        return super::wire::error(status, kind, code, message);
    }
    let mut body = super::wire::envelope(kind, code, &message);
    let mut response = super::wire::error(status, kind, code, message);
    if let Some(seconds) = timing.retry_after {
        body["error"]["retry_after"] = json!(seconds);
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(seconds));
    }
    if !timing.resets_at.is_empty() {
        body["error"]["resets_at"] = json!(timing.resets_at);
    }
    *response.body_mut() = Json(body).into_response().into_body();
    response
}

/// `refusal` with the timing a raw refusal's `error` object states, for the
/// typed facade: `retry_after` in seconds and every `resets_at` time.
pub(super) fn carried(
    error: &Value,
    mut refusal: oneiron::memory::MemoryError,
) -> oneiron::memory::MemoryError {
    refusal.retry_after = error["retry_after"].as_u64();
    refusal.resets_at = error["resets_at"]
        .as_array()
        .map(|resets| resets.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    refusal
}
