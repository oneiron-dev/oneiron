//! The HTTP facade error body on app frames. Engine codes stay open strings.
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::memory::MemoryError;
use serde::Serialize;

use crate::error::ApiError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppError {
    code: String,
    message: String,
    request_id: String,
    suggestions: Vec<String>,
}

impl AppError {
    pub(super) fn new(
        code: &str,
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            code: code.to_owned(),
            message: message.into(),
            request_id: format!("ws-facade-req-{id:016x}"),
            suggestions: suggestions.into_iter().map(Into::into).collect(),
        }
    }

    pub(super) fn forbidden(
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(oneiron::memory::MEMORY_CODE_FORBIDDEN, message, suggestions)
    }

    pub(super) fn invalid_params() -> Self {
        Self::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            "invalid JSON request body",
            ["Send a JSON body matching this verb's documented input."],
        )
    }

    pub(super) fn bad_request(message: impl Into<String>, field: Option<&str>) -> Self {
        ApiError::bad_request(message, field).into()
    }

    pub(super) fn unauthorized() -> Self {
        ApiError::unauthorized().into()
    }

    pub(super) fn not_found(resource: impl Into<String>, id: Option<&str>) -> Self {
        ApiError::not_found(resource, id).into()
    }

    pub(super) fn not_implemented(feature: impl Into<String>) -> Self {
        ApiError::not_implemented(feature).into()
    }

    pub(super) fn internal_server_error(message: impl Into<String>) -> Self {
        ApiError::internal_server_error(message).into()
    }
}

impl From<ApiError> for AppError {
    fn from(error: ApiError) -> Self {
        Self::new(
            error.code().as_str(),
            error.message(),
            error.suggestions().to_vec(),
        )
    }
}

impl From<MemoryError> for AppError {
    fn from(error: MemoryError) -> Self {
        // Match the released HTTP projection, not the engine's internal fields.
        Self::new(&error.code, error.message, error.suggestions)
    }
}
