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
    /// The receipt of the read that refused, when a read verb refused;
    /// boxed so the refusal stays small on every `Result` that carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    narrowing: Option<Box<oneiron::claim::ScopedReadReceipt>>,
    /// A `WRONG_ROOT` refusal's `{attempted, replacement, schemaRef}`.
    #[serde(flatten)]
    wrong_root: Option<Box<oneiron::memory::MemoryWrongRoot>>,
    /// A verb hook's stop (ARCH-0080 §3): skipped with its reason, pending
    /// on an ask with the invocation and the ask, or hidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    hook: Option<Box<oneiron::runtime_hooks::VerbHookStop>>,
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
            narrowing: None,
            wrong_root: None,
            hook: None,
        }
    }

    pub(super) fn forbidden(
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(oneiron::memory::MEMORY_CODE_FORBIDDEN, message, suggestions)
    }

    /// The refusal's engine or transport code, as a call receipt records it.
    pub(super) fn code(&self) -> &str {
        &self.code
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

    /// State kept between frames met the machine's memory floor, the line
    /// `limits.retained_memory_bytes` sizes: the one refusal past that row.
    pub(super) fn memory_floor() -> Self {
        Self::new(
            "MEMORY_FLOOR",
            "retained state reached the memory floor (limits.retained_memory_bytes)",
            ["Retry once other state is released, or raise limits.retained_memory_bytes."],
        )
    }

    /// Work waited for its turn past a row and reached its deadline
    /// (`limits.queue_wait_timeout_ms`). Nothing was opened.
    pub(super) fn waited_out() -> Self {
        Self::new(
            "WAITED_OUT",
            "the request waited for its turn past its deadline",
            ["Retry: nothing was opened."],
        )
    }

    /// A read whose result changed before all of it was sent.
    pub(super) fn result_changed() -> Self {
        Self::new(
            "RESULT_CHANGED",
            "the result changed before it was sent",
            ["Repeat the read."],
        )
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

/// A facade refusal from the generated dispatch, its open code, read
/// receipt, wrong-root correction and hook stop kept, as `rpc.err` states it.
impl From<crate::api::FacadeApiError> for AppError {
    fn from(error: crate::api::FacadeApiError) -> Self {
        error.into_memory_error().into()
    }
}

impl From<MemoryError> for AppError {
    fn from(error: MemoryError) -> Self {
        // Match the released HTTP projection, not the engine's internal
        // fields; a read refusal keeps its receipt and a hook stop its typed
        // stop, as the HTTP envelope does.
        Self {
            narrowing: error.read_receipt,
            wrong_root: error.wrong_root,
            hook: error.hook,
            ..Self::new(&error.code, error.message, error.suggestions)
        }
    }
}
