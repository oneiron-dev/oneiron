//! Door for `tests/facade_status_registry.rs` and
//! `tests/ask_image_kept_on_device_status.rs` (UC-11): the HTTP status the
//! facade answers an engine refusal code with, through
//! `From<MemoryError> for FacadeApiError`, so one test pins every
//! vocabulary's statuses in the facade's order without a fixture per door;
//! and the status the raw media routes answer a failed model call with.

use axum::response::IntoResponse;

/// The status `POST /v1/core/facade/{verb}` answers a refusal whose code is
/// `code` with.
#[must_use]
pub fn facade_status(code: &str) -> u16 {
    crate::api::FacadeApiError::from(oneiron::MemoryError::new(code, "a pinned refusal", &[]))
        .into_response()
        .status()
        .as_u16()
}

/// The status the raw `/v1/ai/*` media routes (`POST /v1/ai/ask_image`
/// among them) answer a model call that failed with `error` with.
#[must_use]
pub fn raw_media_status(error: &oneiron::LlmError) -> u16 {
    crate::api::ai::failure_status_for_test(error).as_u16()
}

/// The status `ai.ask_image`'s own table names for `code`. The facade door
/// keeps a raw refusal's code only when this is the raw route's status;
/// `None` for a code the table does not name.
#[must_use]
pub fn ask_image_table_status(code: &str) -> Option<u16> {
    crate::api::ask_image_refusal_status(code).map(|status| status.as_u16())
}
