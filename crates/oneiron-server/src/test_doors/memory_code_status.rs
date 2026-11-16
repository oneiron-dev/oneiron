//! Door for `tests/facade_status_registry.rs` (UC-11): the HTTP status the
//! facade answers an engine refusal code with, through
//! `From<MemoryError> for FacadeApiError`, so one test pins every
//! vocabulary's statuses in the facade's order without a fixture per door.

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
