//! Door for `tests/owner_refusal_catch_all.rs` and
//! `tests/campaign_surface_unexpected_code.rs` (UC-11): the HTTP status a
//! route answers an engine refusal code with, for the routes whose
//! catch-all ruling UC11-CLIENT-STATUSES names, without a fixture that
//! makes the engine fail.

/// The status `POST /v1/owner/steer`, `POST /v1/owner/inbox/concern/move`
/// and `GET /v1/owner/inbox` answer a refusal whose code is `code` with, in
/// that order.
#[must_use]
pub fn owner_route_statuses(code: &str) -> [u16; 3] {
    crate::api::engine_refusal_statuses_for_test(code).map(|status| status.as_u16())
}

/// The status the campaign and saved-query routes (`/campaigns*`,
/// `/saved-queries*`) answer an engine refusal whose code is `code` with.
#[must_use]
pub fn campaign_surface_status(code: &str) -> u16 {
    crate::api::surface_error(oneiron::MemoryError::new(code, "a pinned refusal", &[]))
        .status()
        .as_u16()
}
