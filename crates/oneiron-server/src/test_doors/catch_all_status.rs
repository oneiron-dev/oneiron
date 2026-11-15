//! Door for `tests/owner_refusal_catch_all.rs`,
//! `tests/campaign_surface_unexpected_code.rs` and
//! `tests/owner_plane_refusal_answers.rs` (UC-11): the HTTP status a route
//! answers an engine refusal code with, for the routes whose catch-all
//! ruling UC11-CLIENT-STATUSES names, and the owner refusal each owner-plane
//! map makes of a code, without a fixture that makes the engine fail.

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

/// What the owner plane's refusal maps make of an engine refusal whose code
/// is `code`, each as `<variant> <payload>`: the off-record witness, the
/// cleanup review, the history erase, the NOTE tombstone, the steer, the
/// concern move and the inbox lens map, in that order.
#[must_use]
pub fn owner_plane_refusals(code: &str) -> [String; 7] {
    let refusal = || oneiron::memory::MemoryError::new(code, "a pinned refusal", &[]);
    let [steer, concern_move, inbox] = crate::api::owner_route_refusals_for_test(code);
    [
        crate::owner::off_record::witness_error(refusal()),
        crate::owner::cleanup::per_item_refusal(refusal()),
        crate::owner::history::erase_error(refusal()),
        crate::owner::note_tombstones::memory_error(refusal()),
        steer,
        concern_move,
        inbox,
    ]
    .map(|answer| owner_answer(&answer))
}

/// An owner refusal's variant and payload, as one line.
fn owner_answer(answer: &crate::owner::OwnerError) -> String {
    use crate::owner::OwnerError;
    match answer {
        OwnerError::Invalid(message) => format!("Invalid {message}"),
        OwnerError::Changed(message) => format!("Changed {message}"),
        OwnerError::Refused(message) => format!("Refused {message}"),
        OwnerError::NotFound(what, which) => format!("NotFound {what} {which}"),
        OwnerError::Engine(error) => format!("Engine {error}"),
        OwnerError::Host(error) => format!("Host {error:#}"),
    }
}
