//! Door for `tests/owner_check_host_fault.rs` (MEMBER-SELECTOR-SOCKET): the
//! status the owner door answers an engine error its check met with.

/// The HTTP status the owner door answers `error` with
/// (`crate::api::owner_check_failure`): 500 for a host fault, 403 for any
/// other error.
#[must_use]
pub fn owner_check_failure_status(error: &oneiron::Error) -> u16 {
    crate::api::owner_check_failure(error).status().as_u16()
}
