//! Single-vault selector grant scope shared by handler and livequery (FIX 9251).

/// The grant scope this single-vault selector server path checks: the one an
/// owner's own-device grant is minted under (FIX 3134). Distinct from the
/// lease ABI's internal vault id.
pub(crate) fn selector_grant_scope() -> oneiron::FederationGrantScope {
    oneiron::federation::own_device_residence_scope()
}
