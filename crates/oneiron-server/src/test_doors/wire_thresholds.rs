//! Door for `tests/esign_qr_refusals.rs` and the signing wire test in
//! `tests/it_esign_public.rs`: the thresholds manifest write without owner
//! proof, for tests that set up a wire window directly.

use crate::wire_telemetry::{WireTelemetry, WireThresholds};

/// Sets the wire thresholds without owner proof, as the tests' window setup
/// does. Production never writes here: the owner's
/// `vault.wire_health.thresholds.set` verb writes through
/// `set_thresholds_as_owner`.
///
/// # Errors
///
/// What the write returns.
pub fn set_thresholds(
    telemetry: &WireTelemetry,
    thresholds: &WireThresholds,
) -> oneiron::Result<()> {
    telemetry.set_thresholds(thresholds)
}
