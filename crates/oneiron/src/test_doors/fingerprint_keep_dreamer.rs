//! The agent-health trend replay hash, for the K-proof of PLAN-UC-04 stage 3.2
//! (`tests/fingerprint_keep_dreamer.rs`).

use crate::dreamer_runner::maintenance::agent_health::HealthTrendComparison;

/// The replay hash a trend DIAGNOSTIC stores for `comparison`.
#[must_use]
pub fn trend_content_hash(comparison: &HealthTrendComparison) -> [u8; 32] {
    crate::dreamer_runner::maintenance::agent_health::content_hash_for_test(comparison)
}
