//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/environment.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Domain of an amendment label's source id: one id per settled cause row
/// and label.
pub const AMENDMENT_SOURCE_DOMAIN: &[u8] = b"oneiron:agent-health-amendment-cause:v1";
