//! Moved from `crates/oneiron/src/store/attempt_cancel.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
pub use oneiron_wake_contract::store::attempt_cancel::LandingTrigger;
use serde::Deserialize;
use serde::Serialize;

/// Durable LANDING record: why the attempt is landing, who asked, and what the
/// worker reported when it accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptLanding {
    pub trigger: LandingTrigger,
    /// The actor whose request was accepted, or the runtime for a warning.
    pub requested_by: String,
    pub entered_at: u64,
    /// The worker's own status at acceptance — "green + pushed + packet-only"
    /// is a complete and valid landing answer.
    #[serde(default)]
    pub status: Option<String>,
}

/// Two-rung cancel pressure counters carried on the row.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct AttemptCancelPressure {
    /// Soft requests recorded against this attempt, ever.
    #[serde(default)]
    pub requests: u32,
    /// Soft requests the worker refused. The pathology signal.
    #[serde(default)]
    pub rejections: u32,
    /// Recorded requests the worker has not yet answered.
    #[serde(default)]
    pub pending: u32,
}
