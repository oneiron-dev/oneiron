//! Moved from `crates/oneiron/src/consent_graduation/api.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Threshold and snooze knobs are policy inputs, never engine-default changes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicy {
    pub scope_pattern: String,
    pub required_streak: u32,
    pub posterior_guard: f32,
    /// First and second decline backoffs, in seconds. The third decline pins.
    pub snooze_backoff_seconds: [u64; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationPolicies {
    pub rows: Vec<GraduationPolicy>,
    pub effective: Option<GraduationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicySetRequest {
    pub policy: GraduationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicyClearRequest {
    pub scope_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationChanged {
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraduationOutcome {
    ApprovedUntouched,
    ApprovedAmended,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GraduationMode {
    #[serde(rename = "propose")]
    Propose,
    #[serde(rename = "offered")]
    Offered,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GraduationSnooze {
    None,
    Snoozed { count: u8, next_eligible_at: u64 },
    ManualPinned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GraduationAnswer {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "not-now")]
    NotNow,
    #[serde(rename = "manual_pinned")]
    ManualPinned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraduationDemotionReason {
    Rejected,
    Amended,
    AgentJudgment,
}
