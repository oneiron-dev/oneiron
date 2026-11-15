//! Moved from `crates/oneiron/src/authority/step_up/totp.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Owner reset names only the person's TOTP factors, not their passkeys.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpTotpResetRequest {
    pub person: String,
    /// An asker's approved check-in for this reset, 32 hex
    /// (`step_up_reset_effect_digest`): the Owner applies it on their own
    /// proof, and the answer names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepUpTotpReset {
    pub person: String,
    pub removed: usize,
    /// The check-in decision the reset ran on (2k3): the Owner on their own
    /// proof, and the approved check-in of another asker it applied, with
    /// its requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}
