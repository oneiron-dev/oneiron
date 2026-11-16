//! Moved from `crates/oneiron/src/authority/step_up/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::step_up::admin_inputs::WeaveAdminDigestRequest;
pub use crate::authority::step_up::admin_inputs::WeaveAdminLinkWrongRequest;
pub use crate::authority::step_up::totp::StepUpTotpReset;
pub use crate::authority::step_up::totp::StepUpTotpResetRequest;
use serde::Deserialize;
use serde::Serialize;

/// `vault.step_up.passkeys.reset`'s input: the person whose passkeys the
/// owner resets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpPasskeysResetRequest {
    /// The person (32 hex).
    pub person: String,
    /// An asker's approved check-in for this reset, 32 hex
    /// (`step_up_reset_effect_digest`): the Owner applies it on their own
    /// proof, and the answer names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// The receipt of an owner's reset of one person's passkeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepUpPasskeysReset {
    /// The person (32 hex).
    pub person: String,
    /// How many enrolled passkeys were removed.
    pub removed: usize,
    /// The check-in decision the reset ran on (2k3): the Owner on their own
    /// proof, and the approved check-in of another asker it applied, with
    /// its requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}
pub mod admin_inputs;
pub mod totp;
