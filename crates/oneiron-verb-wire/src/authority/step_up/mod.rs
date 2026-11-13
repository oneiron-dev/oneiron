//! Moved from `crates/oneiron/src/authority/step_up/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::step_up::admin_inputs::WeaveAdminDigestRequest;
pub use crate::authority::step_up::admin_inputs::WeaveAdminLensRequest;
pub use crate::authority::step_up::admin_inputs::WeaveAdminLinkWrongRequest;
pub use crate::authority::step_up::admin_inputs::WeaveAdminReportRequest;
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
}

/// The receipt of an owner's reset of one person's passkeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepUpPasskeysReset {
    /// The person (32 hex).
    pub person: String,
    /// How many enrolled passkeys were removed.
    pub removed: usize,
}
pub mod admin_inputs;
pub mod totp;
