//! Moved from `crates/oneiron/src/code_run/storage/secret_lift.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_run::storage::secret_lift::room::CodeRunRoomSecretLiftRequest;
use serde::Deserialize;
use serde::Serialize;

/// The exact occurrence whose proposal the owner dismisses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSecretLiftDismiss {
    pub handle: String,
    pub occurrence: String,
}

/// Lists code-run lift proposals, optionally dismissing one first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSecretLiftRequest {
    #[serde(default)]
    pub dismiss: Option<CodeRunSecretLiftDismiss>,
}

/// A proposal's value-free wire form. No body or secret value is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSecretLiftProposalView {
    pub handle: String,
    pub occurrence: String,
    pub detector_reason: String,
    pub suggested_secret_name: String,
}

/// The owner's dismissal and the Gate receipt committed with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSecretLiftDismissal {
    pub handle: String,
    pub occurrence: String,
    pub dismissed_by: String,
    pub dismissed_at: u64,
    pub receipt: String,
}

/// The open proposals after this call, and its dismissal if requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSecretLiftStatus {
    pub proposals: Vec<CodeRunSecretLiftProposalView>,
    pub dismissed: Option<CodeRunSecretLiftDismissal>,
}
pub mod room;
