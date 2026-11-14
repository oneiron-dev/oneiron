//! Moved from `crates/oneiron/src/verbs/shared_policy.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A shared-act policy change, by the id its proposal answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicyChangeRequest {
    pub change_id: String,
}

/// `vault.shared.policy.answer`'s input: the caller's yes or no.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicyAnswerRequest {
    pub change_id: String,
    pub approve: bool,
}
