//! Moved from `crates/oneiron/src/consent/lifecycle.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Approve the exact engine-emitted effect digest, never a caller's description.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveOnceRequest {
    pub effect_digest: String,
}

/// Deny the exact effect the engine emitted, with the same digest grammar as approval.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenyConsentRequest {
    pub effect_digest: String,
}

/// Actor (a lineage for stop-asking), action class and bounded envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionBoundRequest {
    pub actor: String,
    pub class: String,
    pub envelope: ActionEnvelopeRequest,
}

/// Project and audience selectors, pinned to that project, with a per-use cap.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelopeRequest {
    pub project: String,
    pub audience: Vec<String>,
    /// A reviewed batch's count; absent for a standing no-press grant.
    /// Zero leaves every send needing the person's press.
    #[serde(default)]
    pub budget: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureBoundRequest {
    pub audience: Vec<String>,
    pub class: String,
    pub envelope: DisclosureEnvelopeRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureEnvelopeRequest {
    pub selectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    /// The standing grant's bound digest, as emitted by its receipt or registry.
    pub grant: String,
}
