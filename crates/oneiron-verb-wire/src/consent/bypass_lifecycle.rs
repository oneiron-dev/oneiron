//! Moved from `crates/oneiron/src/consent/bypass_lifecycle.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassActionEnvelopeRequest {
    pub selectors: Vec<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub budget: Option<u64>,
    #[serde(default)]
    pub receipt_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveBypassGrantsRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassedEffectReceiptsRequest {
    /// The reference emitted by creation, active state or the registry.
    pub grant: String,
}

/// A projection of an existing Gate receipt, never a caller-authored effect.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassedEffectReceipt {
    pub decision_ref: String,
    pub grant_ref: String,
    pub effect_digest: String,
    pub reason_code: String,
    pub created_at: u64,
}
