//! Artifact-unit refusal records tied to their pinned live body.

use serde_json::Value;

/// A unit the ask will not read as given.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct UnitRefusal {
    pub unit: Value,
    pub reason: String,
    /// The live body the ask read the unit on, when it read one (FIX 12018).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judged_live: Option<crate::typed_body::live_pin::LivePin>,
}
