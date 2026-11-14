//! Moved from `crates/oneiron/src/verbs/model_settings.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whether providers keep each Responses turn. This is the same required
/// boolean carried by the owner's existing HTTP model-settings route.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelResponsesStoreSettings {
    pub responses_store: bool,
}
