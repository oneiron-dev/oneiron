//! The owner's field-specific Responses store setting (OF-602).

use serde::{Deserialize, Serialize};

/// Whether providers keep each Responses turn. This is the same required
/// boolean carried by the owner's existing HTTP model-settings route.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelResponsesStoreSettings {
    pub responses_store: bool,
}
