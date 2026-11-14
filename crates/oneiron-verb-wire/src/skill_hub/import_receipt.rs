//! Moved from `crates/oneiron/src/skill_hub/import_receipt.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_hub::install_transition::InstallDisposition;
use crate::skill_hub::install_transition::InstallLifecycle;

/// A source receipt for a marketplace install. One content holder can have many source receipts.
/// The publisher field is engine-stamped only by the admitted-publisher adapter door.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct HubImportReceipt {
    pub entity: String,
    pub content_hash: String,
    pub hub_id: String,
    pub ref_string: String,
    pub pin_type: String,
    pub pin_value: Option<String>,
    pub publisher: Option<String>,
    pub publisher_grant: Option<String>,
    /// Typed lifecycle and result at this transaction's committed frontier.
    pub installed_as: InstallLifecycle,
    pub disposition: InstallDisposition,
    /// Host fit analysis and exact source-derived permission requests.
    #[serde(default)]
    pub fit_analysis: Option<String>,
    #[serde(default)]
    pub requested_permissions: Vec<String>,
    pub at: u64,
}
