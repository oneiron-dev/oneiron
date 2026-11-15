//! Moved from `crates/oneiron/src/policy_model/owner_rows/secret_scan_switch.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::batch::secret_scan::SecretScanMode;
use serde::Deserialize;
use serde::Serialize;

/// One owner change of the switch, in revision order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretScanReceipt {
    pub receipt_id: String,
    pub revision: u64,
    /// The owner actor who switched it, as hex.
    pub author: String,
    pub mode: SecretScanMode,
    /// The mode the vault had before this change.
    pub previous: SecretScanMode,
    pub at: u64,
}
