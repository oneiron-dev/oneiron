//! Moved from `crates/oneiron/src/policy_setting_doors.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::OwnerAct;
pub use oneiron_authority::authority::PolicySetting;
pub use oneiron_authority::authority::owner_act_target;
use serde::Deserialize;
use serde::Serialize;

/// One owner act on a vault-wide setting, as this install recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettingActReceipt {
    pub setting: PolicySetting,
    pub act: OwnerAct,
    /// BLAKE3 over the setting as it stood, as JSON.
    pub prior: [u8; 32],
    /// Vault clock seconds.
    pub at: u64,
}
