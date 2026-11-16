//! Moved from `crates/oneiron/src/access_grant/owner_act.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's change to an access grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessGrantActChange {
    Grant,
    Revoke,
}

impl AccessGrantActChange {
    /// The stable receipt word for this change, used as the outcome and the
    /// receipt-id event word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "granted",
            Self::Revoke => "revoked",
        }
    }
}
