//! Named deletion reasons accepted by actor-facing doors.

use oneiron_contracts::register::Register;
use serde::{Deserialize, Serialize};

use super::DeleteReason;

/// Named deletion reasons (S7). There is deliberately NO bare bool delete on
/// this surface.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("safe.delete.reason")]
pub enum SafeDeleteReason {
    /// Tombstone delete: local body scrubbed to a shell, no receipt.
    UserDelete,
    /// Hard purge + redaction audit receipt + historical sweep.
    UserHardDelete,
    /// Compliance erase (soft-erase pass + purge + receipt + sweep).
    GdprDelete,
    /// Policy-driven erase (same machinery as GDPR).
    PolicyDelete,
}

impl SafeDeleteReason {
    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }

    pub(crate) const fn delete_reason(self) -> DeleteReason {
        match self {
            Self::UserDelete => DeleteReason::UserDelete,
            Self::UserHardDelete => DeleteReason::UserHardDelete,
            Self::GdprDelete => DeleteReason::GdprDelete,
            Self::PolicyDelete => DeleteReason::PolicyDelete,
        }
    }
}
