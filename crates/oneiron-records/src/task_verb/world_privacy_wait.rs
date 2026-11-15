//! Moved from `crates/oneiron/src/task_verb/world_privacy_wait.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where a waited-on world-privacy request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum WorldPrivacyWaitStatus {
    Pending,
    /// A holder's yes applied it: the settings receipt.
    Applied {
        receipt_id: String,
    },
    /// A holder declined it, or cancelled it from its notice.
    Declined,
}
