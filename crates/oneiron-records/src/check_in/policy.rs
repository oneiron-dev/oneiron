//! Moved from `crates/oneiron/src/check_in/policy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where an act sits, as the wait rows match it: the vault, a world, a
/// project, or a project inside a world.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckInScope {
    pub world_ref: Option<String>,
    pub project_ref: Option<String>,
}

/// Where a captured wait came from. A receipt names it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitSource {
    /// No row: the shipped 24-hour default.
    ShippedDefault,
    /// The policy failed closed: the shipped default, and the receipt says so.
    Unreadable,
    /// The `rung_wait` row with this ref.
    Row(String),
}

impl WaitSource {
    /// The receipt token: `shipped_default`, `unreadable` or `row:<ref>`.
    #[must_use]
    pub fn receipt_token(&self) -> String {
        match self {
            Self::ShippedDefault => "shipped_default".to_owned(),
            Self::Unreadable => "unreadable".to_owned(),
            Self::Row(row_ref) => format!("row:{row_ref}"),
        }
    }
}

/// An act class's effective wait per person rung: its floor. The asker's
/// longer wait and a holder's extension only lengthen it; only a policy
/// holder's row shortens it (Engine ruling P22-SHAPE Q5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassWait {
    pub secs: u64,
    pub source: WaitSource,
}
