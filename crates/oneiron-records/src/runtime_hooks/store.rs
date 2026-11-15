//! Moved from `crates/oneiron/src/runtime_hooks/store.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A run's identity: BLAKE3 over its derivation envelope and its position.
pub type RunKey = [u8; 32];

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookRunState {
    Completed,
    Refused,
    Failed,
}

/// The saved row a run index entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookRunRef {
    /// A fact run's memo row.
    Fact(RunKey),
    /// A verb run's saved record.
    Verb(RunKey),
}

impl HookRunRef {
    pub const fn key(self) -> RunKey {
        match self {
            Self::Fact(key) | Self::Verb(key) => key,
        }
    }
}

/// Where a saved intent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookIntentState {
    Pending,
    Applied,
    Refused,
}
