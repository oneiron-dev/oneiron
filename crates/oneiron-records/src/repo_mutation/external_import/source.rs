//! Moved from `crates/oneiron/src/repo_mutation/external_import/source.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The only schema these records are read at: no migration, no default.
pub const SCHEMA_VERSION: u32 = 1;

/// What one attempt observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportOutcome {
    /// The base or the imported ref holds this import.
    Held,
    /// The outside ref names another commit.
    Moved,
    /// The fetch or its proof refused.
    Refused,
    /// The fetch and every proof of it passed.
    Fetched,
    /// The door took the send.
    Applied,
    /// The door refused the send.
    Rejected,
    /// The send's outcome is unknown.
    Unknown,
    /// The source's Git-LFS objects go through the host's credential broker,
    /// every batch call and object action, which alone installs the
    /// import's binding when it names one (OSH-3, FIX 19876): recorded
    /// before the first LFS request goes out, and again with what the
    /// broker did once they ended. It says nothing of whether the objects
    /// arrived.
    Brokered,
}
