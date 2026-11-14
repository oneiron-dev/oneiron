//! Moved from `crates/oneiron/src/sync/machine_history.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// What the last try at an owed history found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwedStatus {
    /// Owed, and not settled by the last round.
    #[default]
    Owed,
    /// A row the target waits on landed here since: its held rows are tried
    /// again.
    Landed,
    /// The home's own copy of the history does not resolve whole yet.
    HomePending,
    /// The home refused the read, or may not read the target's world.
    HomeRefused,
}
