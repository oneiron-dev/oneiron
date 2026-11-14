//! Moved from `crates/oneiron/src/sync/quota/work.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::cell::Cell;
use std::collections::HashMap;

/// Where a retained maintenance operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceWorkState {
    /// It waits for its turn.
    Pending,
    /// Its wait ended before it landed.
    Expired,
    /// Its replay refused it for good.
    Rejected,
    /// An erase took its row.
    Erased,
}
