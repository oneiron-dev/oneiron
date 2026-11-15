//! Moved from `crates/oneiron/src/store/legal_hold/pending.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which owner act a waiting erase carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingEraseKind {
    /// The owner's "Lift the hold and erase?" confirm: a hard erase, and an
    /// audience edit erased as a privacy erase leaves it.
    LiftAndErase,
}
