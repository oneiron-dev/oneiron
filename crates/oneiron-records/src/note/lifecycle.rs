//! Moved from `crates/oneiron/src/note/lifecycle.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::note::lifecycle::NoteRefRequest;
use serde::Deserialize;
use serde::Serialize;

/// Whether a NOTE is reachable, orthogonal to its mutability (ARCH-0032).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteLifecycleStatus {
    Active,
    Sealed,
    Archived,
    Tombstoned,
}
