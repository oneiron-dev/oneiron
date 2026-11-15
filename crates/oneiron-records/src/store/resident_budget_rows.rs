//! Moved from `crates/oneiron/src/store/resident_budget_rows.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::store::resident_budget_rows::ResidentShare;
use serde::Deserialize;
use serde::Serialize;

/// Which allocation a lease draws on: its id and generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllocationRef {
    pub id: String,
    pub generation: u64,
}
