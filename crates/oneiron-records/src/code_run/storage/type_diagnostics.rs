//! Moved from `crates/oneiron/src/code_run/storage/type_diagnostics.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One step's feedback row. Key: (run, step, invocation).
pub type StepKey = (EntityId, u64, u64);

/// A step's check as a row keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredCheckState {
    Complete,
    Pending,
    Failed,
    Unavailable,
}
