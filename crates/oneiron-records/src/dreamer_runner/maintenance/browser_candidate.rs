//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/browser_candidate.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A candidate program the Coach proposed (CUA E8): its finding, its
/// admission job once one is queued, and the generation it read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSeen {
    pub finding: EntityId,
    pub job: Option<EntityId>,
    pub generation: u64,
}

/// Where a program's ref leads now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowResolution {
    /// The live program `id`: the one named, or its successor.
    Active { id: EntityId },
    /// The lineage ends at `id`, retired for `reason` with no successor.
    Retired {
        id: EntityId,
        reason: Option<String>,
    },
    /// No program was ever filed under the ref.
    Missing,
}
