//! Browser workflow resolution and candidate counters read by the Coach.
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// The domain a candidate program's input fingerprint is hashed in (CUA E8,
/// CALLS row "candidate dedup"), for the Coach's seen marker.
pub const CANDIDATE_DOMAIN: &[u8] = b"oneiron:browser-program-induction:v1";

/// A program whose library runs failed, live or retired (CUA E8a): its
/// own record's lifetime count, never a successor's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFailureRef {
    pub id: EntityId,
    pub failures: u64,
    pub retired: bool,
    pub retire_reason: Option<String>,
    pub refs: FailureLineage,
}

/// Where a failed program sits in its lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureLineage {
    pub site: String,
    pub supersedes: Option<EntityId>,
    /// The program that repaired it, when a retire names one.
    pub successor: Option<EntityId>,
}

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
