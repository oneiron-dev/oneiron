//! Public commitment shapes. IDs are caller references, never raw storage keys.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::commitment_doors::types::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentCloseRequest, CommitmentContent,
    CommitmentCreateReceipt, CommitmentFulfillRequest, CommitmentFulfillmentSource,
    CommitmentIndexOutcome, CommitmentLifecycleReceipt, CommitmentObligor, CommitmentObligorKind,
    CommitmentOccurrence, CommitmentQuotaWindow, CommitmentRefRequest, CommitmentSchedule,
    CommitmentStatus, CommitmentStrength, CommitmentView, CommitmentWakePhase,
    CommitmentWakeProposal,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentCreateRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub obligor: CommitmentObligor,
    pub beneficiary: String,
    pub content: CommitmentContent,
    pub schedule: CommitmentSchedule,
    #[serde(default)]
    pub lead_seconds: Option<u64>,
    pub strength: CommitmentStrength,
    pub birth_provenance: CommitmentBirthProvenance,
    /// When the promise was made, independently of when it was learned.
    pub occurred_at: u64,
    #[serde(default)]
    pub learned_at: Option<u64>,
    pub evidence_turn_refs: Vec<String>,
}
