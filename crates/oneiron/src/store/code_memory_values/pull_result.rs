//! Provenance-labelled code-memory pull values.

use super::{AlwaysOnCodeMemoryContract, CodeMemorySlotValue, ProvenanceLabelled};

/// Provenance-labelled DATA returned by an L2 pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryPullResult {
    pub notes: Vec<ProvenanceLabelled<CodeMemorySlotValue>>,
    pub always_on_contracts: Vec<ProvenanceLabelled<AlwaysOnCodeMemoryContract>>,
    /// The actor's read, resolved in the pull's own snapshot: stored payloads
    /// the actor may not see are counted here, never silently dropped.
    pub read_receipt: oneiron_contracts::claim::ScopedReadReceipt,
}
