//! Moved from `crates/oneiron/src/llm/run_admission/allocation/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::resident_budget_rows::AllocationRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_run_budget::run_budget::LeaseUnit;
use serde::Deserialize;
use serde::Serialize;

/// An observation of the actual writer-lease acquisition, never a bearer grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationServingFence(pub [u8; 16]);

/// Original run/lease identity. Reusing it never reserves a second hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationCallKey {
    pub instance: EntityId,
    pub lease: String,
}

/// A durable reservation on one original allocation, retained after replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableAllocationHold {
    pub key: AllocationCallKey,
    pub allocation: AllocationRef,
    pub unit: LeaseUnit,
    pub reserved_units: u64,
    pub serving_fence: AllocationServingFence,
    pub resident: Option<EntityId>,
    pub resident_share_units: u64,
    pub resident_committed_units: u64,
    pub overdraft_units: u64,
    /// Set only by the physical dispatch adapter's durable start transition.
    pub dispatched: bool,
    pub terminal: Option<AllocationTerminal>,
}

/// Original terminal identity and charge. The receipt digest covers the actual
/// receipt; its clock and payload must not be reconstructed during redelivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationTerminal {
    pub occurred_at: u64,
    pub receipt_digest: [u8; 32],
    pub dispatched: bool,
    pub units: u64,
}
