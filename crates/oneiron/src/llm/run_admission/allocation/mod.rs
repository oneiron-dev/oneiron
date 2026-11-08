//! Durable native allocation state. The explicit current selection and every
//! original hold share the vault writer; no reflected BudgetGuard admits here.
//! Server producer callbacks must use this same writer and persist their original
//! admitted/terminal material. This module does not install a runtime adapter.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::declaration::LeaseUnit;
use super::host::{Allocation, AllocationRef, AllocationRefusal};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod store;

const ACCOUNT: SideTable<(), AccountRow, Named> = SideTable::new(&side_table::BUDGET_HOST_ACCOUNT);

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

/// One allocation's current durable observation, in its original opaque unit.
/// Pending deletion or a newer observation is not Cloud acceptance or backing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAllocationRead {
    pub allocation: Allocation,
    pub accepting: bool,
    pub remaining_units: u64,
    pub pending_units: u64,
    pub used_units: u64,
    pub revision: u64,
    pub serving_fence: AllocationServingFence,
}

/// The write committed even when later unrelated vault work failed. Callers
/// must retain `value` and must not undo or repeat it on `postcommit_error`.
#[must_use]
pub struct AllocationCommit<T> {
    pub value: T,
    pub revision: u64,
    pub postcommit_error: Option<AllocationStoreError>,
}

/// Native storage failures remain distinct from budget/admission denials.
#[derive(Debug, thiserror::Error)]
pub enum AllocationStoreError {
    #[error(transparent)]
    Store(#[from] crate::Error),
    #[error("persistent allocations require the live owned vault writer lease")]
    WriterLease,
    #[error("the actual serving lease changed")]
    ServingChanged,
    #[error("allocation generation is not newer than one already held")]
    StaleGeneration,
    #[error("the host has delivered no allocation")]
    NoAllocation,
    #[error("the selected allocation is not accepting reservations")]
    Closed,
    #[error("the allocation is spent")]
    Exhausted,
    #[error("no rate converts the call into the allocation unit")]
    UnitMismatch,
    #[error("the owner's pinned share for this resident is spent")]
    ResidentShareSpent { resident: EntityId },
    #[error("the original call already has a durable hold")]
    HoldExists,
    #[error("the original hold is absent")]
    HoldNotFound,
    #[error("the original hold is already dispatched or terminal")]
    HoldClosed,
    #[error("the terminal differs from the original durable terminal")]
    TerminalMismatch,
    #[error("the physical dispatch was not durably recorded")]
    DispatchNotRecorded,
    #[error("allocation accounting cannot represent the amount or revision")]
    Overflow,
    #[error("allocation producer: {0}")]
    Producer(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Persistent backend bound to the actual VaultWriterLease, not a constructor
/// generation. Existing HostAccount memory constructors do not use this backend.
pub struct VaultAllocationLedger {
    vault: Arc<Vault>,
    fence: AllocationServingFence,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRow {
    fence: Option<AllocationServingFence>,
    revision: u64,
    current: Option<AllocationRef>,
    newest_generation: Option<u64>,
    refused: Option<AllocationRefusal>,
    allocations: Vec<AllocationRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocationRow {
    allocation: Allocation,
    accepting: bool,
    remaining_units: u64,
    pending_units: u64,
    used_units: u64,
    holds: Vec<DurableAllocationHold>,
}

/// Actor erase removes attribution, not money or pending custody. A later
/// terminal reads this stored hold and cannot recreate the erased resident.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    let Some(mut row) = ACCOUNT.get(&vault.store, txn, &())? else {
        return Ok(());
    };
    let mut changed = false;
    for allocation in &mut row.allocations {
        for hold in &mut allocation.holds {
            if hold.resident.as_ref() == Some(actor) {
                hold.resident = None;
                changed = true;
            }
        }
    }
    if changed {
        row.revision = row.revision.checked_add(1).ok_or_else(|| {
            crate::Error::InvalidConfig("allocation revision overflow".to_owned())
        })?;
        ACCOUNT.put(&vault.store, txn, &(), &row)?;
    }
    Ok(())
}
