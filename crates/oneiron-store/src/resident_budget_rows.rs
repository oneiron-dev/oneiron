//! The vault's durable resident budget rows (FIX 7767): each resident's
//! share of the host-paid allocation and its depletion on the allocation
//! generation it last drew on, keyed by the resident, with the erase an
//! actor's deletion makes of its row (FIX 3520). Run admission
//! (`llm::run_admission`) and the resident ledger (`llm::budget::resident`)
//! read, charge and set them; the side-table declaration's erase hook calls
//! the erase.
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Which allocation a lease draws on: its id and generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllocationRef {
    pub id: String,
    pub generation: u64,
}

/// The owner's setting for one resident's share of the allocation.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ResidentShare {
    /// The share, in the allocation's unit. `None` is the default share:
    /// what the residents with no share of their own split equally, once the
    /// shares the owner set are taken from the allocation.
    pub units: Option<u64>,
    /// The owner pinned it: past it, new paid work for the resident is
    /// refused. An unpinned share is soft, and spend past it writes an
    /// overdraft receipt.
    pub pinned: bool,
}
