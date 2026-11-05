//! The vault's durable resident budget rows (FIX 7767): each resident's
//! share of the host-paid allocation and its depletion on the allocation
//! generation it last drew on, keyed by the resident, with the erase an
//! actor's deletion makes of its row (FIX 3520). Run admission
//! (`llm::run_admission`) and the resident ledger (`llm::budget::resident`)
//! read, charge and set them; the side-table declaration's erase hook calls
//! the erase.
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

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

/// One resident's share and depletion. Key: id16 (the resident).
pub(crate) const RESIDENTS: SideTable<EntityId, ResidentRow, Named> =
    SideTable::new(&side_table::BUDGET_RESIDENT_SHARE);

/// One resident's row: the owner's share setting, and its depletion on the
/// allocation generation it last drew on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentRow {
    pub(crate) share: ResidentShare,
    /// The allocation the counts below are on; `None` before any charge.
    pub(crate) allocation: Option<AllocationRef>,
    pub(crate) used_units: u64,
    pub(crate) overdraft_units: u64,
    /// How many settled calls charged past the share.
    pub(crate) overdrafts: u64,
}

/// An actor's erase removes its resident row (FIX 3520).
pub(crate) fn erase_resident_share_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    RESIDENTS.delete(&vault.store, txn, actor)?;
    Ok(())
}
