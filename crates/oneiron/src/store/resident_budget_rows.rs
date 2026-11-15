//! The vault's durable resident budget rows (FIX 7767): each resident's
//! share of the host-paid allocation and its depletion on every allocation
//! generation it drew on, keyed by the resident, with the erase an
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

#[doc(hidden)]
pub use oneiron_verb_wire::store::resident_budget_rows::ResidentShare;

/// One resident's share and depletion. Key: id16 (the resident).
pub(crate) const RESIDENTS: SideTable<EntityId, ResidentRow, Named> =
    SideTable::new(&side_table::BUDGET_RESIDENT_SHARE);

/// One resident's setting and the depletion of each captured allocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentRow {
    pub(crate) share: ResidentShare,
    pub(crate) usage: Vec<ResidentAllocationUsage>,
}

/// Charges on one original allocation, including settlements after replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentAllocationUsage {
    pub(crate) allocation: AllocationRef,
    pub(crate) used_units: u64,
    pub(crate) overdraft_units: u64,
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
