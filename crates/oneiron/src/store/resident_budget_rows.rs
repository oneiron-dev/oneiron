//! The vault's durable resident ledger rows (FIX 7767): what each resident's
//! settled calls charged every allocation generation it drew on, keyed by the
//! resident, with the erase an actor's deletion makes of its row (FIX 3520).
//! The owner's share for each resident is the setting `budget.resident_share`
//! (DESIGN 15-setting-primitive, stage 4). Run admission
//! (`llm::run_admission`) and the resident ledger (`llm::budget::resident`)
//! read and charge them; the side-table declaration's erase hook calls the
//! erase.
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

/// One resident on record and its depletion. Key: id16 (the resident).
pub(crate) const RESIDENT_USAGE: SideTable<EntityId, ResidentUsageRow, Named> =
    SideTable::new(&side_table::BUDGET_RESIDENT_USAGE);

/// The depletion of each allocation a resident's calls were charged on. The
/// owner's share write for a resident puts an empty row, so the default split
/// counts every resident on record, charged yet or not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentUsageRow {
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

/// An actor's erase removes its ledger row (FIX 3520); the setting tables'
/// own scrub removes its share row.
pub(crate) fn erase_resident_usage_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    RESIDENT_USAGE.delete(&vault.store, txn, actor)?;
    Ok(())
}
