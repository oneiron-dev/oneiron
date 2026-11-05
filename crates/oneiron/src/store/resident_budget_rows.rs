//! Core half of `store::resident_budget_rows`: its store-layer items live in `oneiron_store::resident_budget_rows` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::resident_budget_rows::*;

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

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
