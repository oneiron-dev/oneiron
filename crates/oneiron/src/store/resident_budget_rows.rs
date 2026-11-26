//! The vault's durable resident budget rows (FIX 7767): each resident's
//! share of the host-paid allocation and its depletion on every allocation
//! generation it drew on, keyed by the resident, with the erase an
//! actor's deletion makes of its row (FIX 3520). Run admission
//! (`llm::run_admission`) and the resident ledger (`llm::budget::resident`)
//! read, charge and set them; the side-table declaration's erase hook calls
//! the erase.
use serde::{Deserialize, Serialize};

use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

#[doc(hidden)]
pub use oneiron_records::store::resident_budget_rows::AllocationRef;

#[doc(hidden)]
pub use oneiron_verb_wire::store::resident_budget_rows::ResidentShare;

/// One resident's share and depletion. Key: id16 (the resident).
pub(crate) const RESIDENTS: SideTable<EntityId, ResidentRow, Named> =
    SideTable::new(&side_table::BUDGET_RESIDENT_SHARE);

/// The unit of a share or a charge stored before shares named a unit: the
/// host's money unit (Engine RESIDENT-SHARE-UNIT = A, 25 Nov 19:27).
pub const UNITLESS_SHARE_UNIT: &str = "micro_usd";

pub(crate) fn unitless_share_unit() -> LeaseUnit {
    LeaseUnit::new(UNITLESS_SHARE_UNIT).expect("micro_usd is a lease unit")
}

/// One resident's settings and the depletion of each captured allocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentRow {
    /// The share in [`UNITLESS_SHARE_UNIT`]; a row stored before shares
    /// named a unit holds only this one.
    pub(crate) share: ResidentShare,
    /// The share in each other walletless unit the owner set one in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unit_shares: Vec<ResidentUnitShare>,
    pub(crate) usage: Vec<ResidentAllocationUsage>,
}

/// The owner's share of one resident in one unit other than
/// [`UNITLESS_SHARE_UNIT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentUnitShare {
    pub(crate) unit: LeaseUnit,
    pub(crate) share: ResidentShare,
}

impl ResidentRow {
    /// The owner's share in `unit`: the default split when none is set.
    pub(crate) fn share_in(&self, unit: &str) -> ResidentShare {
        if unit == UNITLESS_SHARE_UNIT {
            return self.share;
        }
        self.unit_shares
            .iter()
            .find(|set| set.unit.as_str() == unit)
            .map_or_else(ResidentShare::default, |set| set.share)
    }

    /// Sets the owner's share in `unit`.
    pub(crate) fn set_share_in(&mut self, unit: &LeaseUnit, share: ResidentShare) {
        if unit.as_str() == UNITLESS_SHARE_UNIT {
            self.share = share;
            return;
        }
        match self.unit_shares.iter_mut().find(|set| &set.unit == unit) {
            Some(set) => set.share = share,
            None => self.unit_shares.push(ResidentUnitShare {
                unit: unit.clone(),
                share,
            }),
        }
    }
}

/// Charges on one original allocation, including settlements after replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentAllocationUsage {
    pub(crate) allocation: AllocationRef,
    /// The allocation's unit; a charge stored before charges named one is
    /// in [`UNITLESS_SHARE_UNIT`].
    #[serde(default = "unitless_share_unit")]
    pub(crate) unit: LeaseUnit,
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
