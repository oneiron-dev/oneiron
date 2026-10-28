//! The vault's durable resident ledger (FIX 7767): each resident's share of
//! the host-paid allocation, as the owner set it, and what its settled calls
//! charged the allocation generation they ran on, overdrafts apart. The run
//! admission reads and charges it through [`ResidentLedger`]; a new
//! allocation generation starts every resident's depletion again, while the
//! owner's share setting stays.
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::llm::run_admission::{AllocationRef, ResidentLedger, ResidentShare, ResidentStanding};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// One resident's share and depletion. Key: id16 (the resident).
const RESIDENTS: SideTable<EntityId, ResidentRow, Named> =
    SideTable::new(&side_table::BUDGET_RESIDENT_SHARE);

/// One resident's row: the owner's share setting, and its depletion on the
/// allocation generation it last drew on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentRow {
    share: ResidentShare,
    /// The allocation the counts below are on; `None` before any charge.
    allocation: Option<AllocationRef>,
    used_units: u64,
    overdraft_units: u64,
    /// How many settled calls charged past the share.
    overdrafts: u64,
}

impl ResidentRow {
    /// The counts on `allocation`: none once a newer generation is live.
    fn used_on(&self, allocation: &AllocationRef) -> u64 {
        if self.allocation.as_ref() == Some(allocation) {
            self.used_units
        } else {
            0
        }
    }
}

/// One resident's share and depletion, as the owner reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentShareRead {
    pub resident: EntityId,
    pub share: ResidentShare,
    /// The allocation the counts are on; `None` before any charge.
    pub allocation: Option<AllocationRef>,
    pub used_units: u64,
    pub overdraft_units: u64,
    pub overdrafts: u64,
}

/// The run admission's resident ledger over one vault's rows.
pub struct VaultResidentLedger {
    vault: Arc<Vault>,
}

impl VaultResidentLedger {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Arc<Self> {
        Arc::new(Self { vault })
    }

    fn rows(&self) -> Result<Vec<(EntityId, ResidentRow)>> {
        let txn = self.vault.store.env.read_txn()?;
        RESIDENTS.scan(&self.vault.store, &txn)
    }

    fn try_charge(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        units: u64,
        overdraft_units: u64,
    ) -> Result<()> {
        let mut txn = self.vault.store.env.write_txn()?;
        let mut row = RESIDENTS
            .get(&self.vault.store, &txn, &resident)?
            .unwrap_or_default();
        if row.allocation.as_ref() != Some(allocation) {
            row.allocation = Some(allocation.clone());
            row.used_units = 0;
            row.overdraft_units = 0;
            row.overdrafts = 0;
        }
        row.used_units = row.used_units.saturating_add(units);
        row.overdraft_units = row.overdraft_units.saturating_add(overdraft_units);
        if overdraft_units > 0 {
            row.overdrafts = row.overdrafts.saturating_add(1);
        }
        RESIDENTS.put(&self.vault.store, &mut txn, &resident, &row)?;
        txn.commit()?;
        Ok(())
    }
}

impl ResidentLedger for VaultResidentLedger {
    /// A resident's own share is the owner's; every resident with none
    /// splits what the owner's shares leave of the allocation equally with
    /// the others on record for it (CALLS: the default share), this one
    /// counted too.
    fn standing(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        allocation_units: u64,
    ) -> ResidentStanding {
        let rows = match self.rows() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "resident shares unreadable; the default share stands");
                Vec::new()
            }
        };
        let own = rows
            .iter()
            .find(|(id, _)| *id == resident)
            .map(|(_, row)| row.clone())
            .unwrap_or_default();
        let set: u64 = rows
            .iter()
            .filter_map(|(_, row)| row.share.units)
            .fold(0, u64::saturating_add);
        let unset = rows
            .iter()
            .filter(|(id, row)| {
                *id != resident
                    && row.share.units.is_none()
                    && row.allocation.as_ref() == Some(allocation)
            })
            .count();
        let share_units = own.share.units.unwrap_or_else(|| {
            let residents = u64::try_from(unset).unwrap_or(u64::MAX).saturating_add(1);
            allocation_units.saturating_sub(set) / residents
        });
        ResidentStanding {
            share_units,
            pinned: own.share.pinned,
            used_units: own.used_on(allocation),
        }
    }

    fn charge(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        units: u64,
        overdraft_units: u64,
    ) {
        if let Err(error) = self.try_charge(resident, allocation, units, overdraft_units) {
            tracing::error!(%error, units, "a resident's charge was not kept");
        }
    }
}

impl Vault {
    /// Sets `resident`'s share of the host-paid allocation (FIX 7767): a
    /// share in units, or `None` for the default split; pinned, it refuses
    /// the resident's new paid work once a call no longer fits it. The
    /// owner's act: the caller has checked the owner's proof. Depletion
    /// stays as it stands.
    pub fn set_resident_share(&self, resident: EntityId, share: ResidentShare) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut row = RESIDENTS
            .get(&self.store, &txn, &resident)?
            .unwrap_or_default();
        row.share = share;
        RESIDENTS.put(&self.store, &mut txn, &resident, &row)?;
        txn.commit()?;
        Ok(())
    }

    /// Every resident's share and depletion on record, by resident.
    pub fn resident_shares(&self) -> Result<Vec<ResidentShareRead>> {
        let txn = self.store.env.read_txn()?;
        Ok(RESIDENTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(resident, row)| ResidentShareRead {
                resident,
                share: row.share,
                allocation: row.allocation,
                used_units: row.used_units,
                overdraft_units: row.overdraft_units,
                overdrafts: row.overdrafts,
            })
            .collect())
    }
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
