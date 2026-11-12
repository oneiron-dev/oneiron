//! The vault's durable resident ledger (FIX 7767): each resident's share of
//! the host-paid allocation, as the owner set it, and what its settled calls
//! charged the allocation generation they ran on, overdrafts apart. The run
//! admission reads and charges it through [`ResidentLedger`]; a new
//! allocation generation starts every resident's depletion again, while the
//! owner's share setting stays.
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::llm::run_admission::{AllocationRef, ResidentLedger, ResidentShare, ResidentStanding};
use crate::store::resident_budget_rows::{RESIDENTS, ResidentAllocationUsage, ResidentRow};
use crate::{EntityId, Result, Vault};

impl ResidentRow {
    fn usage_on(&self, allocation: &AllocationRef) -> Option<&ResidentAllocationUsage> {
        self.usage
            .iter()
            .find(|usage| &usage.allocation == allocation)
    }

    fn used_on(&self, allocation: &AllocationRef) -> u64 {
        self.usage_on(allocation)
            .map_or(0, |usage| usage.used_units)
    }
}

fn standing_from_rows(
    rows: &[(EntityId, ResidentRow)],
    resident: EntityId,
    allocation: &AllocationRef,
    allocation_units: u64,
) -> ResidentStanding {
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
            *id != resident && row.share.units.is_none() && row.usage_on(allocation).is_some()
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

    /// Reads the same setting and exact-generation depletion in the caller's
    /// writer, before a native allocation reserves on that same snapshot.
    pub fn standing_in_write_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        resident: EntityId,
        allocation: &AllocationRef,
        allocation_units: u64,
    ) -> Result<ResidentStanding> {
        let rows = RESIDENTS.scan(&self.vault.store, txn)?;
        Ok(standing_from_rows(
            &rows,
            resident,
            allocation,
            allocation_units,
        ))
    }

    fn try_charge(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        units: u64,
        overdraft_units: u64,
    ) -> Result<()> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.charge_in_write_txn(&mut txn, resident, allocation, units, overdraft_units)?;
        txn.commit()?;
        Ok(())
    }

    /// Charges the resident in this vault's caller-owned writer. The caller
    /// can commit a hold's terminal state with its charge, once, in that same
    /// writer. Repeated calls still charge repeatedly; this is not a deduper.
    pub fn charge_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        resident: EntityId,
        allocation: &AllocationRef,
        units: u64,
        overdraft_units: u64,
    ) -> Result<()> {
        let mut row = RESIDENTS
            .get(&self.vault.store, txn, &resident)?
            .unwrap_or_default();
        let index = match row
            .usage
            .iter()
            .position(|usage| &usage.allocation == allocation)
        {
            Some(index) => index,
            None => {
                row.usage.push(ResidentAllocationUsage {
                    allocation: allocation.clone(),
                    used_units: 0,
                    overdraft_units: 0,
                    overdrafts: 0,
                });
                row.usage.len() - 1
            }
        };
        let usage = &mut row.usage[index];
        usage.used_units = usage.used_units.saturating_add(units);
        usage.overdraft_units = usage.overdraft_units.saturating_add(overdraft_units);
        if overdraft_units > 0 {
            usage.overdrafts = usage.overdrafts.saturating_add(1);
        }
        RESIDENTS.put(&self.vault.store, txn, &resident, &row)?;
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
        standing_from_rows(&rows, resident, allocation, allocation_units)
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

/// Whether `share` frees a call of its resident that needed a share of
/// `needed_units`, in the allocation's unit (D3): an unpinned share never
/// refuses, and a pinned share in units fits it from `needed_units` up. The
/// default split's room depends on the host's live allocation, which only its
/// run admission reads, so a call under it meets that admission again.
pub(crate) const fn resident_share_frees(share: ResidentShare, needed_units: u64) -> bool {
    if !share.pinned {
        return true;
    }
    match share.units {
        Some(units) => units >= needed_units,
        None => true,
    }
}

/// Whether the share on record for `resident` already fits a call that
/// needed a share of `needed_units`, read in the caller's write: the owner's
/// share write that landed after the run admission refused the call (D3). A
/// share on record that is unpinned, or pinned in units from `needed_units`
/// up, fits. No row (a share this vault never set) and the default split
/// (whose room only the host's run admission knows) do not: the park waits
/// for the owner's next share write.
pub(crate) fn resident_share_fits_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    resident: EntityId,
    needed_units: u64,
) -> Result<bool> {
    let Some(row) = RESIDENTS.get(&vault.store, txn, &resident)? else {
        return Ok(false);
    };
    Ok(!row.share.pinned || row.share.units.is_some_and(|units| units >= needed_units))
}

impl Vault {
    /// Sets `resident`'s share of the host-paid allocation (FIX 7767): a
    /// share in units, or `None` for the default split; pinned, it refuses
    /// the resident's new paid work once a call no longer fits it. The
    /// owner's act: the caller has checked the owner's proof. Depletion
    /// stays as it stands. In the same write it wakes each of the
    /// resident's steps parked on its spent share that the new share frees;
    /// a share still short wakes none (D3).
    pub fn set_resident_share(&self, resident: EntityId, share: ResidentShare) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut row = RESIDENTS
            .get(&self.store, &txn, &resident)?
            .unwrap_or_default();
        row.share = share;
        RESIDENTS.put(&self.store, &mut txn, &resident, &row)?;
        let now_ms = self.store.clock.now_recorded_at().saturating_mul(1000);
        let resumed =
            crate::llm::wake_resident_share_traps_in_txn(self, &mut txn, resident, share, now_ms)?;
        txn.commit()?;
        if !resumed.is_empty() {
            self.store.notify_attempt_observers();
            self.store.notify_proactivity_changes();
        }
        Ok(())
    }

    /// Every resident's setting and depletion on this exact allocation.
    pub fn resident_shares_on(&self, allocation: &AllocationRef) -> Result<Vec<ResidentShareRead>> {
        let txn = self.store.env.read_txn()?;
        Ok(RESIDENTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(resident, row)| {
                let usage = row.usage_on(allocation);
                ResidentShareRead {
                    resident,
                    share: row.share,
                    allocation: usage.map(|usage| usage.allocation.clone()),
                    used_units: usage.map_or(0, |usage| usage.used_units),
                    overdraft_units: usage.map_or(0, |usage| usage.overdraft_units),
                    overdrafts: usage.map_or(0, |usage| usage.overdrafts),
                }
            })
            .collect())
    }

    /// Every resident's share and depletion on its newest charged generation.
    pub fn resident_shares(&self) -> Result<Vec<ResidentShareRead>> {
        let txn = self.store.env.read_txn()?;
        Ok(RESIDENTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(resident, row)| {
                // Presentation only. Admission always selects its exact captured ref.
                let latest = row
                    .usage
                    .iter()
                    .max_by_key(|usage| usage.allocation.generation);
                ResidentShareRead {
                    resident,
                    share: row.share,
                    allocation: latest.map(|usage| usage.allocation.clone()),
                    used_units: latest.map_or(0, |usage| usage.used_units),
                    overdraft_units: latest.map_or(0, |usage| usage.overdraft_units),
                    overdrafts: latest.map_or(0, |usage| usage.overdrafts),
                }
            })
            .collect())
    }
}
