//! The vault's durable resident ledger (FIX 7767): each resident's share of
//! the host-paid allocation in each walletless unit, as the owner set it
//! (Engine RESIDENT-SHARE-UNIT = A), and what its settled calls charged the
//! allocation generation they ran on, overdrafts apart. The run admission
//! reads and charges it through [`ResidentLedger`]; a new allocation
//! generation starts every resident's depletion again, while the owner's
//! share setting stays.
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::llm::run_admission::{
    AllocationRef, LeaseUnit, ResidentLedger, ResidentShare, ResidentShareScope, ResidentStanding,
};
use crate::store::resident_budget_rows::{
    RESIDENTS, ResidentAllocationUsage, ResidentRow, unitless_share_unit,
};
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

    /// The newest generation this resident's calls charged in `unit`.
    /// Presentation only: admission always reads its exact captured ref.
    fn newest_usage_in(&self, unit: &LeaseUnit) -> Option<&ResidentAllocationUsage> {
        self.usage
            .iter()
            .filter(|usage| &usage.unit == unit)
            .max_by_key(|usage| usage.allocation.generation)
    }
}

/// Under [`ResidentShareScope::OwnerSetting`] each resident's share is the
/// owner's in the allocation's `unit`. Under
/// [`ResidentShareScope::DefaultSplit`] no owner's setting counts: every
/// resident on record for the allocation splits all of it, softly.
fn standing_from_rows(
    rows: &[(EntityId, ResidentRow)],
    resident: EntityId,
    allocation: &AllocationRef,
    unit: &LeaseUnit,
    allocation_units: u64,
    scope: ResidentShareScope,
) -> ResidentStanding {
    let owner_setting = scope == ResidentShareScope::OwnerSetting;
    let setting = |row: &ResidentRow| {
        if owner_setting {
            row.share_in(unit.as_str())
        } else {
            ResidentShare::default()
        }
    };
    let own = rows
        .iter()
        .find(|(id, _)| *id == resident)
        .map(|(_, row)| row.clone())
        .unwrap_or_default();
    let set: u64 = rows
        .iter()
        .filter_map(|(_, row)| setting(row).units)
        .fold(0, u64::saturating_add);
    let unset = rows
        .iter()
        .filter(|(id, row)| {
            *id != resident && setting(row).units.is_none() && row.usage_on(allocation).is_some()
        })
        .count();
    let share_units = setting(&own).units.unwrap_or_else(|| {
        let residents = u64::try_from(unset).unwrap_or(u64::MAX).saturating_add(1);
        allocation_units.saturating_sub(set) / residents
    });
    ResidentStanding {
        share_units,
        pinned: setting(&own).pinned,
        used_units: own.used_on(allocation),
    }
}

#[doc(hidden)]
pub use oneiron_records::llm::budget::resident::ResidentShareRead;

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
        unit: &LeaseUnit,
        allocation_units: u64,
        scope: ResidentShareScope,
    ) -> Result<ResidentStanding> {
        let rows = RESIDENTS.scan(&self.vault.store, txn)?;
        Ok(standing_from_rows(
            &rows,
            resident,
            allocation,
            unit,
            allocation_units,
            scope,
        ))
    }

    fn try_charge(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        unit: &LeaseUnit,
        units: u64,
        overdraft_units: u64,
    ) -> Result<()> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.charge_in_write_txn(&mut txn, resident, allocation, unit, units, overdraft_units)?;
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
        unit: &LeaseUnit,
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
                    unit: unit.clone(),
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
    /// A resident's own share is the owner's in the allocation's unit; every
    /// resident with none splits what the owner's shares in that unit leave
    /// of the allocation equally with the others on record for it (CALLS:
    /// the default share), this one counted too. Under
    /// [`ResidentShareScope::DefaultSplit`] (an allocation the host named a
    /// wallet for) every resident on record splits all of it, and none is
    /// pinned.
    fn standing(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        unit: &LeaseUnit,
        allocation_units: u64,
        scope: ResidentShareScope,
    ) -> ResidentStanding {
        let rows = match self.rows() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "resident shares unreadable; the default share stands");
                Vec::new()
            }
        };
        standing_from_rows(&rows, resident, allocation, unit, allocation_units, scope)
    }

    fn charge(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        unit: &LeaseUnit,
        units: u64,
        overdraft_units: u64,
    ) {
        if let Err(error) = self.try_charge(resident, allocation, unit, units, overdraft_units) {
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

/// Whether the share on record for `resident` in `unit` already fits a
/// call that needed a share of `needed_units` in that unit, read in the
/// caller's write: the owner's share write that landed after the run
/// admission refused the call (D3). A share on record that is unpinned, or
/// pinned in units from `needed_units` up, fits. No row (a share this vault
/// never set) and the default split (whose room only the host's run
/// admission knows) do not: the park waits for the owner's next share write.
pub(crate) fn resident_share_fits_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    resident: EntityId,
    unit: &str,
    needed_units: u64,
) -> Result<bool> {
    let Some(row) = RESIDENTS.get(&vault.store, txn, &resident)? else {
        return Ok(false);
    };
    let share = row.share_in(unit);
    Ok(!share.pinned || share.units.is_some_and(|units| units >= needed_units))
}

/// The share on record for `resident` in `unit`, read in the caller's
/// transaction: `None` for a resident this vault never set a share for.
pub(crate) fn resident_share_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    resident: EntityId,
    unit: &str,
) -> Result<Option<ResidentShare>> {
    Ok(RESIDENTS
        .get(&vault.store, txn, &resident)?
        .map(|row| row.share_in(unit)))
}

impl Vault {
    /// Sets `resident`'s share of the host's walletless allocation in `unit`
    /// (FIX 7767; Engine RESIDENT-SHARE-UNIT = A): a share in units, or
    /// `None` for the default split; pinned, it refuses the resident's new
    /// paid work in that unit once a call no longer fits it. Its shares in
    /// other units stay. The owner's act: the caller has checked the owner's
    /// proof. Depletion stays as it stands. In the same write it wakes each
    /// of the resident's steps parked on its spent share in `unit` that the
    /// new share frees; a share still short wakes none (D3).
    pub fn set_resident_share(
        &self,
        resident: EntityId,
        unit: &LeaseUnit,
        share: ResidentShare,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let now_ms = self.store.clock.now_recorded_at().saturating_mul(1000);
        let resumed = self.set_resident_share_in_txn(&mut txn, resident, unit, share, now_ms)?;
        txn.commit()?;
        if !resumed.is_empty() {
            self.store.notify_attempt_observers();
            self.store.notify_proactivity_changes();
        }
        Ok(())
    }

    /// [`Self::set_resident_share`] in the caller's write, at `now_ms`: the
    /// share set, and each of the resident's parks it frees woken. Returns
    /// the tries woken, whose observers the caller notifies once its write
    /// committed. The owner's act: the caller has checked the owner.
    pub(crate) fn set_resident_share_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        resident: EntityId,
        unit: &LeaseUnit,
        share: ResidentShare,
        now_ms: u64,
    ) -> Result<Vec<crate::attempt_queue::AttemptId>> {
        let mut row = RESIDENTS
            .get(&self.store, &*txn, &resident)?
            .unwrap_or_default();
        row.set_share_in(unit, share);
        RESIDENTS.put(&self.store, txn, &resident, &row)?;
        crate::llm::wake_resident_share_traps_in_txn(self, txn, resident, unit, share, now_ms)
    }

    /// Every resident's setting in `unit` and depletion on this exact
    /// allocation, which is in that unit.
    pub fn resident_shares_on(
        &self,
        unit: &LeaseUnit,
        allocation: &AllocationRef,
    ) -> Result<Vec<ResidentShareRead>> {
        let txn = self.store.env.read_txn()?;
        Ok(RESIDENTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(resident, row)| {
                let usage = row.usage_on(allocation);
                ResidentShareRead {
                    resident,
                    share: row.share_in(unit.as_str()),
                    allocation: usage.map(|usage| usage.allocation.clone()),
                    used_units: usage.map_or(0, |usage| usage.used_units),
                    overdraft_units: usage.map_or(0, |usage| usage.overdraft_units),
                    overdrafts: usage.map_or(0, |usage| usage.overdrafts),
                }
            })
            .collect())
    }

    /// Every resident's share in `unit` and depletion on its newest charged
    /// generation in that unit.
    pub fn resident_shares(&self, unit: &LeaseUnit) -> Result<Vec<ResidentShareRead>> {
        let txn = self.store.env.read_txn()?;
        Ok(RESIDENTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(resident, row)| {
                let latest = row.newest_usage_in(unit);
                ResidentShareRead {
                    resident,
                    share: row.share_in(unit.as_str()),
                    allocation: latest.map(|usage| usage.allocation.clone()),
                    used_units: latest.map_or(0, |usage| usage.used_units),
                    overdraft_units: latest.map_or(0, |usage| usage.overdraft_units),
                    overdrafts: latest.map_or(0, |usage| usage.overdrafts),
                }
            })
            .collect())
    }

    /// Every unit a resident's share is on record in: the unit-less stored
    /// share's once any row exists, and each other unit a share is set in.
    pub fn resident_share_units(&self) -> Result<Vec<LeaseUnit>> {
        let txn = self.store.env.read_txn()?;
        let rows = RESIDENTS.scan(&self.store, &txn)?;
        let mut units = BTreeSet::new();
        if !rows.is_empty() {
            units.insert(unitless_share_unit());
        }
        for (_, row) in rows {
            units.extend(row.unit_shares.into_iter().map(|set| set.unit));
        }
        Ok(units.into_iter().collect())
    }
}
