//! The vault's durable resident ledger (FIX 7767): what each resident's
//! settled calls charged the allocation generation they ran on, overdrafts
//! apart, beside each resident's share of the host-paid allocation, which is
//! the owner's setting `budget.resident_share`. The run admission reads and
//! charges it through [`ResidentLedger`]; a new allocation generation starts
//! every resident's depletion again, while the owner's share stays.
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::setting_keys::RESIDENT_SHARE;
use crate::llm::run_admission::{AllocationRef, ResidentLedger, ResidentShare, ResidentStanding};
use crate::setting::{SettingChange, SettingScope, SettingSource};
use crate::side_table::SideTableDbs;
use crate::store::resident_budget_rows::{
    RESIDENT_USAGE, ResidentAllocationUsage, ResidentUsageRow,
};
use crate::{EntityId, Result, Vault};

impl ResidentUsageRow {
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

/// One resident on record: its share in force and its depletion.
struct OnRecord {
    resident: EntityId,
    share: ResidentShare,
    row: ResidentUsageRow,
}

/// `resident`'s share in force in `txn`: its own row, else the vault's, else the default split.
fn share_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    resident: EntityId,
) -> Result<crate::setting::Resolved<ResidentShare>> {
    RESIDENT_SHARE.read_in_dbs_txn(dbs, txn, &[SettingScope::Agent(resident)], None)
}

/// Every resident on record in `txn`, with its share in force.
fn on_record_in_txn(dbs: &impl SideTableDbs, txn: &heed::RoTxn<'_>) -> Result<Vec<OnRecord>> {
    RESIDENT_USAGE
        .scan(dbs, txn)?
        .into_iter()
        .map(|(resident, row)| {
            Ok(OnRecord {
                resident,
                share: share_in_txn(dbs, txn, resident)?.value,
                row,
            })
        })
        .collect()
}

fn standing_from_rows(
    rows: &[OnRecord],
    resident: EntityId,
    own_share: ResidentShare,
    allocation: &AllocationRef,
    allocation_units: u64,
) -> ResidentStanding {
    let own = rows
        .iter()
        .find(|on_record| on_record.resident == resident)
        .map(|on_record| on_record.row.clone())
        .unwrap_or_default();
    let set: u64 = rows
        .iter()
        .filter_map(|on_record| on_record.share.units)
        .fold(0, u64::saturating_add);
    let unset = rows
        .iter()
        .filter(|on_record| {
            on_record.resident != resident
                && on_record.share.units.is_none()
                && on_record.row.usage_on(allocation).is_some()
        })
        .count();
    let share_units = own_share.units.unwrap_or_else(|| {
        let residents = u64::try_from(unset).unwrap_or(u64::MAX).saturating_add(1);
        allocation_units.saturating_sub(set) / residents
    });
    ResidentStanding {
        share_units,
        pinned: own_share.pinned,
        used_units: own.used_on(allocation),
    }
}

/// `resident`'s standing on `allocation` in `txn`: its share in force and its depletion.
fn standing_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    resident: EntityId,
    allocation: &AllocationRef,
    allocation_units: u64,
) -> Result<ResidentStanding> {
    let rows = on_record_in_txn(dbs, txn)?;
    let own_share = share_in_txn(dbs, txn, resident)?.value;
    Ok(standing_from_rows(
        &rows,
        resident,
        own_share,
        allocation,
        allocation_units,
    ))
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

    /// Reads the same setting and exact-generation depletion in the caller's
    /// writer, before a native allocation reserves on that same snapshot.
    pub fn standing_in_write_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        resident: EntityId,
        allocation: &AllocationRef,
        allocation_units: u64,
    ) -> Result<ResidentStanding> {
        standing_in_txn(
            &self.vault.store,
            txn,
            resident,
            allocation,
            allocation_units,
        )
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
        let mut row = RESIDENT_USAGE
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
        RESIDENT_USAGE.put(&self.vault.store, txn, &resident, &row)?;
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
        let read = || -> Result<ResidentStanding> {
            let txn = self.vault.store.env.read_txn()?;
            standing_in_txn(
                &self.vault.store,
                &txn,
                resident,
                allocation,
                allocation_units,
            )
        };
        read().unwrap_or_else(|error| {
            tracing::error!(%error, "resident shares unreadable; the default share stands");
            standing_from_rows(
                &[],
                resident,
                ResidentShare::default(),
                allocation,
                allocation_units,
            )
        })
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
/// up, fits. A resident with no share row and no ledger row (a share this
/// vault never set) and the default split (whose room only the host's run
/// admission knows) do not: the park waits for the owner's next share write.
pub(crate) fn resident_share_fits_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    resident: EntityId,
    needed_units: u64,
) -> Result<bool> {
    let share = share_in_txn(&vault.store, txn, resident)?;
    if share.source == SettingSource::Default
        && RESIDENT_USAGE.get(&vault.store, txn, &resident)?.is_none()
    {
        return Ok(false);
    }
    let share = share.value;
    Ok(!share.pinned || share.units.is_some_and(|units| units >= needed_units))
}

/// `budget.resident_share`'s hook, in the write that changed it: a resident's
/// own row puts it on record (an empty ledger row), so the default split counts
/// it; then each resident the change reaches (that one, or every resident on
/// record for the vault's row) has the steps parked on its spent share that the
/// share in force now frees woken (D3). A share still short wakes none.
pub(super) fn record_share_change(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    let residents = match change.scope {
        SettingScope::Agent(resident) => {
            if RESIDENT_USAGE.get(&vault.store, txn, &resident)?.is_none() {
                RESIDENT_USAGE.put(&vault.store, txn, &resident, &ResidentUsageRow::default())?;
            }
            vec![resident]
        }
        _ => RESIDENT_USAGE.scan_keys(&vault.store, txn, &[])?,
    };
    let now_ms = change.at.saturating_mul(1000);
    for resident in residents {
        let share = share_in_txn(&vault.store, txn, resident)?.value;
        crate::llm::wake_resident_share_traps_in_txn(vault, txn, resident, share, now_ms)?;
    }
    Ok(())
}

/// `budget.resident_share`'s after-commit: the woken steps' observers and the
/// proactivity readers hear of it once the share is committed.
pub(super) fn announce_share_change(vault: &Vault) {
    vault.store.notify_attempt_observers();
    vault.store.notify_proactivity_changes();
}

impl Vault {
    /// Every resident's setting and depletion on this exact allocation.
    pub fn resident_shares_on(&self, allocation: &AllocationRef) -> Result<Vec<ResidentShareRead>> {
        let txn = self.store.env.read_txn()?;
        Ok(on_record_in_txn(&self.store, &txn)?
            .into_iter()
            .map(|on_record| {
                let usage = on_record.row.usage_on(allocation);
                ResidentShareRead {
                    resident: on_record.resident,
                    share: on_record.share,
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
        Ok(on_record_in_txn(&self.store, &txn)?
            .into_iter()
            .map(|on_record| {
                // Presentation only. Admission always selects its exact captured ref.
                let latest = on_record
                    .row
                    .usage
                    .iter()
                    .max_by_key(|usage| usage.allocation.generation);
                ResidentShareRead {
                    resident: on_record.resident,
                    share: on_record.share,
                    allocation: latest.map(|usage| usage.allocation.clone()),
                    used_units: latest.map_or(0, |usage| usage.used_units),
                    overdraft_units: latest.map_or(0, |usage| usage.overdraft_units),
                    overdrafts: latest.map_or(0, |usage| usage.overdrafts),
                }
            })
            .collect())
    }
}
