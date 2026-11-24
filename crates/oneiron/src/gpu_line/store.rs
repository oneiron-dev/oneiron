//! The GPU line's stored rows (design pass 32, sections 3.1, 3.2 and 4.1):
//! one `GPU_LINE` row per lane project and one `GPU_LINE_PERIOD` record per
//! period, minted at the period's first write and never written again.
//!
//! The mint reads the team receipts the lane's arms wrote
//! (`team_ref = "arm:<arm hex>:r<rung>"`, `project` = the family): every
//! outcome stamped inside the window counts, a win or a loss, with the
//! receipt's settled seconds as cost. A promote that waits for its review
//! has no outcome yet and counts for nothing (LE-3 = A). An invalid rung
//! writes no receipt; its seconds join `invalid_secs` once the arm rows hold
//! verdicts (row M2-E), until then a family's tally has none.
use std::collections::BTreeMap;

use super::fold::{GpuLine, GpuLinePeriod};
use super::mint::{MintError, SettledTally, mint_period};
use crate::llm::run_admission::{Allocation, AllocationRef, LeaseUnit};
use crate::side_table::{self, Named, SideTable};
use crate::team::{ReceiptScan, team_receipts_in_txn};
use crate::{EntityId, Vault};

const LINES: SideTable<EntityId, GpuLine, Named> = SideTable::new(&side_table::GPU_LINE);
const PERIODS: SideTable<(EntityId, u32), GpuLinePeriod, Named> =
    SideTable::new(&side_table::GPU_LINE_PERIOD);

/// The start of the team reference of every receipt an arm's rung writes.
pub const ARM_TEAM_REF_PREFIX: &str = "arm:";

/// The id of the host allocation a line's wallet is installed as; its
/// generation is the period index plus one.
#[must_use]
pub fn line_allocation_id(project: &EntityId) -> String {
    format!("gpu-line:{}", project.to_hex())
}

impl GpuLine {
    /// The host allocation that funds period `index` (LM-1): the period's
    /// allowance in `gpu_seconds` on the line's wallet. Each period is a new
    /// generation, so unused room lapses with its period and holds made in
    /// an older one still settle there.
    #[must_use]
    pub fn period_allocation(&self, index: u32) -> Allocation {
        Allocation {
            reference: AllocationRef {
                id: line_allocation_id(&self.project),
                generation: u64::from(index) + 1,
            },
            units: self.allowance_units,
            unit: self.unit.clone(),
            wallet: Some(self.wallet.clone()),
        }
    }
}

/// The lease unit of every GPU line.
#[must_use]
pub fn gpu_seconds() -> LeaseUnit {
    LeaseUnit::new(super::mint::GPU_SECONDS).expect("a valid lease unit")
}

/// The line of lane project `project`, if the owner set one.
///
/// # Errors
///
/// A store read failure.
pub fn line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
) -> crate::Result<Option<GpuLine>> {
    LINES.get(&vault.store, txn, project)
}

/// Writes `line` as its project's row.
pub(crate) fn put_line_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    line: &GpuLine,
) -> crate::Result<()> {
    LINES.put(&vault.store, wtxn, &line.project, line)
}

/// The stored record of period `index` of `project`'s line, if it was
/// minted.
///
/// # Errors
///
/// A store read failure.
pub fn stored_period_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
    index: u32,
) -> crate::Result<Option<GpuLinePeriod>> {
    PERIODS.get(&vault.store, txn, &(*project, index))
}

/// What the outcomes settled inside the window of period `index` say about
/// each family seated on `line`.
///
/// # Errors
///
/// A store read failure.
pub fn settled_tallies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &GpuLine,
    index: u32,
) -> crate::Result<BTreeMap<EntityId, SettledTally>> {
    let mut tallies: BTreeMap<EntityId, SettledTally> = BTreeMap::new();
    let Some((from, to)) = line.window_of(index) else {
        return Ok(tallies);
    };
    for receipt in team_receipts_in_txn(vault, txn, ReceiptScan::AllScopes(None))? {
        let (Some(family), Some(outcome)) = (receipt.project, receipt.outcome.as_ref()) else {
            continue;
        };
        if !receipt.team_ref.starts_with(ARM_TEAM_REF_PREFIX)
            || line.seat(&family).is_none()
            || outcome.at < from
            || outcome.at >= to
        {
            continue;
        }
        let tally = tallies.entry(family).or_default();
        if outcome.success {
            tally.wins += 1;
        } else {
            tally.losses += 1;
        }
        let spent = receipt
            .spend
            .filter(|spend| spend.is_finite() && *spend > 0.0);
        // Settled seconds are whole; the cast floors a stray fraction.
        tally.cost_secs = tally
            .cost_secs
            .saturating_add(spent.map_or(0, |spend| spend as u64));
    }
    Ok(tallies)
}

/// The record of the period of `line` that holds `now_ms`: the stored one,
/// or the mint's at this first touch, written once. `None` before period 0
/// starts. Every write door of the lane economy calls it before it writes,
/// so a record always reads the line as it stood when its period began.
///
/// # Errors
///
/// A store failure as `Ok(Err)`'s outer error; [`MintError`] when the line
/// names a rule the mint cannot fund.
pub fn period_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    line: &GpuLine,
    now_ms: u64,
) -> crate::Result<Result<Option<GpuLinePeriod>, MintError>> {
    let Some(index) = line.period_index(now_ms) else {
        return Ok(Ok(None));
    };
    if let Some(stored) = stored_period_in_txn(vault, wtxn, &line.project, index)? {
        return Ok(Ok(Some(stored)));
    }
    let tallies = settled_tallies_in_txn(vault, wtxn, line, index)?;
    let record = match mint_period(line, index, &tallies, now_ms) {
        Ok(record) => record,
        Err(refusal) => return Ok(Err(refusal)),
    };
    PERIODS.put(&vault.store, wtxn, &(line.project, index), &record)?;
    Ok(Ok(Some(record)))
}

/// The record of the period of `line` that holds `now_ms` without writing:
/// the stored one (`true`), or the mint's preview (`false`), which is the
/// record the next write door mints while the settled outcomes stay as
/// they are. `None` before period 0 starts.
///
/// # Errors
///
/// A store read failure as the outer error; [`MintError`] as the inner.
pub fn period_view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &GpuLine,
    now_ms: u64,
) -> crate::Result<Result<Option<(GpuLinePeriod, bool)>, MintError>> {
    let Some(index) = line.period_index(now_ms) else {
        return Ok(Ok(None));
    };
    if let Some(stored) = stored_period_in_txn(vault, txn, &line.project, index)? {
        return Ok(Ok(Some((stored, true))));
    }
    let tallies = settled_tallies_in_txn(vault, txn, line, index)?;
    Ok(mint_period(line, index, &tallies, now_ms).map(|record| Some((record, false))))
}

impl Vault {
    /// The GPU line of lane project `project`, if the owner set one.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn gpu_line(&self, project: &EntityId) -> crate::Result<Option<GpuLine>> {
        line_in_txn(self, &self.store.env.read_txn()?, project)
    }

    /// Every GPU line of the vault, by project.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn gpu_lines(&self) -> crate::Result<Vec<GpuLine>> {
        let txn = self.store.env.read_txn()?;
        Ok(LINES
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, line)| line)
            .collect())
    }

    /// The minted record of period `index` of `project`'s line.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn gpu_line_period(
        &self,
        project: &EntityId,
        index: u32,
    ) -> crate::Result<Option<GpuLinePeriod>> {
        stored_period_in_txn(self, &self.store.env.read_txn()?, project, index)
    }
}

/// Takes the erased actor out of every line: who set its policy and who
/// seated each family (the side table's actor scrub). Period records name no
/// actor.
pub(crate) fn erase_line_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (project, mut line) in LINES.scan(&vault.store, wtxn)? {
        let mut changed = false;
        if line.set_by == Some(*actor) {
            line.set_by = None;
            changed = true;
        }
        for seat in &mut line.families {
            if seat.admitted_by == Some(*actor) {
                seat.admitted_by = None;
                changed = true;
            }
        }
        if changed {
            line.revision += 1;
            LINES.put(&vault.store, wtxn, &project, &line)?;
        }
    }
    Ok(())
}
