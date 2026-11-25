//! The GPU line's stored rows (design pass 32, sections 3.1, 3.2 and 4.1):
//! one `GPU_LINE` row per lane project and one `GPU_LINE_PERIOD` record per
//! period, minted at the period's first write and never written again.
//!
//! The mint reads the line's own rows and nothing else (section 4.3): the
//! tally of each family's results and cost inside the window comes from the
//! line's arm rows and claims. Row M2-A defines its shape
//! ([`SettledTally`]); row M2-E fills it. Until then every family scores the
//! base rate. No generic team receipt, no seed and no unattributed seconds
//! (EM-15) is an input.
use std::collections::BTreeMap;

use rand_core::RngCore;

use super::cohort::cohort_seed_commit;
use super::fold::{GpuLine, GpuLinePeriod, PeriodAllocation, PeriodClockError};
use super::mint::{MintError, SettledTally, mint_period};
use crate::llm::run_admission::{Allocation, AllocationRef, LeaseUnit};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

const LINES: SideTable<EntityId, GpuLine, Named> = SideTable::new(&side_table::GPU_LINE);
const PERIODS: SideTable<(EntityId, u32), GpuLinePeriod, Named> =
    SideTable::new(&side_table::GPU_LINE_PERIOD);

/// Whether a stored `GPU_LINE_PERIOD` value holds a cohort seed still sealed at `now_ms`: the
/// get view withholds the seed until the period's `end_ms` (`doors::view_in_txn`), and the
/// whole-vault export withholds the whole row until then (Engine ANSWER LE-ARCHIVE-PERIOD-SEED
/// = A). Bytes that do not read as a period count as sealed.
pub(crate) fn period_row_seals_seed(value: &[u8], now_ms: u64) -> bool {
    match PERIODS.decode_value(value) {
        Ok(period) => period.cohort_seed.is_some() && now_ms < period.end_ms,
        Err(_) => true,
    }
}

impl PeriodAllocation {
    /// The host allocation the installer installs for this period.
    #[must_use]
    pub fn allocation(&self, unit: LeaseUnit) -> Allocation {
        Allocation {
            reference: AllocationRef {
                id: self.id.clone(),
                generation: self.generation,
            },
            units: self.units,
            unit,
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

/// Whether a GPU line names the offer `offer`. Such an offer is line-managed: a job starts on
/// it only through the one start gate, under a unit claim of a line (design pass 32 r2, 5.3).
///
/// # Errors
///
/// A store read failure.
pub fn offer_line_managed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    offer: &str,
) -> crate::Result<bool> {
    Ok(LINES
        .scan(&vault.store, txn)?
        .iter()
        .any(|(_, line)| line.offers.iter().any(|name| name == offer)))
}

/// Writes `line` as its project's row.
pub(crate) fn put_line_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    line: &GpuLine,
) -> crate::Result<()> {
    LINES.put(&vault.store, wtxn, &line.project, line)
}

/// Whether the vault holds a line for a project other than `project`: one
/// account holds one line until row M2-I lands.
pub(super) fn other_line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
) -> crate::Result<bool> {
    Ok(LINES
        .scan_keys(&vault.store, txn, &[])?
        .iter()
        .any(|key| key != project))
}

/// Whether `family` holds a live seat on a line other than `project`'s.
pub(super) fn seated_elsewhere_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
    family: &EntityId,
) -> crate::Result<bool> {
    Ok(LINES
        .scan(&vault.store, txn)?
        .iter()
        .any(|(key, line)| key != project && line.seat(family).is_some()))
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

/// [`MintError::BehindMintedPeriod`] when `project`'s line already minted a
/// period after `index`: the vault clock went back, and a period once passed
/// never reopens, minted or not.
fn behind_minted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
    index: u32,
) -> crate::Result<Option<MintError>> {
    Ok(newest_minted_in_txn(vault, txn, project)?
        .filter(|newest| index < *newest)
        .map(|newest| MintError::BehindMintedPeriod { index, newest }))
}

/// The index of the newest period `project`'s line minted, if any.
///
/// # Errors
///
/// A store read failure.
pub(super) fn newest_minted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
) -> crate::Result<Option<u32>> {
    Ok(PERIODS
        .scan_keys(&vault.store, txn, project.as_bytes())?
        .last()
        .map(|(_, index)| *index))
}

/// What the line's own rows inside the window of period `index` say about
/// each family seated on `line`, following a seat through `replaces` (the
/// family's project is the same). The join over arm rows and claims is row
/// M2-E's; until it lands no family has a tally.
///
/// # Errors
///
/// A store read failure.
pub fn settled_tallies_in_txn(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
    _line: &GpuLine,
    _index: u32,
) -> crate::Result<BTreeMap<EntityId, SettledTally>> {
    Ok(BTreeMap::new())
}

/// The period of `line` that holds `now_ms`: `Ok(None)` before period 0.
fn current_index(line: &GpuLine, now_ms: u64) -> Result<Option<u32>, MintError> {
    match line.period_index(now_ms) {
        Ok(index) => Ok(Some(index)),
        Err(PeriodClockError::NotBegun) => Ok(None),
        Err(PeriodClockError::OutOfRange) => Err(MintError::PeriodOutOfRange),
    }
}

/// A line and the record of its period that holds now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedLine {
    pub line: GpuLine,
    /// `None` before period 0 starts.
    pub period: Option<GpuLinePeriod>,
}

/// Mints first (section 4.1): reads `project`'s line and the record of its
/// period that holds `now_ms`, minting that record at this first write and
/// marking the new-idea seats it no longer funds as lapsed. Every write door
/// of the lane economy calls it before anything else, so a record always
/// reads the line as it stood when its period began, and no edit reaches a
/// period that has begun. `Ok(Ok(None))` when no line is set.
///
/// # Errors
///
/// A store failure as the outer error; [`MintError`] when the clock is past
/// the last period, falls in a period before the newest one minted, or the
/// mint cannot fund its floors or rules.
pub fn mint_first_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    project: &EntityId,
    now_ms: u64,
) -> crate::Result<Result<Option<MintedLine>, MintError>> {
    let Some(mut line) = line_in_txn(vault, wtxn, project)? else {
        return Ok(Ok(None));
    };
    let index = match current_index(&line, now_ms) {
        Ok(Some(index)) => index,
        Ok(None) => return Ok(Ok(Some(MintedLine { line, period: None }))),
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(behind) = behind_minted_in_txn(vault, wtxn, project, index)? {
        return Ok(Err(behind));
    }
    if let Some(stored) = stored_period_in_txn(vault, wtxn, project, index)? {
        return Ok(Ok(Some(MintedLine {
            line,
            period: Some(stored),
        })));
    }
    let tallies = settled_tallies_in_txn(vault, wtxn, &line, index)?;
    let mut record = match mint_period(&line, index, &tallies, now_ms) {
        Ok(record) => record,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // A two-rule period draws its cohort seed now (section 4.4). The seed and
    // its commit are outside the economic digest; the get view withholds the
    // seed until the period ends.
    if record.tables.len() == 2 {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        record.cohort_seed_commit = Some(cohort_seed_commit(&seed));
        record.cohort_seed = Some(seed);
    }
    PERIODS.put(&vault.store, wtxn, &(*project, index), &record)?;
    let mut lapsed = false;
    for seat in &mut line.families {
        if seat.lapsed_from_period.is_none()
            && let Some(lapse) = seat.lapses_from(line.budget.new_idea_periods)
            && lapse <= index
        {
            seat.lapsed_from_period = Some(lapse);
            lapsed = true;
        }
    }
    if lapsed {
        line.revision += 1;
        put_line_in_txn(vault, wtxn, &line)?;
    }
    Ok(Ok(Some(MintedLine {
        line,
        period: Some(record),
    })))
}

/// The record of the period of `line` that holds `now_ms` without writing:
/// the stored one (`preview: false`), or the mint's preview (`true`), which
/// is the record the next write door mints while the line's rows stay as
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
    let index = match current_index(line, now_ms) {
        Ok(Some(index)) => index,
        Ok(None) => return Ok(Ok(None)),
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(behind) = behind_minted_in_txn(vault, txn, &line.project, index)? {
        return Ok(Err(behind));
    }
    if let Some(stored) = stored_period_in_txn(vault, txn, &line.project, index)? {
        return Ok(Ok(Some((stored, false))));
    }
    let tallies = settled_tallies_in_txn(vault, txn, line, index)?;
    Ok(mint_period(line, index, &tallies, now_ms).map(|record| Some((record, true))))
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

/// Takes the erased actor out of every line: who set its policy, who seated
/// each family and who graduated it (the side table's actor scrub). Period
/// records name no actor.
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
            if let Some(graduation) = &mut seat.graduated
                && graduation.by == Some(*actor)
            {
                graduation.by = None;
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
