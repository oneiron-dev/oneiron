//! Judge swaps as projections (ARCH-0079 #model-swaps, ARCH-0003 #learning).
//!
//! A judge swap converts history through the overlap's score map: the new
//! judge scored the same cases as the old one, and the fitted map turns an old
//! score into the new judge's scale. The conversion is a versioned projection
//! over the evidence; no receipt and no evidence row is rewritten, and
//! withdrawing the conversion restores the old reading. The judge is never in
//! the cell key, so a swap never forks a cell.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::estimate::Estimate;
use super::evidence::EVIDENCE;
use super::project::project_cell_in_txn;

/// One-sided 95% normal quantile for the divergence interval.
const WILSON_Z: f64 = 1.645;

/// Fewest overlap pairs a score map is fitted from.
const MIN_OVERLAP_PAIRS: usize = 2;

/// Conversions in force. Key: the old judge revision.
const CONVERSION: SideTable<String, JudgeConversion, Named> =
    SideTable::new(&side_table::LEARNING_JUDGE_CONVERSION);

/// The score map from an old judge's scale to its successor's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeConversion {
    pub from_judge: String,
    pub to_judge: String,
    /// Monotone `(old, new)` knots, ascending in `old`; scores between knots
    /// interpolate and scores past the ends clamp to the end knot.
    pub points: Vec<(f64, f64)>,
    /// How many overlap cases the map was fitted from.
    pub overlap_cases: u32,
    pub at: u64,
    /// Whether this map's chain from `from_judge` through the stored
    /// conversions resolves or loops; reporting only, recomputed on every
    /// record/withdraw — recording still succeeds when cyclic.
    pub chain: ConversionChainStatus,
}

impl JudgeConversion {
    /// Maps an old-judge score onto the new judge's scale.
    #[must_use]
    pub fn map(&self, x: f64) -> f64 {
        let Some(first) = self.points.first() else {
            return x;
        };
        if x <= first.0 {
            return first.1;
        }
        for pair in self.points.windows(2) {
            let ((x0, y0), (x1, y1)) = (pair[0], pair[1]);
            if x <= x1 {
                if x1 == x0 {
                    return y1;
                }
                return y0 + (x - x0) * (y1 - y0) / (x1 - x0);
            }
        }
        self.points.last().map_or(x, |last| last.1)
    }
}

/// Fits a monotone score map from overlap pairs `(old score, new score)` by
/// pooling adjacent violators: pairs sorted by old score, equal old scores
/// averaged, then any knot that would make the map decrease merged with its
/// neighbour.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for fewer than two pairs or a non-finite score.
pub fn fit_score_map(pairs: &[(f64, f64)]) -> Result<Vec<(f64, f64)>> {
    if pairs.len() < MIN_OVERLAP_PAIRS {
        return Err(Error::InvalidClaimBody(
            "a judge conversion is fitted from at least two overlap cases",
        ));
    }
    if pairs.iter().any(|(a, b)| !a.is_finite() || !b.is_finite()) {
        return Err(Error::InvalidClaimBody("overlap scores are finite"));
    }
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    // Blocks of (sum old, sum new, count).
    let mut blocks: Vec<(f64, f64, f64)> = Vec::new();
    for (old, new) in sorted {
        if let Some(last) = blocks.last_mut()
            && (last.0 / last.2 - old).abs() < f64::EPSILON
        {
            last.0 += old;
            last.1 += new;
            last.2 += 1.0;
            continue;
        }
        blocks.push((old, new, 1.0));
        while blocks.len() >= 2 {
            let n = blocks.len();
            let (prev, cur) = (blocks[n - 2], blocks[n - 1]);
            if prev.1 / prev.2 <= cur.1 / cur.2 {
                break;
            }
            blocks.truncate(n - 2);
            blocks.push((prev.0 + cur.0, prev.1 + cur.1, prev.2 + cur.2));
        }
    }
    Ok(blocks
        .into_iter()
        .map(|(sum_old, sum_new, n)| (sum_old / n, sum_new / n))
        .collect())
}

/// Records that `to_judge` replaces `from_judge`, fitted from the overlap
/// `pairs`, and re-projects every cell the old judge scored. Recording again
/// for the same old judge replaces the map.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a self-conversion, a bad revision or too
/// few pairs; storage errors.
pub fn record_judge_conversion(
    vault: &Vault,
    from_judge: &str,
    to_judge: &str,
    pairs: &[(f64, f64)],
    now: u64,
) -> Result<JudgeConversion> {
    if from_judge == to_judge || from_judge.is_empty() || to_judge.is_empty() {
        return Err(Error::InvalidClaimBody(
            "a judge conversion names two distinct judge revisions",
        ));
    }
    if from_judge.len() > 256 || to_judge.len() > 256 {
        return Err(Error::InvalidClaimBody(
            "a judge revision is at most 256 bytes",
        ));
    }
    let mut conversion = JudgeConversion {
        from_judge: from_judge.to_owned(),
        to_judge: to_judge.to_owned(),
        points: fit_score_map(pairs)?,
        overlap_cases: u32::try_from(pairs.len()).unwrap_or(u32::MAX),
        at: now,
        chain: ConversionChainStatus::Valid,
    };
    vault.with_write_txn_grouped(|wtxn| {
        let mut overlaid = conversions_in_txn(vault, wtxn)?;
        overlaid.insert(conversion.from_judge.clone(), conversion.clone());
        restamp_chains_in_txn(vault, wtxn, &mut overlaid)?;
        if let Some(record) = overlaid.get(&conversion.from_judge) {
            conversion.chain = record.chain;
        }
        reproject_judged_in_txn(vault, wtxn, now)
    })?;
    Ok(conversion)
}

/// Withdraws the conversion away from `from_judge`, restoring its scores'
/// original reading.
///
/// # Errors
///
/// Storage errors.
pub fn withdraw_judge_conversion(vault: &Vault, from_judge: &str, now: u64) -> Result<bool> {
    vault.with_write_txn_grouped(|wtxn| {
        if !CONVERSION.delete(&vault.store, wtxn, &from_judge.to_owned())? {
            return Ok(false);
        }
        // A withdraw can heal other records' chains: recompute every
        // remaining record's status in the same txn.
        let mut remaining = conversions_in_txn(vault, wtxn)?;
        restamp_chains_in_txn(vault, wtxn, &mut remaining)?;
        reproject_judged_in_txn(vault, wtxn, now)?;
        Ok(true)
    })
}

/// Recomputes every record in `conversions`' chain status and writes each
/// row back under its from-key. Chains form and heal through other records'
/// writes, so a record and a withdraw both restamp the whole table.
fn restamp_chains_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    conversions: &mut BTreeMap<String, JudgeConversion>,
) -> Result<()> {
    let froms: Vec<String> = conversions.keys().cloned().collect();
    for from in froms {
        let status = chain_status(&from, conversions);
        if let Some(record) = conversions.get_mut(&from) {
            record.chain = status;
            CONVERSION.put(&vault.store, wtxn, &from, record)?;
        }
    }
    Ok(())
}

/// This map's chain validity from `from` through `conversions`: the same
/// rule the fold applies (FIX 9890), so the stored status cannot drift from
/// it. The probe value is irrelevant — cycle detection is judge-sequence
/// only.
fn chain_status(
    from: &str,
    conversions: &BTreeMap<String, JudgeConversion>,
) -> ConversionChainStatus {
    match super::conversion_chain::resolve(from, 0.0, conversions) {
        super::conversion_chain::Resolved::Invalid => ConversionChainStatus::Cyclic,
        _ => ConversionChainStatus::Valid,
    }
}

/// Every conversion in force, by old judge.
pub(crate) fn conversions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<String, JudgeConversion>> {
    Ok(CONVERSION.scan(&vault.store, txn)?.into_iter().collect())
}

fn reproject_judged_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, now: u64) -> Result<()> {
    let digests: BTreeSet<[u8; 32]> = EVIDENCE
        .scan(&vault.store, wtxn)?
        .into_iter()
        // Earlier judges can reach this map through another conversion.
        .filter(|(_, row)| row.judge.is_some())
        .map(|((digest, _), _)| digest)
        .collect();
    for digest in &digests {
        project_cell_in_txn(vault, wtxn, digest, now)?;
    }
    Ok(())
}

/// One overlap case for a judge takeover: did the new judge diverge from the
/// old one, and which source family did the case come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceCase {
    pub source_family: String,
    pub diverged: bool,
}

/// Whether a conversion map's chain from its old judge resolves or loops.
/// Reporting only: recording still succeeds when cyclic, and the status is
/// recomputed on every record and withdraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionChainStatus {
    /// The chain from `from_judge` through the stored conversions reaches a
    /// terminal judge.
    Valid,
    /// The chain loops back on itself; the lineage folds as unknown.
    Cyclic,
}

/// The takeover ladder's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverVerdict {
    /// Divergence sits within the old judge's own retest noise in every
    /// source family: the new judge governs.
    TakeOver,
    /// Divergence exceeds the noise floor somewhere: the incumbent holds.
    Hold,
    /// Too few cases, or no measured noise: the incumbent holds with no
    /// automatic takeover and no tie-breaker until more arrive.
    Unknown,
}

/// Whether a shadowing judge may take over (ARCH-0079 Fig. 6). It takes over
/// only when the high end of its divergence interval, grouped by source
/// family, stays within the incumbent's retest noise. The old judge never
/// settles a disagreement.
#[must_use]
pub fn judge_takeover_verdict(
    cases: &[DivergenceCase],
    incumbent_noise: Option<&Estimate>,
    min_cases_per_family: u32,
) -> TakeoverVerdict {
    let Some(noise) = incumbent_noise.filter(|n| n.runs > 0.0) else {
        return TakeoverVerdict::Unknown;
    };
    let mut families: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    for case in cases {
        let entry = families
            .entry(case.source_family.as_str())
            .or_insert((0, 0));
        entry.0 += 1;
        if case.diverged {
            entry.1 += 1;
        }
    }
    if families.is_empty()
        || families
            .values()
            .any(|(n, _)| *n < min_cases_per_family.max(1))
    {
        return TakeoverVerdict::Unknown;
    }
    let floor = noise.mean();
    let worst = families
        .values()
        .map(|(n, k)| wilson_upper(*k, *n))
        .fold(0.0_f64, f64::max);
    if worst <= floor {
        TakeoverVerdict::TakeOver
    } else {
        TakeoverVerdict::Hold
    }
}

fn wilson_upper(successes: u32, n: u32) -> f64 {
    if n == 0 {
        return 1.0;
    }
    let n = f64::from(n);
    let p = f64::from(successes) / n;
    let z2 = WILSON_Z * WILSON_Z;
    let centre = p + z2 / (2.0 * n);
    let margin = WILSON_Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    ((centre + margin) / (1.0 + z2 / n)).clamp(0.0, 1.0)
}
