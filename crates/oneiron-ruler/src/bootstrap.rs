//! The paired bootstrap over per-query differences (RESEARCH-0651 Tier 0).
//!
//! A candidate parameter set is compared with the incumbent on the held_out
//! slice: the engine's dominance rule decides first (in oneiron-bench, a later
//! PR), then a paired bootstrap on each Primary axis must show a 95 % lower
//! bound above 0. This module pairs the two held_out scorecards by query id,
//! resamples the per-query differences, and reports the 2.5 % lower bound of
//! the mean difference. The generator is splitmix64 seeded from the pack
//! digest, so a bound is reproducible anywhere.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::axes::is_per_query_axis;
use crate::pack::Slice;
use crate::scorecard::{QueryScore, RANKED_METRICS, Scorecard};

/// Resamples per bootstrap (RESEARCH-0651 Tier 0).
pub const BOOTSTRAP_RESAMPLES: u32 = 2000;
/// The lower bound's percentile, in tenths of a percent: 25 = 2.5 %.
pub const LOWER_BOUND_PER_MILLE: u32 = 25;

/// splitmix64 (Steele, Lea, Flood 2014): a tiny, fully specified generator, so a bound is reproducible anywhere.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    /// The generator state.
    state: u64,
}

impl SplitMix64 {
    /// A generator starting from `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next output word.
    ///
    /// state += 0x9E37_79B9_7F4A_7C15; z = state;
    /// z = (z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9;
    /// z = (z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB; return z ^ (z >> 31).
    /// All wrapping.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform index below `bound` (> 0) by multiply-shift: ((next_u64() as u128 * bound as u128) >> 64) as usize.
    pub fn index_below(&mut self, bound: usize) -> usize {
        ((self.next_u64() as u128 * bound as u128) >> 64) as usize
    }
}

/// One Primary axis's bootstrap: pairs, mean difference and lower bound.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AxisBound {
    /// The bootstrapped axis.
    pub axis: String,
    /// How many query pairs the bootstrap ran on.
    pub pairs: u32,
    /// The plain mean of the per-query differences.
    pub mean_difference: f64,
    /// The 2.5 % lower bound of the mean difference.
    pub lower_bound: f64,
}

/// Every way a bootstrap can fail to pair, seed or resample.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The pack digest is not 64 lowercase hex.
    #[error("bad pack digest")]
    BadDigest,
    /// The metric is not one of the five ranked metrics.
    #[error("unknown metric: {metric}")]
    UnknownMetric {
        /// The unknown metric.
        metric: String,
    },
    /// One side names a query twice.
    #[error("duplicate query: {query_id}")]
    DuplicateQuery {
        /// The repeated query.
        query_id: String,
    },
    /// A query sits on one side only.
    #[error("query set mismatch at: {query_id}")]
    QuerySetMismatch {
        /// The first query, in sorted order, on one side only.
        query_id: String,
    },
    /// The metric is present on one side only.
    #[error("metric presence mismatch at: {query_id}")]
    MetricPresenceMismatch {
        /// The mismatching query.
        query_id: String,
    },
    /// A per-query difference is not finite.
    #[error("non-finite difference at: {query_id}")]
    NonFinite {
        /// The bad query.
        query_id: String,
    },
    /// No query pairs survived (every query abstained).
    #[error("no pairs")]
    NoPairs,
    /// The bootstrap was asked for no resamples.
    #[error("no resamples")]
    NoResamples,
    /// A bootstrap input is not finite.
    #[error("non-finite bootstrap input")]
    NonFiniteInput,
    /// A scorecard is not on the held_out slice.
    #[error("not the held_out slice")]
    NotHeldOut,
    /// The two scorecards name different packs.
    #[error("pack mismatch")]
    PackMismatch,
    /// The axis has no per-query values.
    #[error("not a per-query axis: {axis}")]
    NotPerQueryAxis {
        /// The bad axis.
        axis: String,
    },
    /// More pairs than fit in a u32.
    #[error("too many pairs")]
    TooManyPairs,
}

/// The seed: the first 16 hex digits of the pack digest read as one big-endian u64.
pub fn seed_from_pack_digest(pack_digest: &str) -> Result<u64, BootstrapError> {
    if pack_digest.len() != 64
        || !pack_digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BootstrapError::BadDigest);
    }
    u64::from_str_radix(&pack_digest[..16], 16).map_err(|_| BootstrapError::BadDigest)
}

/// Per-query candidate-minus-incumbent differences of one ranked metric, oriented so positive = better (all five
/// ranked metrics are higher-is-better). Pairs by query_id, in query_id order (BTreeMap), so file order never matters.
pub fn paired_differences(
    incumbent: &[QueryScore],
    candidate: &[QueryScore],
    metric: &str,
) -> Result<Vec<f64>, BootstrapError> {
    if !RANKED_METRICS.contains(&metric) {
        return Err(BootstrapError::UnknownMetric {
            metric: metric.to_owned(),
        });
    }
    let mut ours: BTreeMap<&str, &QueryScore> = BTreeMap::new();
    for score in incumbent {
        if ours.insert(score.query_id.as_str(), score).is_some() {
            return Err(BootstrapError::DuplicateQuery {
                query_id: score.query_id.clone(),
            });
        }
    }
    let mut theirs: BTreeMap<&str, &QueryScore> = BTreeMap::new();
    for score in candidate {
        if theirs.insert(score.query_id.as_str(), score).is_some() {
            return Err(BootstrapError::DuplicateQuery {
                query_id: score.query_id.clone(),
            });
        }
    }
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for id in ours.keys() {
        ids.insert(*id);
    }
    for id in theirs.keys() {
        ids.insert(*id);
    }
    for id in &ids {
        if !ours.contains_key(*id) || !theirs.contains_key(*id) {
            return Err(BootstrapError::QuerySetMismatch {
                query_id: (*id).to_owned(),
            });
        }
    }
    let mut differences = Vec::new();
    for id in &ids {
        let (Some(left), Some(right)) = (ours.get(*id), theirs.get(*id)) else {
            return Err(BootstrapError::QuerySetMismatch {
                query_id: (*id).to_owned(),
            });
        };
        match (metric_value(left, metric), metric_value(right, metric)) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                let difference = b - a;
                if !difference.is_finite() {
                    return Err(BootstrapError::NonFinite {
                        query_id: (*id).to_owned(),
                    });
                }
                differences.push(difference);
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(BootstrapError::MetricPresenceMismatch {
                    query_id: (*id).to_owned(),
                });
            }
        }
    }
    if differences.is_empty() {
        return Err(BootstrapError::NoPairs);
    }
    Ok(differences)
}

/// The 2.5 % lower bound of the mean difference over `resamples` bootstrap resamples.
pub fn paired_lower_bound(
    differences: &[f64],
    resamples: u32,
    seed: u64,
) -> Result<f64, BootstrapError> {
    if differences.is_empty() {
        return Err(BootstrapError::NoPairs);
    }
    if resamples == 0 {
        return Err(BootstrapError::NoResamples);
    }
    for value in differences {
        if !value.is_finite() {
            return Err(BootstrapError::NonFiniteInput);
        }
    }
    let count = differences.len();
    let mut rng = SplitMix64::new(seed);
    let mut means: Vec<f64> = Vec::with_capacity(resamples as usize);
    for _ in 0..resamples {
        let mut sum = 0.0;
        for _ in 0..count {
            sum += differences[rng.index_below(count)];
        }
        means.push(sum / count as f64);
    }
    means.sort_by(f64::total_cmp);
    let total = u64::from(resamples);
    let rank = (total * u64::from(LOWER_BOUND_PER_MILLE))
        .div_ceil(1000)
        .clamp(1, total);
    Ok(means[(rank - 1) as usize])
}

/// Bootstrap one per-query axis of two held_out scorecards of ONE pack (seed from its digest, BOOTSTRAP_RESAMPLES).
pub fn bootstrap_axis(
    incumbent: &Scorecard,
    candidate: &Scorecard,
    axis: &str,
) -> Result<AxisBound, BootstrapError> {
    if incumbent.slice != Slice::HeldOut || candidate.slice != Slice::HeldOut {
        return Err(BootstrapError::NotHeldOut);
    }
    if incumbent.pack_digest != candidate.pack_digest {
        return Err(BootstrapError::PackMismatch);
    }
    if !is_per_query_axis(axis) {
        return Err(BootstrapError::NotPerQueryAxis {
            axis: axis.to_owned(),
        });
    }
    let differences = paired_differences(&incumbent.per_query, &candidate.per_query, axis)?;
    let seed = seed_from_pack_digest(&incumbent.pack_digest)?;
    let lower_bound = paired_lower_bound(&differences, BOOTSTRAP_RESAMPLES, seed)?;
    let mut sum = 0.0;
    for value in &differences {
        sum += *value;
    }
    let mean_difference = sum / differences.len() as f64;
    let pairs = u32::try_from(differences.len()).map_err(|_| BootstrapError::TooManyPairs)?;
    Ok(AxisBound {
        axis: axis.to_owned(),
        pairs,
        mean_difference,
        lower_bound,
    })
}

/// One ranked metric of a query score, by [`RANKED_METRICS`] name.
fn metric_value(score: &QueryScore, metric: &str) -> Option<f64> {
    match metric {
        "ndcg_at_10" => score.ndcg_at_10,
        "mrr" => score.mrr,
        "recall_at_5" => score.recall_at_5,
        "recall_at_20" => score.recall_at_20,
        "recall_at_budget" => score.recall_at_budget,
        _ => None,
    }
}
