//! The paired, family-grouped estimator behind an eval measurement (FIX 574,
//! OF-578).
//!
//! Canon fixes the contract, not the arithmetic: "a set too small to judge
//! shows as unknown" (ARCH-0053). Every number below is a method choice with
//! no canon cite, so each sits behind one named constant and is pinned into
//! the request through [`MeasurementMethodPin`]: a stored measurement names
//! the method that produced it. Scores are oriented higher-is-better; a case's
//! delta is candidate minus incumbent; families are averaged equally and only
//! families are resampled, never rows.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// Revision of the whole method; any change below bumps it.
pub(crate) const METHOD_REVISION: u32 = 1;
/// Family resamples drawn for the paired interval.
pub(crate) const BOOTSTRAP_RESAMPLES: u32 = 2_000;
/// Two-sided coverage of the paired interval.
pub(crate) const CI_LEVEL: f64 = 0.95;
/// Domain mixed with the request digest into the resampling seed.
pub(crate) const SEED_DOMAIN: &str = "eval-paired-bootstrap-v1";
/// Normal quantile of a two-sided 5% test, for the detectable effect only.
pub(crate) const DETECTABLE_Z_ALPHA: f64 = 1.96;
/// Normal quantile of 80% power, for the detectable effect only.
pub(crate) const DETECTABLE_Z_POWER: f64 = 0.84;
/// Fewest families an interval is drawn from; a larger declared policy
/// minimum wins.
pub(crate) const MIN_INTERVAL_FAMILIES: u32 = 10;
/// How a family's matched cases reduce to one delta.
pub(crate) const WITHIN_FAMILY_REDUCER: &str = "mean_paired_delta";
/// How family deltas reduce to the measured delta.
pub(crate) const FAMILY_REDUCER: &str = "equal_weight_mean";
/// The interval's quantile: linear interpolation at `p * (B - 1)`.
pub(crate) const QUANTILE_METHOD: &str = "linear_p_times_b_minus_one";
/// The resampler: SplitMix64 with rejection sampling for an index.
pub(crate) const SAMPLER: &str = "splitmix64_rejection";

/// The method a measurement was asked for and computed with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementMethodPin {
    pub revision: u32,
    pub within_family: String,
    pub across_families: String,
    pub resamples: u32,
    pub ci_level: f64,
    pub quantile: String,
    pub sampler: String,
    pub seed_domain: String,
    pub detectable_z_alpha: f64,
    pub detectable_z_power: f64,
    pub min_interval_families: u32,
}

impl MeasurementMethodPin {
    /// The method this build runs.
    #[must_use]
    pub fn current() -> Self {
        Self {
            revision: METHOD_REVISION,
            within_family: WITHIN_FAMILY_REDUCER.to_owned(),
            across_families: FAMILY_REDUCER.to_owned(),
            resamples: BOOTSTRAP_RESAMPLES,
            ci_level: CI_LEVEL,
            quantile: QUANTILE_METHOD.to_owned(),
            sampler: SAMPLER.to_owned(),
            seed_domain: SEED_DOMAIN.to_owned(),
            detectable_z_alpha: DETECTABLE_Z_ALPHA,
            detectable_z_power: DETECTABLE_Z_POWER,
            min_interval_families: MIN_INTERVAL_FAMILIES,
        }
    }
}

/// One family's matched cases, reduced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalFamilySummary {
    pub family: EntityId,
    pub cases: u32,
    /// Mean of candidate minus incumbent over the family's cases.
    pub mean_delta: f64,
    /// Mean of |incumbent - incumbent retest| over the family's cases.
    pub retest_noise: f64,
    /// The floor slices the family's cases fall in.
    pub slices: BTreeSet<String>,
}

/// Why the estimator drew no interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimateGap {
    /// Fewer families than the method or the declared policy needs.
    TooFewFamilies,
    /// Every family delta is the same; no spread to bound.
    ZeroDeltaVariance,
    /// A score or a derived number is not finite.
    NonFinite,
}

/// One matched case as the estimator reads it, oriented higher-is-better.
pub(crate) struct PairedScores<'a> {
    pub(crate) family: EntityId,
    pub(crate) stratum: Option<&'a str>,
    pub(crate) incumbent: f64,
    pub(crate) candidate: f64,
    pub(crate) retest: f64,
}

/// What the estimator found. Absent numbers stay absent, never zero.
pub(crate) struct EvalEstimate {
    pub(crate) families: Vec<EvalFamilySummary>,
    pub(crate) slice_families: BTreeMap<String, u32>,
    pub(crate) retest_noise: Option<f64>,
    pub(crate) mean_delta: Option<f64>,
    pub(crate) interval: Option<(f64, f64)>,
    pub(crate) detectable_effect: Option<f64>,
    pub(crate) gap: Option<EstimateGap>,
}

#[derive(Default)]
struct FamilyAcc {
    cases: u32,
    delta: f64,
    noise: f64,
    slices: BTreeSet<String>,
}

/// SplitMix64: small, version-stable, and fixed by its seed alone.
struct SplitMix64(u64);

impl SplitMix64 {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform index below `n` (n > 0), rejecting the biased low tail.
    fn below(&mut self, n: u64) -> u64 {
        let threshold = n.wrapping_neg() % n;
        loop {
            let draw = self.draw();
            if draw >= threshold {
                return draw % n;
            }
        }
    }
}

/// The resampling seed: fixed by the domain and the request digest before
/// any score exists.
fn seed(request_digest: &[u8; 32]) -> u64 {
    let mut hash = blake3::Hasher::new();
    hash.update(SEED_DOMAIN.as_bytes());
    hash.update(b"\0");
    hash.update(request_digest);
    let bytes = hash.finalize();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&bytes.as_bytes()[..8]);
    u64::from_le_bytes(head)
}

fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let value = values.iter().sum::<f64>() / values.len() as f64;
    value.is_finite().then_some(value)
}

/// Linear interpolation at `p * (len - 1)` over sorted values.
fn quantile(sorted: &[f64], p: f64) -> Option<f64> {
    let last = sorted.len().checked_sub(1)?;
    let h = p * last as f64;
    let low = h.floor();
    let below = *sorted.get(low as usize)?;
    let above = *sorted.get(h.ceil() as usize)?;
    Some(below + (h - low) * (above - below))
}

fn families(cases: &[PairedScores<'_>]) -> Option<Vec<EvalFamilySummary>> {
    let mut by_family: BTreeMap<EntityId, FamilyAcc> = BTreeMap::new();
    for case in cases {
        let delta = case.candidate - case.incumbent;
        let noise = (case.incumbent - case.retest).abs();
        if !delta.is_finite() || !noise.is_finite() {
            return None;
        }
        let acc = by_family.entry(case.family).or_default();
        acc.cases += 1;
        acc.delta += delta;
        acc.noise += noise;
        acc.slices.extend(case.stratum.map(str::to_owned));
    }
    by_family
        .into_iter()
        .map(|(family, acc)| {
            let count = f64::from(acc.cases);
            let summary = EvalFamilySummary {
                family,
                cases: acc.cases,
                mean_delta: acc.delta / count,
                retest_noise: acc.noise / count,
                slices: acc.slices,
            };
            (summary.mean_delta.is_finite() && summary.retest_noise.is_finite()).then_some(summary)
        })
        .collect()
}

/// Families per required floor slice, a required slice with none counted as
/// zero.
fn slice_families(
    summaries: &[EvalFamilySummary],
    required: &BTreeSet<String>,
) -> BTreeMap<String, u32> {
    let mut counts: BTreeMap<String, u32> =
        required.iter().map(|slice| (slice.clone(), 0)).collect();
    for summary in summaries {
        for slice in &summary.slices {
            if let Some(count) = counts.get_mut(slice) {
                *count += 1;
            }
        }
    }
    counts
}

/// The family bootstrap of the equal-weight mean delta.
fn bootstrap(deltas: &[f64], request_digest: &[u8; 32]) -> Option<(f64, f64)> {
    let n = u64::try_from(deltas.len()).ok()?;
    let mut rng = SplitMix64(seed(request_digest));
    let mut means = Vec::with_capacity(BOOTSTRAP_RESAMPLES as usize);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut total = 0.0;
        for _ in 0..n {
            total += *deltas.get(usize::try_from(rng.below(n)).ok()?)?;
        }
        means.push(total / n as f64);
    }
    means.sort_by(f64::total_cmp);
    let tail = (1.0 - CI_LEVEL) / 2.0;
    let low = quantile(&means, tail)?;
    let high = quantile(&means, 1.0 - tail)?;
    (low.is_finite() && high.is_finite() && low <= high).then_some((low, high))
}

/// The detectable effect at the current family count: `(z_a + z_p) * SE`,
/// with the family-level standard error. Display data, never the margin.
fn detectable_effect(deltas: &[f64], center: f64) -> Option<f64> {
    let count = deltas.len() as f64;
    let spread = deltas.iter().map(|d| (d - center).powi(2)).sum::<f64>() / (count - 1.0);
    let effect = (DETECTABLE_Z_ALPHA + DETECTABLE_Z_POWER) * (spread / count).sqrt();
    effect.is_finite().then_some(effect)
}

/// Estimate the paired delta of a complete matched case set. Below
/// `max(MIN_INTERVAL_FAMILIES, policy_min)` families, with a non-finite
/// number or with no spread in family deltas, the interval and the effect
/// stay `None` with the gap named.
pub(crate) fn estimate(
    cases: &[PairedScores<'_>],
    required_slices: &BTreeSet<String>,
    policy_min_families: u32,
    request_digest: &[u8; 32],
) -> EvalEstimate {
    let Some(summaries) = families(cases) else {
        return EvalEstimate {
            families: Vec::new(),
            slice_families: slice_families(&[], required_slices),
            retest_noise: None,
            mean_delta: None,
            interval: None,
            detectable_effect: None,
            gap: Some(EstimateGap::NonFinite),
        };
    };
    let deltas: Vec<f64> = summaries.iter().map(|family| family.mean_delta).collect();
    let noises: Vec<f64> = summaries.iter().map(|family| family.retest_noise).collect();
    let mean_delta = mean(&deltas);
    let floor = MIN_INTERVAL_FAMILIES.max(policy_min_families) as usize;
    let mut gap = None;
    let mut interval = None;
    let mut effect = None;
    if deltas.len() < floor.max(2) {
        gap = Some(EstimateGap::TooFewFamilies);
    } else if let Some(center) = mean_delta {
        if deltas
            .iter()
            .all(|delta| (delta - center).abs() <= f64::EPSILON)
        {
            gap = Some(EstimateGap::ZeroDeltaVariance);
        } else {
            interval = bootstrap(&deltas, request_digest);
            effect = detectable_effect(&deltas, center);
            if interval.is_none() || effect.is_none() {
                gap = Some(EstimateGap::NonFinite);
            }
        }
    } else {
        gap = Some(EstimateGap::NonFinite);
    }
    EvalEstimate {
        slice_families: slice_families(&summaries, required_slices),
        retest_noise: mean(&noises),
        mean_delta,
        interval: interval.filter(|_| effect.is_some()),
        detectable_effect: effect.filter(|_| interval.is_some()),
        gap,
        families: summaries,
    }
}
