//! Moved from `crates/oneiron/src/skill_optimize/eval_set/measurement/statistics.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Revision of the whole method; any change below bumps it.
pub const METHOD_REVISION: u32 = 1;

/// Family resamples drawn for the paired interval.
pub const BOOTSTRAP_RESAMPLES: u32 = 2_000;

/// Two-sided coverage of the paired interval.
pub const CI_LEVEL: f64 = 0.95;

/// Domain mixed with the request digest into the resampling seed.
pub const SEED_DOMAIN: &str = "eval-paired-bootstrap-v1";

/// Normal quantile of a two-sided 5% test, for the detectable effect only.
pub const DETECTABLE_Z_ALPHA: f64 = 1.96;

/// Normal quantile of 80% power, for the detectable effect only.
pub const DETECTABLE_Z_POWER: f64 = 0.84;

/// Fewest families an interval is drawn from; a larger declared policy
/// minimum wins.
pub const MIN_INTERVAL_FAMILIES: u32 = 10;

/// How a family's matched cases reduce to one delta.
pub const WITHIN_FAMILY_REDUCER: &str = "mean_paired_delta";

/// How family deltas reduce to the measured delta.
pub const FAMILY_REDUCER: &str = "equal_weight_mean";

/// The interval's quantile: linear interpolation at `p * (B - 1)`.
pub const QUANTILE_METHOD: &str = "linear_p_times_b_minus_one";

/// The resampler: SplitMix64 with rejection sampling for an index.
pub const SAMPLER: &str = "splitmix64_rejection";

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
