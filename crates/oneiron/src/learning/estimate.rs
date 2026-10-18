//! The `estimate` value (ARCH-0003 #estimate): one measured answer, its own
//! runs, the prior it started from and the window its runs fade over.
//!
//! Every `learning.*` member carries this one value. The form picks the shape
//! (`beta`, `mean` or `counts`) and every member reads it through the same
//! posterior code path: mean, sample, bonus and lower bound.

use std::collections::BTreeMap;

use rand::Rng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::posterior::{Posterior, beta_mean, beta_std_dev};

/// The estimator version this module writes. Versions never average: an
/// estimate under another version is a different answer, not more evidence.
pub const ESTIMATOR_VERSION: u32 = 1;

/// One-sided 95% normal quantile, the same bound the shared posterior uses.
const BOUND_Z: f64 = 1.645;

/// Smallest Beta parameter the fold keeps, so a cell with no prior mass and
/// one-sided evidence still reads as a valid distribution.
const MIN_BETA_PARAMETER: f64 = 1e-6;

/// The value shape an estimate carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimateForm {
    /// Success/failure uncertainty: `{alpha, beta}`.
    Beta,
    /// A fitted magnitude and its spread: `{mean, spread}`.
    Mean,
    /// Named weighted outcome counts, such as untouched/amended/rejected.
    Counts,
}

impl EstimateForm {
    /// The pinned wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Beta => "beta",
            Self::Mean => "mean",
            Self::Counts => "counts",
        }
    }
}

/// The measured answer, in its form's shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum EstimateValue {
    Beta { alpha: f64, beta: f64 },
    Mean { mean: f64, spread: f64 },
    Counts { counts: BTreeMap<String, f64> },
}

impl EstimateValue {
    /// The form this value is shaped for.
    #[must_use]
    pub const fn form(&self) -> EstimateForm {
        match self {
            Self::Beta { .. } => EstimateForm::Beta,
            Self::Mean { .. } => EstimateForm::Mean,
            Self::Counts { .. } => EstimateForm::Counts,
        }
    }

    /// The uninformative value of `form`: Beta(1, 1), a zero mean, no counts.
    #[must_use]
    pub fn uninformative(form: EstimateForm) -> Self {
        match form {
            EstimateForm::Beta => Self::Beta {
                alpha: 1.0,
                beta: 1.0,
            },
            EstimateForm::Mean => Self::Mean {
                mean: 0.0,
                spread: 0.0,
            },
            EstimateForm::Counts => Self::Counts {
                counts: BTreeMap::new(),
            },
        }
    }

    fn validate(&self) -> Result<()> {
        let finite = |x: f64| x.is_finite();
        let ok = match self {
            Self::Beta { alpha, beta } => {
                finite(*alpha) && finite(*beta) && *alpha > 0.0 && *beta > 0.0
            }
            Self::Mean { mean, spread } => finite(*mean) && finite(*spread) && *spread >= 0.0,
            Self::Counts { counts } => counts
                .iter()
                .all(|(name, n)| !name.is_empty() && finite(*n) && *n >= 0.0),
        };
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "an estimate value must be finite, with positive Beta parameters and non-negative spread and counts",
            ))
        }
    }

    /// The normalized answer the value key spells: four decimals, keys sorted.
    fn normalized(&self) -> String {
        match self {
            Self::Beta { alpha, beta } => format!("{{alpha:{alpha:.4},beta:{beta:.4}}}"),
            Self::Mean { mean, spread } => format!("{{mean:{mean:.4},spread:{spread:.4}}}"),
            Self::Counts { counts } => {
                let parts: Vec<String> = counts
                    .iter()
                    .map(|(name, n)| {
                        if n.fract() == 0.0 {
                            format!("{name}:{n:.0}")
                        } else {
                            format!("{name}:{n:.4}")
                        }
                    })
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }
}

/// Where a prior came from (ARCH-0003 "The six prior origins").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PriorOrigin {
    /// The pack's default.
    Shipped,
    /// A hub import's record.
    Provenance,
    /// Another executor's record, carried weakly; the new pair has no own runs.
    Carried,
    /// The parent task type's or parent project's record.
    Parent,
    /// A model's weak guess for this task.
    Model,
    /// The owner's value and its weight in runs.
    Seed,
}

impl PriorOrigin {
    /// The pinned wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shipped => "shipped",
            Self::Provenance => "provenance",
            Self::Carried => "carried",
            Self::Parent => "parent",
            Self::Model => "model",
            Self::Seed => "seed",
        }
    }
}

/// Everything that is not this cell's own evidence: an origin, a value in the
/// estimate's form and an explicit weight in runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Prior {
    pub origin: PriorOrigin,
    pub value: EstimateValue,
    /// How many own runs this prior counts as. Zero is no prior at all.
    pub weight_runs: f64,
    /// What it was taken from: the parent type, the carried executor, the hub
    /// record. Free text for display, never a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

impl Prior {
    /// The shipped default for `form`: Beta(1, 1) worth two runs, or nothing
    /// for a mean or counts estimate.
    #[must_use]
    pub fn shipped(form: EstimateForm) -> Self {
        let weight_runs = match form {
            EstimateForm::Beta => 2.0,
            EstimateForm::Mean | EstimateForm::Counts => 0.0,
        };
        Self {
            origin: PriorOrigin::Shipped,
            value: EstimateValue::uninformative(form),
            weight_runs,
            from: None,
        }
    }

    /// Structural checks: a finite non-negative weight and a valid value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] on a bad weight or value.
    pub fn validate(&self) -> Result<()> {
        if !self.weight_runs.is_finite() || self.weight_runs < 0.0 {
            return Err(Error::InvalidClaimBody(
                "a prior's weight in runs is finite and non-negative",
            ));
        }
        self.value.validate()
    }
}

/// What the evidence behind the number was, kept to explain it. Labels are
/// never extra wins.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EstimateLabels {
    /// Effective runs per judge revision that scored them.
    #[serde(default)]
    pub by_judge: BTreeMap<String, f64>,
    /// Effective runs whose score went through a judge-swap conversion.
    #[serde(default)]
    pub converted: f64,
    /// Effective runs the judge scored on its own model.
    #[serde(default)]
    pub on_judge_model: f64,
    /// Outcome categories a mean edit-cost estimate also keeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_counts: Option<BTreeMap<String, f64>>,
}

/// The fade window: old runs halve in weight every `half_life` seconds, so a
/// silent vendor update under one model id shows up. Receipts never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Window {
    pub half_life: u64,
}

impl Window {
    /// The weight factor of a run `age` seconds old.
    #[must_use]
    pub fn decay(self, age: u64) -> f64 {
        if self.half_life == 0 {
            return 1.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let halvings = age as f64 / self.half_life as f64;
        0.5_f64.powf(halvings)
    }
}

/// One measured answer (ARCH-0003 #estimate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Estimate {
    pub value: EstimateValue,
    /// Own effective runs: this cell's attributed, windowed evidence only.
    pub runs: f64,
    pub prior: Prior,
    /// What counted: the event the number estimates.
    pub of: String,
    pub labels: EstimateLabels,
    pub window: Window,
    pub ver: u32,
}

impl Estimate {
    /// The estimate's form.
    #[must_use]
    pub const fn form(&self) -> EstimateForm {
        self.value.form()
    }

    /// The UNTESTED display mark: fewer own runs than the prior's weight.
    #[must_use]
    pub fn untested(&self) -> bool {
        self.runs < self.prior.weight_runs
    }

    /// A zero-run estimate assembled from a prior at read; it is never stored.
    #[must_use]
    pub fn from_prior(prior: Prior, of: impl Into<String>, window: Window) -> Self {
        Self {
            value: fold_value(&prior, &OwnTally::empty(prior.value.form())),
            runs: 0.0,
            prior,
            of: of.into(),
            labels: EstimateLabels::default(),
            window,
            ver: ESTIMATOR_VERSION,
        }
    }

    /// `estimate:{form}:{normalized answer}:{ver}`, the equality key.
    #[must_use]
    pub fn value_key(&self) -> String {
        format!(
            "estimate:{}:{}:{}",
            self.form().as_str(),
            self.value.normalized(),
            self.ver
        )
    }

    /// Structural checks over every field.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] on a non-finite or negative number, a
    /// prior in another form, an empty `of` or a zero window.
    pub fn validate(&self) -> Result<()> {
        self.value.validate()?;
        self.prior.validate()?;
        if self.prior.value.form() != self.form() {
            return Err(Error::InvalidClaimBody(
                "an estimate's prior is in the estimate's own form",
            ));
        }
        if !self.runs.is_finite() || self.runs < 0.0 {
            return Err(Error::InvalidClaimBody(
                "an estimate's own runs are finite and non-negative",
            ));
        }
        if self.of.is_empty() || self.of.len() > 128 {
            return Err(Error::InvalidClaimBody(
                "an estimate names what counted in at most 128 bytes",
            ));
        }
        if self.window.half_life == 0 {
            return Err(Error::InvalidClaimBody("an estimate's window is positive"));
        }
        Ok(())
    }

    /// The point answer: the Beta mean, the fitted mean, or the share of the
    /// `of` category among the counts.
    #[must_use]
    pub fn mean(&self) -> f64 {
        match &self.value {
            EstimateValue::Beta { alpha, beta } => beta_mean(*alpha, *beta),
            EstimateValue::Mean { mean, .. } => *mean,
            EstimateValue::Counts { .. } => {
                let (alpha, beta) = self.counts_split();
                beta_mean(alpha, beta)
            }
        }
    }

    /// The conservative bound the selectors gate on.
    #[must_use]
    pub fn lower_bound(&self) -> f64 {
        match &self.value {
            EstimateValue::Mean { mean, spread } => mean - BOUND_Z * self.standard_error(*spread),
            _ => self.beta_view().lower_bound(),
        }
    }

    /// The optimistic bound, the mirror of [`Self::lower_bound`].
    #[must_use]
    pub fn upper_bound(&self) -> f64 {
        match &self.value {
            EstimateValue::Mean { mean, spread } => mean + BOUND_Z * self.standard_error(*spread),
            _ => {
                let (alpha, beta) = self.beta_view().beta_parameters();
                (beta_mean(alpha, beta) + BOUND_Z * beta_std_dev(alpha, beta)).clamp(0.0, 1.0)
            }
        }
    }

    /// The exploration term for a selector over `total` pulls.
    #[must_use]
    pub fn bonus(&self, total: u64, exploration: f64) -> f64 {
        match &self.value {
            EstimateValue::Mean { spread, .. } => {
                #[allow(clippy::cast_precision_loss)]
                let n = (total.max(1)) as f64;
                exploration * self.standard_error(*spread) * (2.0 * n.ln()).max(0.0).sqrt()
            }
            _ => self.beta_view().ucb_bonus(total, exploration),
        }
    }

    /// A Thompson draw from the estimate.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the state cannot be sampled.
    pub fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Result<f64> {
        match &self.value {
            EstimateValue::Mean { mean, spread } => {
                let sd = self.standard_error(*spread);
                if sd == 0.0 {
                    return Ok(*mean);
                }
                let normal = Normal::new(*mean, sd)
                    .map_err(|_| Error::InvalidConfig("estimate cannot be sampled".into()))?;
                Ok(normal.sample(rng))
            }
            _ => self.beta_view().sample(rng),
        }
    }

    fn standard_error(&self, spread: f64) -> f64 {
        let n = self.runs + self.prior.weight_runs;
        if n <= 1.0 { spread } else { spread / n.sqrt() }
    }

    /// Counts read as success (`of`) against everything else.
    fn counts_split(&self) -> (f64, f64) {
        let EstimateValue::Counts { counts } = &self.value else {
            return (1.0, 1.0);
        };
        let hit = counts.get(&self.of).copied().unwrap_or(0.0);
        let rest: f64 = counts
            .iter()
            .filter(|(name, _)| **name != self.of)
            .map(|(_, n)| *n)
            .sum();
        (hit.max(MIN_BETA_PARAMETER), rest.max(MIN_BETA_PARAMETER))
    }

    /// The Beta reading of a beta or counts estimate.
    fn beta_view(&self) -> BetaView {
        match &self.value {
            EstimateValue::Beta { alpha, beta } => BetaView {
                alpha: *alpha,
                beta: *beta,
            },
            _ => {
                let (alpha, beta) = self.counts_split();
                BetaView { alpha, beta }
            }
        }
    }
}

/// A Beta reading through the shared [`Posterior`] interface.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BetaView {
    pub alpha: f64,
    pub beta: f64,
}

impl Posterior for BetaView {
    /// A weighted success or failure.
    type Outcome = (bool, f64);

    fn update(&mut self, (success, weight): Self::Outcome) -> Result<()> {
        if !weight.is_finite() || weight < 0.0 {
            return Err(Error::InvalidConfig(
                "an outcome weight is finite and non-negative".into(),
            ));
        }
        if success {
            self.alpha += weight;
        } else {
            self.beta += weight;
        }
        Ok(())
    }

    fn beta_parameters(&self) -> (f64, f64) {
        (
            self.alpha.max(MIN_BETA_PARAMETER),
            self.beta.max(MIN_BETA_PARAMETER),
        )
    }

    fn ucb_bonus(&self, total_observations: u64, exploration: f64) -> f64 {
        let (alpha, beta) = self.beta_parameters();
        #[allow(clippy::cast_precision_loss)]
        let n = (total_observations.max(1)) as f64;
        exploration * beta_std_dev(alpha, beta) * (2.0 * n.ln()).max(0.0).sqrt()
    }
}

/// Folds a prior and weighted own evidence into one value of the prior's form.
///
/// The prior enters at its weight: a Beta prior's mean is spread over
/// `weight_runs` pseudo-runs, a mean prior counts as `weight_runs` samples of
/// its value, and prior counts are rescaled to `weight_runs` in total.
pub(crate) fn fold_value(prior: &Prior, own: &OwnTally) -> EstimateValue {
    let w = prior.weight_runs;
    match (&prior.value, own) {
        (EstimateValue::Beta { alpha, beta }, OwnTally::Beta { wins, losses }) => {
            let mean = beta_mean(alpha.max(MIN_BETA_PARAMETER), beta.max(MIN_BETA_PARAMETER));
            EstimateValue::Beta {
                alpha: (mean * w + wins).max(MIN_BETA_PARAMETER),
                beta: ((1.0 - mean) * w + losses).max(MIN_BETA_PARAMETER),
            }
        }
        (
            EstimateValue::Mean { mean, spread },
            OwnTally::Mean {
                sum_w,
                sum_wx,
                sum_wxx,
            },
        ) => {
            let total = w + sum_w;
            if total <= 0.0 {
                return EstimateValue::Mean {
                    mean: *mean,
                    spread: *spread,
                };
            }
            let pooled_mean = (w * mean + sum_wx) / total;
            // Pooled second moment: the prior's samples sit at its mean with
            // its own spread.
            let prior_second = w * (spread * spread + mean * mean);
            let variance = ((prior_second + sum_wxx) / total - pooled_mean * pooled_mean).max(0.0);
            EstimateValue::Mean {
                mean: pooled_mean,
                spread: variance.sqrt(),
            }
        }
        (
            EstimateValue::Counts {
                counts: prior_counts,
            },
            OwnTally::Counts { counts },
        ) => {
            let prior_total: f64 = prior_counts.values().sum();
            let scale = if prior_total > 0.0 {
                w / prior_total
            } else {
                0.0
            };
            let mut merged: BTreeMap<String, f64> = prior_counts
                .iter()
                .map(|(name, n)| (name.clone(), n * scale))
                .collect();
            for (name, n) in counts {
                *merged.entry(name.clone()).or_insert(0.0) += n;
            }
            EstimateValue::Counts { counts: merged }
        }
        // A prior in another form than the cell is refused at its door; read
        // it as no prior rather than invent a conversion.
        (_, own) => fold_value(&Prior::shipped(own.form()), own),
    }
}

/// Windowed own evidence for one cell, by form.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum OwnTally {
    Beta {
        wins: f64,
        losses: f64,
    },
    Mean {
        sum_w: f64,
        sum_wx: f64,
        sum_wxx: f64,
    },
    Counts {
        counts: BTreeMap<String, f64>,
    },
}

impl OwnTally {
    pub(crate) fn empty(form: EstimateForm) -> Self {
        match form {
            EstimateForm::Beta => Self::Beta {
                wins: 0.0,
                losses: 0.0,
            },
            EstimateForm::Mean => Self::Mean {
                sum_w: 0.0,
                sum_wx: 0.0,
                sum_wxx: 0.0,
            },
            EstimateForm::Counts => Self::Counts {
                counts: BTreeMap::new(),
            },
        }
    }

    pub(crate) const fn form(&self) -> EstimateForm {
        match self {
            Self::Beta { .. } => EstimateForm::Beta,
            Self::Mean { .. } => EstimateForm::Mean,
            Self::Counts { .. } => EstimateForm::Counts,
        }
    }
}
