//! Shared Beta posterior bandit seam; outcome admission stays with each estimator.

use rand::Rng;
use rand_distr::{Beta, Distribution};

use crate::error::{Error, Result};

/// One-sided 95% normal quantile for the conservative posterior bound.
const LOWER_BOUND_Z: f64 = 1.645;

/// A common interface for the skill and critic reliability estimators.
///
/// Implementations choose which evidence can become an `Outcome`, how to count
/// pulls, and which exploration bonus their selector uses. Only admitted
/// outcomes should reach `update`; callers with untrusted evidence must use
/// the estimator's admission door rather than bypass its source policy.
pub trait Posterior {
    /// The estimator's admitted outcome type.
    type Outcome;

    /// Fold one admitted outcome into the posterior.
    fn update(&mut self, outcome: Self::Outcome) -> Result<()>;

    /// Positive, finite Beta parameters, maintained by each estimator.
    fn beta_parameters(&self) -> (f64, f64);

    /// Draw a Thompson sample, using a caller-owned RNG for reproducibility.
    /// Invalid state and distributions that cannot yield a finite probability
    /// return a validation error instead of panicking or emitting NaN.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Result<f64> {
        let (alpha, beta) = self.beta_parameters();
        if !alpha.is_finite() || !beta.is_finite() || alpha <= 0.0 || beta <= 0.0 {
            return Err(Error::InvalidConfig(
                "posterior parameters must be finite and positive".into(),
            ));
        }
        let distribution = Beta::new(alpha, beta)
            .map_err(|_| Error::InvalidConfig("posterior parameters cannot be sampled".into()))?;
        let draw = distribution.sample(rng);
        if !draw.is_finite() || !(0.0..=1.0).contains(&draw) {
            return Err(Error::InvalidConfig(
                "posterior sample is not a finite probability".into(),
            ));
        }
        Ok(draw)
    }

    /// The exploration term only; each estimator owns its selection policy.
    fn ucb_bonus(&self, total_observations: u64, exploration: f64) -> f64;

    /// Conservative Beta confidence bound, clamped to a probability.
    fn lower_bound(&self) -> f64 {
        let (alpha, beta) = self.beta_parameters();
        (beta_mean(alpha, beta) - LOWER_BOUND_Z * beta_std_dev(alpha, beta)).clamp(0.0, 1.0)
    }
}

/// Beta mean and variance are shared by both reliability lanes.
pub(crate) fn beta_mean(alpha: f64, beta: f64) -> f64 {
    if alpha <= beta {
        let ratio = alpha / beta;
        ratio / (1.0 + ratio)
    } else {
        1.0 / (1.0 + beta / alpha)
    }
}

pub(crate) fn beta_std_dev(alpha: f64, beta: f64) -> f64 {
    let mean = beta_mean(alpha, beta);
    // A sum above f64::MAX is an infinite effective sample size: variance
    // tends to zero. Ratios also avoid underflow when both priors are tiny.
    (mean * (1.0 - mean) / (alpha + beta + 1.0)).sqrt()
}
