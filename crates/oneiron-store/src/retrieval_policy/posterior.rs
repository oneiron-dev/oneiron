//! A continuous-context Beta kernel posterior. Nearby gated end outcomes
//! contribute fractional observations; Thompson draws use the shared Posterior
//! interface. No intermediate score is a success label.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::posterior::Posterior;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const MIN_CONTEXT_MASS: f64 = 3.0;

/// Fractional Bernoulli evidence after the terminal gate and cost shaping.
#[derive(Clone)]
pub struct RewardPosterior {
    pub alpha: f64,
    pub beta: f64,
}

impl Default for RewardPosterior {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

impl Posterior for RewardPosterior {
    type Outcome = (f64, f64);

    fn update(&mut self, (reward, weight): Self::Outcome) -> Result<()> {
        if !reward.is_finite()
            || !(0.0..=1.0).contains(&reward)
            || !weight.is_finite()
            || !(0.0..=1.0).contains(&weight)
        {
            return Err(Error::InvalidConfig(
                "invalid retrieval policy evidence".into(),
            ));
        }
        self.alpha += weight * reward;
        self.beta += weight * (1.0 - reward);
        Ok(())
    }

    fn beta_parameters(&self) -> (f64, f64) {
        (self.alpha, self.beta)
    }

    fn ucb_bonus(&self, total_observations: u64, exploration: f64) -> f64 {
        exploration * ((total_observations.max(1) as f64).ln() / (self.alpha + self.beta)).sqrt()
    }
}
