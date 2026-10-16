//! A continuous-context Beta kernel posterior. Nearby gated end outcomes
//! contribute fractional observations; Thompson draws use the shared Posterior
//! interface. No intermediate score is a success label.

use super::{RetrievalPolicyAction, RetrievalPolicyIdentity, RetrievalPolicyTier};
use crate::error::{Error, Result};
use crate::posterior::Posterior;
use crate::store::RetrievalState;
use rand::Rng;
use serde::{Deserialize, Serialize};

const MIN_CONTEXT_MASS: f64 = 3.0;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct PolicyObservation {
    pub identity: RetrievalPolicyIdentity,
    pub context: [f64; 16],
    pub action: RetrievalPolicyAction,
    pub reward: f64,
    pub weight: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RetrievalPolicyPosterior {
    pub tuned_at: u64,
    pub labeled_runs: usize,
    pub(crate) observations: Vec<PolicyObservation>,
}

impl RetrievalPolicyPosterior {
    pub(crate) fn observe(
        &mut self,
        identity: RetrievalPolicyIdentity,
        state: &RetrievalState,
        action: RetrievalPolicyAction,
        reward: f64,
        weight: f64,
    ) -> Result<()> {
        state.validate()?;
        let mut check = RewardPosterior::default();
        check.update((reward, weight))?;
        self.observations.push(PolicyObservation {
            identity,
            context: state.policy_context(),
            action,
            reward,
            weight,
        });
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for observation in &self.observations {
            if observation
                .context
                .iter()
                .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
            {
                return Err(Error::CorruptedIndex("retrieval policy posterior"));
            }
            RewardPosterior::default().update((observation.reward, observation.weight))?;
        }
        Ok(())
    }

    pub(super) fn pick<R: Rng + ?Sized>(
        &self,
        identity: RetrievalPolicyIdentity,
        state: &RetrievalState,
        actions: &[RetrievalPolicyAction],
        rng: &mut R,
    ) -> Result<Option<(RetrievalPolicyAction, RetrievalPolicyTier)>> {
        let context = state.policy_context();
        for tier in [
            RetrievalPolicyTier::User,
            RetrievalPolicyTier::Persona,
            RetrievalPolicyTier::Global,
        ] {
            if tier == RetrievalPolicyTier::Persona && identity.persona.is_none() {
                continue;
            }
            let mut arms = vec![RewardPosterior::default(); actions.len()];
            let mut mass = 0.0;
            for observation in &self.observations {
                let scope_matches = match tier {
                    RetrievalPolicyTier::User => observation.identity.user == identity.user,
                    RetrievalPolicyTier::Persona => {
                        observation.identity.persona == identity.persona
                    }
                    RetrievalPolicyTier::Global => true,
                    RetrievalPolicyTier::Seed => false,
                };
                // Semantic intent is categorical; the other fifteen inputs are continuous.
                if !scope_matches || observation.context[15] != context[15] {
                    continue;
                }
                let Some(index) = actions
                    .iter()
                    .position(|action| *action == observation.action)
                else {
                    continue;
                };
                let distance: f64 = context
                    .iter()
                    .zip(observation.context)
                    .map(|(a, b)| (a - b).powi(2))
                    .sum();
                let weight = observation.weight * (-2.0 * distance).exp();
                mass += weight;
                arms[index].update((observation.reward, weight))?;
            }
            if mass < MIN_CONTEXT_MASS {
                continue;
            }
            let mut best = None;
            for (action, arm) in actions.iter().zip(arms) {
                let draw = arm.sample(rng)?;
                if best.is_none_or(|(_, score): (RetrievalPolicyAction, f64)| draw > score) {
                    best = Some((*action, draw));
                }
            }
            return Ok(best.map(|(action, _)| (action, tier)));
        }
        Ok(None)
    }
}

/// Fractional Bernoulli evidence after the terminal gate and cost shaping.
#[derive(Clone)]
struct RewardPosterior {
    alpha: f64,
    beta: f64,
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
