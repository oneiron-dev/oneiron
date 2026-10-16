//! Read-only critic weights from the shared measured-state projector.
use super::*;
use crate::learning::{Anchor, Estimate, EstimateValue};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticReliability {
    pub cell: LearningCell,
    pub estimate: Estimate,
}

impl CriticReliability {
    pub fn new(cell: LearningCell, estimate: Estimate) -> Result<Self> {
        let reliability = Self { cell, estimate };
        validate_reliability(&reliability)?;
        Ok(reliability)
    }

    #[must_use]
    pub fn posterior_mean(&self) -> f64 {
        self.estimate.mean()
    }

    #[must_use]
    pub fn triage_weight(&self, total_observations: u64, exploration: f64) -> f64 {
        self.posterior_mean() + self.estimate.bonus(total_observations, exploration)
    }

    pub(super) fn beta_parameters(&self) -> (f64, f64) {
        match &self.estimate.value {
            EstimateValue::Beta { alpha, beta } => (*alpha, *beta),
            _ => unreachable!("critic reliability validates the Beta form"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReliabilityOutcomeSource {
    HeldOutEval,
    OwnerVerdict,
    Beam,
    CriticAgreement,
}

impl ReliabilityOutcomeSource {
    #[must_use]
    pub const fn is_anchored(self) -> bool {
        !matches!(self, Self::CriticAgreement)
    }

    pub(super) fn anchor(self) -> Result<Anchor> {
        match self {
            Self::HeldOutEval | Self::Beam => Ok(Anchor::HeldOut),
            Self::OwnerVerdict => Ok(Anchor::OwnerVerdict),
            Self::CriticAgreement => Err(invalid_critic_config(
                "critic agreement is never learning evidence",
            )),
        }
    }
}
