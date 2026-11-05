//! Frozen numeric inputs behind a borrowed prior, without donor references.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::estimate::{EstimateForm, EstimateValue, OwnTally, Prior, fold_value};
use super::evidence::Observation;
use super::judge::JudgeConversion;
use super::project::convert;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredPrior {
    pub(crate) prior: Prior,
    pub(crate) fold: Option<Box<FrozenFold>>,
}

impl StoredPrior {
    pub(crate) fn plain(prior: Prior) -> Self {
        Self { prior, fold: None }
    }

    pub(crate) fn project(&self, conversions: &BTreeMap<String, JudgeConversion>) -> Prior {
        let mut prior = self.prior.clone();
        if let Some(fold) = &self.fold {
            prior.value = fold.value(conversions);
        }
        prior
    }

    fn validate(&self) -> Result<()> {
        self.prior.validate()?;
        if let Some(fold) = &self.fold {
            if fold.form != self.prior.value.form() {
                return Err(Error::InvalidClaimBody("a frozen prior retains its form"));
            }
            fold.validate_for(self.prior.value.form())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FrozenFold {
    prior: StoredPrior,
    form: EstimateForm,
    convert_judges: bool,
    observations: Vec<FrozenObservation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FrozenObservation {
    observation: Observation,
    judge: Option<String>,
    weight: f64,
}

impl FrozenFold {
    pub(crate) fn new(mut prior: StoredPrior, form: EstimateForm, convert_judges: bool) -> Self {
        prior.prior.from = None;
        Self {
            prior,
            form,
            convert_judges,
            observations: Vec::new(),
        }
    }

    pub(crate) fn observe(&mut self, observation: &Observation, judge: Option<&str>, weight: f64) {
        if matches!(
            observation,
            Observation::Success(_) | Observation::Magnitude(_)
        ) {
            self.observations.push(FrozenObservation {
                observation: observation.clone(),
                judge: judge.map(str::to_owned),
                weight,
            });
        }
    }

    fn value(&self, conversions: &BTreeMap<String, JudgeConversion>) -> EstimateValue {
        let prior = self.prior.project(conversions);
        let mut tally = OwnTally::empty(self.form);
        for sample in &self.observations {
            let projected = if self.convert_judges {
                convert(&sample.observation, sample.judge.as_deref(), conversions)
            } else {
                Some((sample.observation.clone(), false))
            };
            if let Some((observation, _)) = projected {
                accumulate(&mut tally, &observation, sample.weight);
            }
        }
        fold_value(&prior, &tally)
    }

    pub(crate) fn has_judge(&self) -> bool {
        self.prior
            .fold
            .as_ref()
            .is_some_and(|fold| fold.has_judge())
            || (self.convert_judges
                && self
                    .observations
                    .iter()
                    .any(|sample| sample.judge.is_some()))
    }

    pub(crate) fn validate_for(&self, form: EstimateForm) -> Result<()> {
        self.prior.validate()?;
        if self.form == EstimateForm::Counts
            || self.form != form
            || self.form != self.prior.prior.value.form()
        {
            return Err(Error::InvalidClaimBody(
                "a frozen fold has a numeric estimate form",
            ));
        }
        for sample in &self.observations {
            let numeric = match &sample.observation {
                Observation::Success(_) => true,
                Observation::Magnitude(x) => x.is_finite(),
                Observation::Category(_) | Observation::CountOnly(_) => false,
            };
            if !numeric
                || sample.observation.form() != self.form
                || !sample.weight.is_finite()
                || sample.weight <= 0.0
            {
                return Err(Error::InvalidClaimBody(
                    "a frozen fold holds valid weighted numeric observations",
                ));
            }
        }
        Ok(())
    }
}

/// The same numerical accumulation for live evidence and its frozen snapshot.
pub(super) fn accumulate(tally: &mut OwnTally, observation: &Observation, w: f64) -> bool {
    match (tally, observation) {
        (OwnTally::Beta { wins, losses }, Observation::Success(ok)) => {
            if *ok {
                *wins += w;
            } else {
                *losses += w;
            }
        }
        (OwnTally::Beta { wins, losses }, Observation::Magnitude(score)) => {
            let score = score.clamp(0.0, 1.0);
            *wins += w * score;
            *losses += w * (1.0 - score);
        }
        (
            OwnTally::Mean {
                sum_w,
                sum_wx,
                sum_wxx,
            },
            Observation::Magnitude(x),
        ) => {
            *sum_w += w;
            *sum_wx += w * x;
            *sum_wxx += w * x * x;
        }
        (OwnTally::Counts { counts }, Observation::Category(name)) => {
            *counts.entry(name.clone()).or_insert(0.0) += w;
        }
        _ => return false,
    }
    true
}
