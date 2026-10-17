//! Question- and reversibility-scoped escalation bands; learning starts in shadow.

use super::types::invalid;
use super::{DecisionBand, DecisionQuestion};
use crate::{EntityId, Result};
use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    ReversibleRead,
    OutboundEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BandMode {
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LearnedBand {
    pub band: DecisionBand,
    pub version: u32,
    pub mode: BandMode,
}

/// The owner's "ask a person?" row. A read whose P(ask a person) reaches `threshold`
/// goes to the person rung at the start. It starts high so asks stay rare; the Coach
/// tunes it from cases where a person changed the answer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PersonThreshold {
    pub threshold: f64,
    pub version: u32,
}

/// The "does this need more thinking?" row. A read whose paired P(yes) reaches
/// `threshold` steps to the next rung while the call has time. No row never steps on
/// it; the Coach tunes it from quick answers that later proved wrong.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThinkThreshold {
    pub threshold: f64,
    pub version: u32,
}

/// Vault-owned policy snapshot. No learned row means shadow at the dial's
/// seed band, not an implicit permission to enforce a global threshold.
/// No person row means a person reading never routes. Every clone shares one
/// person row, so the host's accepted row reaches each caller that cloned it.
#[derive(Debug, Clone, Default)]
pub struct DecisionBandPolicy {
    rows: BTreeMap<(EntityId, u32, Reversibility), LearnedBand>,
    person: Arc<RwLock<Option<PersonThreshold>>>,
    think: Option<ThinkThreshold>,
    questions_per_call: Option<usize>,
}

/// The questions-per-call row's value until the vault sets one.
pub const DEFAULT_QUESTIONS_PER_CALL: usize = 16;

impl DecisionBandPolicy {
    /// The questions-per-call row (Rule 5): a pack larger than it goes as several requests
    /// in turn under the same clock. A decision is never refused for count.
    pub fn set_questions_per_call(&mut self, count: usize) -> Result<()> {
        if count == 0 {
            return Err(invalid("invalid questions per call"));
        }
        self.questions_per_call = Some(count);
        Ok(())
    }

    pub fn questions_per_call(&self) -> usize {
        self.questions_per_call
            .unwrap_or(DEFAULT_QUESTIONS_PER_CALL)
    }

    pub fn set_person_threshold(&mut self, threshold: f64, version: u32) -> Result<()> {
        if !(threshold > 0.0 && threshold <= 1.0) || version == 0 {
            return Err(invalid("invalid person threshold"));
        }
        let mut person = self.person.write().unwrap_or_else(PoisonError::into_inner);
        if person.is_some_and(|row| row.version >= version) {
            return Err(invalid("person threshold version must advance"));
        }
        *person = Some(PersonThreshold { threshold, version });
        Ok(())
    }

    /// Replaces the shared person row with `row`, for every clone. Unlike
    /// [`Self::set_person_threshold`] the version may go back: a retracted
    /// revision gives way to the one before it.
    pub fn replace_person_threshold(&self, row: PersonThreshold) -> Result<()> {
        if !(row.threshold > 0.0 && row.threshold <= 1.0) || row.version == 0 {
            return Err(invalid("invalid person threshold"));
        }
        *self.person.write().unwrap_or_else(PoisonError::into_inner) = Some(row);
        Ok(())
    }

    pub fn set_think_threshold(&mut self, threshold: f64, version: u32) -> Result<()> {
        if !(threshold > 0.0 && threshold <= 1.0) || version == 0 {
            return Err(invalid("invalid think threshold"));
        }
        if self.think.is_some_and(|row| row.version >= version) {
            return Err(invalid("think threshold version must advance"));
        }
        self.think = Some(ThinkThreshold { threshold, version });
        Ok(())
    }

    pub fn think_threshold(&self) -> Option<ThinkThreshold> {
        self.think
    }

    pub fn person_threshold(&self) -> Option<PersonThreshold> {
        *self.person.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn learn_shadow(
        &mut self,
        question: &DecisionQuestion,
        reversibility: Reversibility,
        band: DecisionBand,
        version: u32,
    ) -> Result<()> {
        question.validate()?;
        band.validate()?;
        if version == 0 {
            return Err(invalid("invalid learned band version"));
        }
        let key = (question.id, question.version, reversibility);
        if self
            .rows
            .get(&key)
            .is_some_and(|row| row.version >= version)
        {
            return Err(invalid("learned band version must advance"));
        }
        self.rows.insert(
            key,
            LearnedBand {
                band,
                version,
                mode: BandMode::Shadow,
            },
        );
        Ok(())
    }

    pub fn enforce(
        &mut self,
        question: &DecisionQuestion,
        reversibility: Reversibility,
    ) -> Result<()> {
        question.validate()?;
        let row = self
            .rows
            .get_mut(&(question.id, question.version, reversibility))
            .ok_or_else(|| invalid("band must be learned before enforcement"))?;
        row.mode = BandMode::Enforce;
        Ok(())
    }

    pub fn resolve(
        &self,
        question: &DecisionQuestion,
        reversibility: Reversibility,
        seed: DecisionBand,
    ) -> Result<LearnedBand> {
        question.validate()?;
        seed.validate()?;
        Ok(self
            .rows
            .get(&(question.id, question.version, reversibility))
            .copied()
            .unwrap_or(LearnedBand {
                band: seed,
                version: 0,
                mode: BandMode::Shadow,
            }))
    }
}
