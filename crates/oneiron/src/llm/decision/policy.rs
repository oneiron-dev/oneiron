//! Question- and reversibility-scoped escalation bands; learning starts in shadow.

use super::types::invalid;
use super::{DecisionBand, DecisionQuestion};
use crate::{EntityId, Result};
use std::collections::BTreeMap;

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

/// Vault-owned policy snapshot. No learned row means shadow at the dial's
/// seed band, not an implicit permission to enforce a global threshold.
/// No person row means a person reading never routes.
#[derive(Debug, Clone, Default)]
pub struct DecisionBandPolicy {
    rows: BTreeMap<(EntityId, u32, Reversibility), LearnedBand>,
    person: Option<PersonThreshold>,
}

impl DecisionBandPolicy {
    pub fn set_person_threshold(&mut self, threshold: f64, version: u32) -> Result<()> {
        if !(threshold > 0.0 && threshold <= 1.0) || version == 0 {
            return Err(invalid("invalid person threshold"));
        }
        if self.person.is_some_and(|row| row.version >= version) {
            return Err(invalid("person threshold version must advance"));
        }
        self.person = Some(PersonThreshold { threshold, version });
        Ok(())
    }

    pub fn person_threshold(&self) -> Option<PersonThreshold> {
        self.person
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
