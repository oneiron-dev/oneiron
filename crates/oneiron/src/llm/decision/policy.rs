//! Question- and reversibility-scoped escalation bands; learning starts in shadow.

use super::types::invalid;
use super::{DecisionBand, DecisionQuestion};
use crate::{EntityId, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reversibility {
    ReversibleRead,
    OutboundEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Vault-owned policy snapshot. No learned row means shadow at the dial's
/// seed band, not an implicit permission to enforce a global threshold.
#[derive(Debug, Clone, Default)]
pub struct DecisionBandPolicy {
    rows: BTreeMap<(EntityId, u32, Reversibility), LearnedBand>,
}

impl DecisionBandPolicy {
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
