//! Provenance-carrying composite state for mode selection, never a diagnostic label.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::Vad;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};

/// Input claims use unit-interval values. Producers own measurement, not this projection.
pub const GOAL_VELOCITY: &str = "state.goal_velocity";
pub const ENGAGEMENT: &str = "state.engagement";
pub const COMPOSITE_INDEX: &str = "state.composite_index";

/// Evidence selected by a derived/Dreamer pass. Each reference must resolve in the vault.
#[derive(Debug, Clone)]
pub struct StateIndexEvidence {
    pub vad_turns: Vec<EntityId>,
    pub goal_velocity: EntityId,
    pub engagement: EntityId,
}

/// Numerical inputs retained so an agent can make its own mode decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModeGateInputs {
    pub affect: f32,
    pub goal_velocity: f32,
    pub engagement: f32,
}

/// Unknown subjects return a neutral 0.5 with no inputs or claim. Absence is not evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateIndex {
    pub value: f32,
    pub inputs: Option<ModeGateInputs>,
    pub claim: Option<String>,
    pub observed_at: Option<u64>,
}
impl Default for StateIndex {
    fn default() -> Self {
        Self {
            value: 0.5,
            inputs: None,
            claim: None,
            observed_at: None,
        }
    }
}

impl Vault {
    /// Blend the mean VAD trajectory, goal velocity and engagement with equal weight.
    /// VAD is normalized to the unit interval; high arousal alone is not judged adverse.
    /// All three signal families are required. Repeating identical evidence is a no-op.
    pub fn derive_state_index(
        &self,
        subject: &EntityId,
        evidence: &StateIndexEvidence,
        at: u64,
    ) -> Result<EntityId> {
        if evidence.vad_turns.is_empty() || evidence.vad_turns.len() > 256 {
            return Err(Error::InvalidClaimBody(
                "state index needs 1..=256 VAD turns",
            ));
        }
        let mut turns = evidence.vad_turns.clone();
        turns.sort();
        turns.dedup();
        self.with_write_txn(|txn| {
            let mut mean = Vad::NEUTRAL;
            let mut count = 0.0_f32;
            for turn in &turns {
                let annotation = self
                    .turn_vad_annotation_in_txn(txn, turn)?
                    .ok_or(Error::EntityNotFound)?;
                annotation.vad.validate()?;
                if annotation.annotated_at > at {
                    return Err(Error::InvalidClaimBody(
                        "state index cannot cite future signals",
                    ));
                }
                count += 1.0;
                mean.valence += (annotation.vad.valence - mean.valence) / count;
                mean.arousal += (annotation.vad.arousal - mean.arousal) / count;
                mean.dominance += (annotation.vad.dominance - mean.dominance) / count;
            }
            let signal = |id: &EntityId, predicate: &str| -> Result<f32> {
                let body = self
                    .get_claim_in_txn(txn, id)?
                    .ok_or(Error::EntityNotFound)?;
                if body.subject != ClaimSubject::Entity(*subject)
                    || body.predicate != predicate
                    || body.lifecycle != ClaimLifecycleStatus::Active
                    || body.stale
                    || !matches!(
                        body.approval,
                        ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
                    )
                    || body.valid_from.is_some_and(|start| start > at)
                    || body.valid_to.is_some_and(|end| end <= at)
                {
                    return Err(Error::InvalidClaimBody("state index signal does not apply"));
                }
                match body.value {
                    Value::F32(value) if value.is_finite() && (0.0..=1.0).contains(&value) => {
                        Ok(value)
                    }
                    Value::F64(value) if value.is_finite() && (0.0..=1.0).contains(&value) => {
                        Ok(value as f32)
                    }
                    _ => Err(Error::InvalidClaimBody(
                        "state index signal must be a unit float",
                    )),
                }
            };
            let inputs = ModeGateInputs {
                affect: ((mean.valence + 1.0) / 2.0 + mean.arousal + mean.dominance) / 3.0,
                goal_velocity: signal(&evidence.goal_velocity, GOAL_VELOCITY)?,
                engagement: signal(&evidence.engagement, ENGAGEMENT)?,
            };
            let value = Value::Map(vec![
                (
                    Value::from("value"),
                    Value::F32((inputs.affect + inputs.goal_velocity + inputs.engagement) / 3.0),
                ),
                (Value::from("affect"), Value::F32(inputs.affect)),
                (
                    Value::from("goal_velocity"),
                    Value::F32(inputs.goal_velocity),
                ),
                (Value::from("engagement"), Value::F32(inputs.engagement)),
            ]);
            let refs = Value::Array(
                turns
                    .iter()
                    .chain([&evidence.goal_velocity, &evidence.engagement])
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            );
            let mut previous = Vec::new();
            let mut matching = None;
            for id in self.claims_for_subject_in_txn(txn, subject)? {
                let Some(body) = self.get_claim_in_txn(txn, &id)? else {
                    continue;
                };
                if body.predicate != COMPOSITE_INDEX
                    || body.lifecycle != ClaimLifecycleStatus::Active
                    || body.stale
                    || !matches!(
                        body.approval,
                        ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
                    )
                {
                    continue;
                }
                if body.valid_from.is_some_and(|start| start > at) {
                    return Err(Error::InvalidClaimBody(
                        "state index refuses a stale projection",
                    ));
                }
                if body.value == value && body.evidence.as_ref() == Some(&refs) {
                    matching = Some(id);
                }
                previous.push(id);
            }
            if let Some(id) = matching {
                return Ok(id);
            }
            let id = EntityId::now();
            let mut body = ClaimBody::new(
                COMPOSITE_INDEX,
                ClaimSubject::Entity(*subject),
                value,
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.source = Some(ClaimSource::Observed);
            body.valid_from = Some(at);
            body.evidence = Some(refs);
            self.put_claim_in_txn(txn, &id, &body, TimeRange { start: at, end: at }, at)?;
            for old in previous {
                self.supersede_claim_in_txn(txn, &id, &old, at)?;
            }
            Ok(id)
        })
    }

    /// Latest scalar and its mode-gate inputs. Unknown subjects have a neutral, explicitly absent default.
    pub fn state_index(&self, subject: &EntityId) -> Result<StateIndex> {
        self.state_index_at(subject, crate::unix_seconds_now())
    }

    /// Read the current projection at an explicit clock without treating future rows as current.
    pub fn state_index_at(&self, subject: &EntityId, now: u64) -> Result<StateIndex> {
        let txn = self.store.env.read_txn()?;
        let mut latest = None;
        for id in self.claims_for_subject_in_txn(&txn, subject)? {
            let Some(body) = self.get_claim_in_txn(&txn, &id)? else {
                continue;
            };
            if body.predicate != COMPOSITE_INDEX
                || body.valid_from.is_some_and(|at| at > now)
                || body.valid_to.is_some_and(|at| at <= now)
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.stale
                || !matches!(
                    body.approval,
                    ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
                )
            {
                continue;
            }
            let key = (body.valid_from.unwrap_or(0), id);
            if latest.as_ref().is_none_or(|(held, _)| key > *held) {
                latest = Some((key, body));
            }
        }
        let Some(((at, id), body)) = latest else {
            return Ok(StateIndex::default());
        };
        let field = |name: &str| -> Result<f32> {
            let Value::Map(fields) = &body.value else {
                return Err(Error::InvalidClaimBody("invalid composite index"));
            };
            match fields
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
            {
                Some(Value::F32(value)) if value.is_finite() && (0.0..=1.0).contains(value) => {
                    Ok(*value)
                }
                _ => Err(Error::InvalidClaimBody("invalid composite index component")),
            }
        };
        Ok(StateIndex {
            value: field("value")?,
            inputs: Some(ModeGateInputs {
                affect: field("affect")?,
                goal_velocity: field("goal_velocity")?,
                engagement: field("engagement")?,
            }),
            claim: Some(id.to_hex()),
            observed_at: Some(at),
        })
    }
}

impl crate::memory::Memory<'_> {
    /// Read the composite state through the transport-neutral agent facade.
    pub fn state_index(&self, subject_ref: &str) -> crate::memory::MemoryResult<StateIndex> {
        let subject = crate::memory::resolve_entity_ref(self.vault(), subject_ref)?;
        Ok(self.vault().state_index(&subject)?)
    }
}

#[cfg(test)]
mod tests;
