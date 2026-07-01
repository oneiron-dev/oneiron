use rmpv::Value;

use super::{VadDelta, decode_entity_ref, decode_vad_delta, reject_duplicate, vad_delta_value};
use crate::claim::{ClaimBody, ClaimSubject, unit_interval_f32};
use crate::error::{Error, Result};
use crate::types::{ClaimCandidate, EntityId};

pub const COPING_OUTCOME_PREDICATE: &str = "coping.outcome";

const KEY_AFFECTED_PERSON: &str = "affectedPerson";
const KEY_STRATEGY_REF: &str = "strategyRef";
const KEY_STRATEGY: &str = "strategy";
const KEY_VAD_DELTA: &str = "vadDelta";
const KEY_CONFIDENCE: &str = "confidence";
const KEY_SUCCESSFUL: &str = "successful";
const KEY_OBSERVED_N: &str = "observedN";
const EVIDENCE_KIND: &str = "coping_outcome_turn_vad_delta";
const EVIDENCE_KEY_KIND: &str = "kind";
const EVIDENCE_KEY_TURN: &str = "turn";
const EVIDENCE_KEY_DELTA: &str = "vadDelta";
const EVIDENCE_KEY_CONFIDENCE: &str = "confidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CopingStrategy {
    SitSel,
    SitMod,
    AttDep,
    CogChg,
    ResMod,
    ERFlex,
}

impl CopingStrategy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SitSel => "SitSel",
            Self::SitMod => "SitMod",
            Self::AttDep => "AttDep",
            Self::CogChg => "CogChg",
            Self::ResMod => "ResMod",
            Self::ERFlex => "ERFlex",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "SitSel" => Some(Self::SitSel),
            "SitMod" => Some(Self::SitMod),
            "AttDep" => Some(Self::AttDep),
            "CogChg" => Some(Self::CogChg),
            "ResMod" => Some(Self::ResMod),
            "ERFlex" => Some(Self::ERFlex),
            _ => None,
        }
    }
}

impl TryFrom<&str> for CopingStrategy {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value).ok_or(Error::InvalidClaimBody(
            "strategy must be SitSel|SitMod|AttDep|CogChg|ResMod|ERFlex",
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CopingOutcomeValue {
    affected_person: EntityId,
    strategy_ref: EntityId,
    strategy: CopingStrategy,
    vad_delta: VadDelta,
    confidence: f32,
    successful: bool,
    observed_n: u64,
}

impl CopingOutcomeValue {
    pub fn new(
        affected_person: EntityId,
        strategy_ref: EntityId,
        strategy: CopingStrategy,
        vad_delta: VadDelta,
        confidence: f32,
        observed_n: u64,
    ) -> Result<Self> {
        validate_confidence(confidence)?;
        if observed_n == 0 {
            return Err(Error::InvalidClaimBody("observedN must be positive"));
        }
        Ok(Self {
            affected_person,
            strategy_ref,
            strategy,
            vad_delta,
            confidence,
            successful: coping_delta_successful(vad_delta),
            observed_n,
        })
    }

    #[must_use]
    pub fn affected_person(&self) -> EntityId {
        self.affected_person
    }

    #[must_use]
    pub fn strategy_ref(&self) -> EntityId {
        self.strategy_ref
    }

    #[must_use]
    pub fn strategy(&self) -> CopingStrategy {
        self.strategy
    }

    #[must_use]
    pub fn vad_delta(&self) -> VadDelta {
        self.vad_delta
    }

    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    #[must_use]
    pub fn successful(&self) -> bool {
        self.successful
    }

    #[must_use]
    pub fn observed_n(&self) -> u64 {
        self.observed_n
    }

    pub fn with_observation(&self, vad_delta: VadDelta, confidence: f32) -> Result<Self> {
        validate_confidence(confidence)?;
        let observed_n = self
            .observed_n
            .checked_add(1)
            .ok_or(Error::InvalidClaimBody("observedN overflow"))?;
        let prior_n = self.observed_n as f64;
        let next_n = observed_n as f64;
        let averaged_delta = VadDelta::new(
            ((f64::from(self.vad_delta.valence()) * prior_n + f64::from(vad_delta.valence()))
                / next_n) as f32,
            ((f64::from(self.vad_delta.arousal()) * prior_n + f64::from(vad_delta.arousal()))
                / next_n) as f32,
            ((f64::from(self.vad_delta.dominance()) * prior_n + f64::from(vad_delta.dominance()))
                / next_n) as f32,
        )?;
        let averaged_confidence =
            ((f64::from(self.confidence) * prior_n + f64::from(confidence)) / next_n) as f32;
        Self::new(
            self.affected_person,
            self.strategy_ref,
            self.strategy,
            averaged_delta,
            averaged_confidence,
            observed_n,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CopingOutcomeRecord {
    pub claim_id: EntityId,
    pub learned_at: u64,
    pub valid_from: u64,
    pub valid_to: Option<u64>,
    pub value: CopingOutcomeValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CopingOutcomeUpdate {
    pub prior_claim_id: EntityId,
    pub active_claim_id: EntityId,
    pub superseded_claim_ids: Vec<EntityId>,
    pub value: CopingOutcomeValue,
}

#[must_use]
pub fn coping_delta_successful(delta: VadDelta) -> bool {
    delta.valence() > 0.0 || delta.arousal() < 0.0 || delta.dominance() > 0.0
}

#[must_use]
pub fn coping_outcome_value(value: &CopingOutcomeValue) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_AFFECTED_PERSON),
            Value::from(value.affected_person.to_hex()),
        ),
        (
            Value::from(KEY_STRATEGY_REF),
            Value::from(value.strategy_ref.to_hex()),
        ),
        (
            Value::from(KEY_STRATEGY),
            Value::from(value.strategy.as_str()),
        ),
        (Value::from(KEY_VAD_DELTA), vad_delta_value(value.vad_delta)),
        (Value::from(KEY_CONFIDENCE), Value::F32(value.confidence)),
        (
            Value::from(KEY_SUCCESSFUL),
            Value::Boolean(value.successful),
        ),
        (Value::from(KEY_OBSERVED_N), Value::from(value.observed_n)),
    ])
}

pub fn decode_coping_outcome_value(value: &Value) -> Result<CopingOutcomeValue> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "coping.outcome value must be a map",
        ));
    };

    let mut affected_person = None;
    let mut strategy_ref = None;
    let mut strategy = None;
    let mut vad_delta = None;
    let mut confidence = None;
    let mut successful = None;
    let mut observed_n = None;
    let mut seen_affected_person = false;
    let mut seen_strategy_ref = false;
    let mut seen_strategy = false;
    let mut seen_vad_delta = false;
    let mut seen_confidence = false;
    let mut seen_successful = false;
    let mut seen_observed_n = false;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody(
                "coping.outcome value keys must be strings",
            ));
        };
        match key {
            KEY_AFFECTED_PERSON => {
                reject_duplicate(
                    &mut seen_affected_person,
                    "duplicate coping.outcome value key",
                )?;
                affected_person = Some(decode_entity_ref(
                    value,
                    "affectedPerson must be a canonical entity ref",
                )?);
            }
            KEY_STRATEGY_REF => {
                reject_duplicate(&mut seen_strategy_ref, "duplicate coping.outcome value key")?;
                strategy_ref = Some(decode_entity_ref(
                    value,
                    "strategyRef must be a canonical entity ref",
                )?);
            }
            KEY_STRATEGY => {
                reject_duplicate(&mut seen_strategy, "duplicate coping.outcome value key")?;
                let Some(raw_strategy) = value.as_str() else {
                    return Err(Error::InvalidClaimBody("strategy must be a string"));
                };
                strategy = Some(CopingStrategy::try_from(raw_strategy)?);
            }
            KEY_VAD_DELTA => {
                reject_duplicate(&mut seen_vad_delta, "duplicate coping.outcome value key")?;
                vad_delta = Some(decode_vad_delta(value)?);
            }
            KEY_CONFIDENCE => {
                reject_duplicate(&mut seen_confidence, "duplicate coping.outcome value key")?;
                confidence = Some(unit_interval_f32(value).ok_or(Error::InvalidClaimBody(
                    "coping.outcome confidence must be finite in [0, 1]",
                ))?);
            }
            KEY_SUCCESSFUL => {
                reject_duplicate(&mut seen_successful, "duplicate coping.outcome value key")?;
                let Value::Boolean(value) = value else {
                    return Err(Error::InvalidClaimBody("successful must be a boolean"));
                };
                successful = Some(*value);
            }
            KEY_OBSERVED_N => {
                reject_duplicate(&mut seen_observed_n, "duplicate coping.outcome value key")?;
                let observed = value.as_u64().ok_or(Error::InvalidClaimBody(
                    "observedN must be a positive integer",
                ))?;
                if observed == 0 {
                    return Err(Error::InvalidClaimBody("observedN must be positive"));
                }
                observed_n = Some(observed);
            }
            _ => {
                return Err(Error::InvalidClaimBody(
                    "coping.outcome value key is not in the pinned set",
                ));
            }
        }
    }

    let outcome = CopingOutcomeValue::new(
        affected_person.ok_or(Error::InvalidClaimBody("missing affectedPerson"))?,
        strategy_ref.ok_or(Error::InvalidClaimBody("missing strategyRef"))?,
        strategy.ok_or(Error::InvalidClaimBody("missing strategy"))?,
        vad_delta.ok_or(Error::InvalidClaimBody("missing vadDelta"))?,
        confidence.ok_or(Error::InvalidClaimBody("missing coping.outcome confidence"))?,
        observed_n.ok_or(Error::InvalidClaimBody("missing observedN"))?,
    )?;
    if successful != Some(outcome.successful) {
        return Err(Error::InvalidClaimBody(
            "successful must match the coping.outcome VAD delta",
        ));
    }
    Ok(outcome)
}

pub fn decode_coping_outcome_claim(body: &ClaimBody) -> Result<Option<CopingOutcomeValue>> {
    if body.predicate != COPING_OUTCOME_PREDICATE {
        return Ok(None);
    }
    Ok(Some(decode_coping_outcome_value(&body.value)?))
}

#[must_use]
pub fn coping_outcome_claim_candidate(
    value: CopingOutcomeValue,
    valid_from: u64,
) -> ClaimCandidate {
    ClaimCandidate::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(value.affected_person),
        coping_outcome_value(&value),
        value.confidence,
    )
    .with_validity(Some(valid_from), None)
}

#[must_use]
pub(crate) fn coping_outcome_evidence_value(
    turn_id: EntityId,
    vad_delta: VadDelta,
    confidence: f32,
) -> Value {
    Value::Map(vec![
        (Value::from(EVIDENCE_KEY_KIND), Value::from(EVIDENCE_KIND)),
        (
            Value::from(EVIDENCE_KEY_TURN),
            Value::Binary(turn_id.as_bytes().to_vec()),
        ),
        (Value::from(EVIDENCE_KEY_DELTA), vad_delta_value(vad_delta)),
        (Value::from(EVIDENCE_KEY_CONFIDENCE), Value::F32(confidence)),
    ])
}

pub(crate) fn validate_coping_outcome_claim_structure(body: &ClaimBody) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "coping.outcome subject must be an entity",
        ));
    };
    let value = decode_coping_outcome_value(&body.value)?;
    if value.affected_person != subject {
        return Err(Error::InvalidClaimBody(
            "coping.outcome affectedPerson must match subject",
        ));
    }
    if body.confidence.to_bits() != value.confidence.to_bits() {
        return Err(Error::InvalidClaimBody(
            "coping.outcome wrapper confidence must mirror value confidence",
        ));
    }
    let valid_from = body.valid_from.ok_or(Error::InvalidClaimBody(
        "coping.outcome valid_from is required",
    ))?;
    if let Some(valid_to) = body.valid_to
        && valid_to < valid_from
    {
        return Err(Error::InvalidClaimBody(
            "coping.outcome valid_to must not precede valid_from",
        ));
    }
    Ok(())
}

fn validate_confidence(confidence: f32) -> Result<()> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(Error::InvalidClaimBody(
            "coping.outcome confidence must be finite in [0, 1]",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coping_outcome_strategy_round_trips_contract_names() {
        for strategy in [
            CopingStrategy::SitSel,
            CopingStrategy::SitMod,
            CopingStrategy::AttDep,
            CopingStrategy::CogChg,
            CopingStrategy::ResMod,
            CopingStrategy::ERFlex,
        ] {
            assert_eq!(CopingStrategy::parse(strategy.as_str()), Some(strategy));
        }
        assert_eq!(CopingStrategy::parse("sit_sel"), None);
    }
}
