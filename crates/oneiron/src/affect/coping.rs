use rmpv::Value;

use super::{
    Vad, VadDelta, decode_entity_ref, decode_vad_delta, reject_duplicate, vad_delta_value,
};
use crate::claim::{ClaimBody, ClaimSubject, unit_interval_f32};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::ClaimCandidate;

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimLifecycleStatus, ClaimSource, claim_consolidatable, encode_claim_body};
use crate::edge::EdgeKind;
use crate::error::ClaimError;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, SUPERSEDES_DEFAULT_WEIGHT};

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
fn coping_outcome_evidence_value(turn_id: EntityId, vad_delta: VadDelta, confidence: f32) -> Value {
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

impl Vault {
    /// Updates an active `coping.outcome` claim from two turn-level VAD
    /// annotations. The baseline turn supplies the before state; the later
    /// turn supplies the after state.
    pub fn update_coping_outcome_from_turn_vad(
        &self,
        prior_claim_id: &EntityId,
        baseline_turn_id: &EntityId,
        later_turn_id: &EntityId,
        confidence: f32,
        now: u64,
    ) -> Result<CopingOutcomeUpdate> {
        let baseline =
            self.get_turn_vad_annotation(baseline_turn_id)?
                .ok_or(Error::InvalidClaimBody(
                    "baseline turn VAD annotation missing",
                ))?;
        let later = self
            .get_turn_vad_annotation(later_turn_id)?
            .ok_or(Error::InvalidClaimBody("later turn VAD annotation missing"))?;
        let delta = VadDelta::new(
            later.vad.valence - baseline.vad.valence,
            later.vad.arousal - baseline.vad.arousal,
            later.vad.dominance - baseline.vad.dominance,
        )?;
        self.update_coping_outcome_from_turn_vad_delta_checked(
            prior_claim_id,
            *later_turn_id,
            delta,
            confidence,
            now,
            Some(*baseline_turn_id),
        )
    }

    /// Supersedes an active `coping.outcome` claim with an updated aggregate
    /// derived from a later turn-level VAD delta.
    pub fn update_coping_outcome_from_turn_vad_delta(
        &self,
        prior_claim_id: &EntityId,
        turn_id: EntityId,
        vad_delta: VadDelta,
        confidence: f32,
        now: u64,
    ) -> Result<CopingOutcomeUpdate> {
        self.update_coping_outcome_from_turn_vad_delta_checked(
            prior_claim_id,
            turn_id,
            vad_delta,
            confidence,
            now,
            None,
        )
    }

    fn update_coping_outcome_from_turn_vad_delta_checked(
        &self,
        prior_claim_id: &EntityId,
        turn_id: EntityId,
        vad_delta: VadDelta,
        confidence: f32,
        now: u64,
        expected_strategy_ref: Option<EntityId>,
    ) -> Result<CopingOutcomeUpdate> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, prior_claim_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let prior_body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if prior_body.predicate != COPING_OUTCOME_PREDICATE {
            return Err(Error::InvalidClaimBody("claim is not a coping.outcome"));
        }
        if prior_body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::Claim(ClaimError::ClaimAlreadyClosed {
                status: prior_body.lifecycle,
            }));
        }
        if !claim_consolidatable(&prior_body) {
            return Err(Error::InvalidClaimBody("claim is not consolidatable"));
        }
        let prior_value = decode_coping_outcome_claim(&prior_body)?
            .ok_or(Error::InvalidClaimBody("claim is not a coping.outcome"))?;
        if let Some(expected_strategy_ref) = expected_strategy_ref
            && prior_value.strategy_ref() != expected_strategy_ref
        {
            return Err(Error::InvalidClaimBody(
                "baseline turn must match coping.outcome strategyRef",
            ));
        }
        let prior_valid_from = prior_body.valid_from.ok_or(Error::InvalidClaimBody(
            "coping.outcome valid_from is required",
        ))?;
        if now < prior_valid_from || now < header.occurred_start {
            return Err(Error::InvalidClaimBody(
                "coping.outcome update timestamp must not precede active valid_from",
            ));
        }
        let updated_value = prior_value.with_observation(vad_delta, confidence)?;
        let ClaimSubject::Entity(subject) = prior_body.subject else {
            return Err(Error::InvalidClaimBody(
                "coping.outcome subject must be an entity",
            ));
        };

        let new_claim_id = EntityId::now();
        let mut closed = prior_body.clone();
        closed.lifecycle = ClaimLifecycleStatus::Superseded;
        closed.valid_to = Some(now);
        let closed_data = encode_claim_body(&closed)?;

        let mut updated_body = ClaimBody::new(
            COPING_OUTCOME_PREDICATE,
            prior_body.subject,
            coping_outcome_value(&updated_value),
            updated_value.confidence(),
            prior_body.approval,
            ClaimLifecycleStatus::Active,
        );
        updated_body.salience = prior_body.salience;
        updated_body.evidence = Some(coping_outcome_evidence_value(
            turn_id, vad_delta, confidence,
        ));
        updated_body.source = Some(ClaimSource::Inferred);
        updated_body.valid_from = Some(now);
        updated_body.world = prior_body.world;
        updated_body.scope = prior_body.scope;
        let updated_data = encode_claim_body(&updated_body)?;

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![
                BatchOp::Put {
                    id: *prior_claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: header.occurred_start,
                        end: now,
                    },
                    learned_at: header.learned_at,
                    data: closed_data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                BatchOp::Put {
                    id: new_claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: u64::MAX,
                    },
                    learned_at: now,
                    data: updated_data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                BatchOp::Edge {
                    src: new_claim_id,
                    kind: EdgeKind::ClaimOf,
                    tgt: subject,
                    weight: CLAIM_OF_DEFAULT_WEIGHT,
                    vad: Vad::NEUTRAL,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: new_claim_id,
                    kind: EdgeKind::Supersedes,
                    tgt: *prior_claim_id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;

        Ok(CopingOutcomeUpdate {
            prior_claim_id: *prior_claim_id,
            active_claim_id: new_claim_id,
            superseded_claim_ids: vec![*prior_claim_id],
            value: updated_value,
        })
    }
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
