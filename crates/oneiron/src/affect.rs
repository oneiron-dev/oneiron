use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject, unit_interval_f32};
use crate::error::{Error, Result};
use crate::types::{ClaimCandidate, ENTITY_ID_LEN, EntityId, Vad, VadAnnotation};

pub mod coping;

pub const AFFECT_TRIGGER_PREDICATE: &str = "affect.trigger";
pub const CLAIM_VAD_REAPPRAISAL_PREDICATE: &str = "affect.claim_vad";

const AFFECT_TRIGGER_KEY_AFFECTED_PERSON: &str = "affectedPerson";
const AFFECT_TRIGGER_KEY_TRIGGER_REF: &str = "triggerRef";
const AFFECT_TRIGGER_KEY_VAD_DELTA: &str = "vadDelta";
const AFFECT_TRIGGER_KEY_CONFIDENCE: &str = "confidence";
const AFFECT_TRIGGER_KEY_K: &str = "k";
const AFFECT_TRIGGER_KEY_OBSERVED_N: &str = "observedN";
const AFFECT_TRIGGER_VAD_KEY_VALENCE: &str = "valence";
const AFFECT_TRIGGER_VAD_KEY_AROUSAL: &str = "arousal";
const AFFECT_TRIGGER_VAD_KEY_DOMINANCE: &str = "dominance";
const CLAIM_VAD_KEY_VALENCE: &str = "valence";
const CLAIM_VAD_KEY_AROUSAL: &str = "arousal";
const CLAIM_VAD_KEY_DOMINANCE: &str = "dominance";
const CLAIM_VAD_KEY_TURN_COUNT: &str = "turn_count";
const CLAIM_VAD_EVIDENCE_KIND: &str = "claim_vad_turn_vad";
const CLAIM_VAD_EVIDENCE_KEY_KIND: &str = "kind";
const CLAIM_VAD_EVIDENCE_KEY_TURNS: &str = "turns";
const CLAIM_VAD_EVIDENCE_KEY_TURN: &str = "turn";
const CLAIM_VAD_EVIDENCE_KEY_VAD: &str = "vad";
const CLAIM_VAD_EVIDENCE_KEY_SOURCE: &str = "source";
const CLAIM_VAD_EVIDENCE_KEY_ANNOTATED_AT: &str = "annotated_at";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VadDelta {
    valence: f32,
    arousal: f32,
    dominance: f32,
}

impl VadDelta {
    pub fn new(valence: f32, arousal: f32, dominance: f32) -> Result<Self> {
        let delta = Self {
            valence,
            arousal,
            dominance,
        };
        delta.validate()?;
        Ok(delta)
    }

    pub(crate) fn validate(self) -> Result<()> {
        validate_delta_component(self.valence, -2.0, 2.0, "vadDelta valence")?;
        validate_delta_component(self.arousal, -1.0, 1.0, "vadDelta arousal")?;
        validate_delta_component(self.dominance, -1.0, 1.0, "vadDelta dominance")
    }

    #[must_use]
    pub fn valence(self) -> f32 {
        self.valence
    }

    #[must_use]
    pub fn arousal(self) -> f32 {
        self.arousal
    }

    #[must_use]
    pub fn dominance(self) -> f32 {
        self.dominance
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AffectTriggerValue {
    affected_person: EntityId,
    trigger_ref: EntityId,
    vad_delta: VadDelta,
    confidence: f32,
    k: u64,
    observed_n: u64,
}

impl AffectTriggerValue {
    pub fn new(
        affected_person: EntityId,
        trigger_ref: EntityId,
        vad_delta: VadDelta,
        confidence: f32,
        k: u64,
        observed_n: u64,
    ) -> Result<Self> {
        vad_delta.validate()?;
        validate_trigger_confidence(confidence)?;
        if observed_n == 0 {
            return Err(Error::InvalidClaimBody("observedN must be positive"));
        }
        Ok(Self {
            affected_person,
            trigger_ref,
            vad_delta,
            confidence,
            k,
            observed_n,
        })
    }

    #[must_use]
    pub fn affected_person(&self) -> EntityId {
        self.affected_person
    }

    #[must_use]
    pub fn trigger_ref(&self) -> EntityId {
        self.trigger_ref
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
    pub fn k(&self) -> u64 {
        self.k
    }

    #[must_use]
    pub fn observed_n(&self) -> u64 {
        self.observed_n
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClaimVadTurnEvidence {
    pub turn_id: EntityId,
    pub annotation: VadAnnotation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimVadReappraisal {
    pub active_claim_id: Option<EntityId>,
    pub created_claim_id: Option<EntityId>,
    pub superseded_claim_ids: Vec<EntityId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimVadConsolidation {
    pub claim_id: EntityId,
    pub vad: Option<Vad>,
    pub evidence_turns: Vec<ClaimVadTurnEvidence>,
    pub semantic_edges_updated: usize,
    pub structural_edges_skipped: usize,
    pub reappraisal: ClaimVadReappraisal,
}

pub(crate) fn collect_claim_turn_evidence_refs(body: &ClaimBody) -> Vec<EntityId> {
    let mut ids = BTreeSet::new();
    if let ClaimSubject::Entity(subject) = body.subject {
        ids.insert(subject);
    }
    if let Some(evidence) = &body.evidence {
        collect_entity_refs_from_value(evidence, &mut ids);
    }
    ids.into_iter().collect()
}

pub(crate) fn mean_vad(evidence: &[ClaimVadTurnEvidence]) -> Option<Vad> {
    if evidence.is_empty() {
        return None;
    }

    let len = evidence.len() as f64;
    let mut valence = 0.0_f64;
    let mut arousal = 0.0_f64;
    let mut dominance = 0.0_f64;
    for item in evidence {
        valence += f64::from(item.annotation.vad.valence);
        arousal += f64::from(item.annotation.vad.arousal);
        dominance += f64::from(item.annotation.vad.dominance);
    }
    Some(Vad {
        valence: clamp_mean((valence / len) as f32, -1.0, 1.0),
        arousal: clamp_mean((arousal / len) as f32, 0.0, 1.0),
        dominance: clamp_mean((dominance / len) as f32, 0.0, 1.0),
    })
}

fn clamp_mean(value: f32, min: f32, max: f32) -> f32 {
    value.clamp(min, max)
}

#[must_use]
pub fn affect_trigger_value(value: &AffectTriggerValue) -> Value {
    Value::Map(vec![
        (
            Value::from(AFFECT_TRIGGER_KEY_AFFECTED_PERSON),
            Value::from(value.affected_person.to_hex()),
        ),
        (
            Value::from(AFFECT_TRIGGER_KEY_TRIGGER_REF),
            Value::from(value.trigger_ref.to_hex()),
        ),
        (
            Value::from(AFFECT_TRIGGER_KEY_VAD_DELTA),
            vad_delta_value(value.vad_delta),
        ),
        (
            Value::from(AFFECT_TRIGGER_KEY_CONFIDENCE),
            Value::F32(value.confidence),
        ),
        (Value::from(AFFECT_TRIGGER_KEY_K), Value::from(value.k)),
        (
            Value::from(AFFECT_TRIGGER_KEY_OBSERVED_N),
            Value::from(value.observed_n),
        ),
    ])
}

pub fn decode_affect_trigger_value(value: &Value) -> Result<AffectTriggerValue> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "affect.trigger value must be a map",
        ));
    };

    let mut affected_person = None;
    let mut trigger_ref = None;
    let mut vad_delta = None;
    let mut confidence = None;
    let mut k = None;
    let mut observed_n = None;
    let mut seen_affected_person = false;
    let mut seen_trigger_ref = false;
    let mut seen_vad_delta = false;
    let mut seen_confidence = false;
    let mut seen_k = false;
    let mut seen_observed_n = false;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody(
                "affect.trigger value keys must be strings",
            ));
        };
        match key {
            AFFECT_TRIGGER_KEY_AFFECTED_PERSON => {
                reject_duplicate(
                    &mut seen_affected_person,
                    "duplicate affect.trigger value key",
                )?;
                affected_person = Some(decode_entity_ref(
                    value,
                    "affectedPerson must be a canonical entity ref",
                )?);
            }
            AFFECT_TRIGGER_KEY_TRIGGER_REF => {
                reject_duplicate(&mut seen_trigger_ref, "duplicate affect.trigger value key")?;
                trigger_ref = Some(decode_entity_ref(
                    value,
                    "triggerRef must be a canonical entity ref",
                )?);
            }
            AFFECT_TRIGGER_KEY_VAD_DELTA => {
                reject_duplicate(&mut seen_vad_delta, "duplicate affect.trigger value key")?;
                vad_delta = Some(decode_vad_delta(value)?);
            }
            AFFECT_TRIGGER_KEY_CONFIDENCE => {
                reject_duplicate(&mut seen_confidence, "duplicate affect.trigger value key")?;
                confidence = Some(unit_interval_f32(value).ok_or(Error::InvalidClaimBody(
                    "affect.trigger confidence must be finite in [0, 1]",
                ))?);
            }
            AFFECT_TRIGGER_KEY_K => {
                reject_duplicate(&mut seen_k, "duplicate affect.trigger value key")?;
                k = Some(
                    value
                        .as_u64()
                        .ok_or(Error::InvalidClaimBody("k must be a non-negative integer"))?,
                );
            }
            AFFECT_TRIGGER_KEY_OBSERVED_N => {
                reject_duplicate(&mut seen_observed_n, "duplicate affect.trigger value key")?;
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
                    "affect.trigger value key is not in the pinned set",
                ));
            }
        }
    }

    AffectTriggerValue::new(
        affected_person.ok_or(Error::InvalidClaimBody("missing affectedPerson"))?,
        trigger_ref.ok_or(Error::InvalidClaimBody("missing triggerRef"))?,
        vad_delta.ok_or(Error::InvalidClaimBody("missing vadDelta"))?,
        confidence.ok_or(Error::InvalidClaimBody("missing affect.trigger confidence"))?,
        k.ok_or(Error::InvalidClaimBody("missing k"))?,
        observed_n.ok_or(Error::InvalidClaimBody("missing observedN"))?,
    )
}

pub fn decode_affect_trigger_claim(body: &ClaimBody) -> Result<Option<AffectTriggerValue>> {
    if body.predicate != AFFECT_TRIGGER_PREDICATE {
        return Ok(None);
    }
    Ok(Some(decode_affect_trigger_value(&body.value)?))
}

#[must_use]
pub fn affect_trigger_claim_candidate(value: AffectTriggerValue) -> ClaimCandidate {
    ClaimCandidate::new(
        AFFECT_TRIGGER_PREDICATE,
        ClaimSubject::Entity(value.affected_person),
        affect_trigger_value(&value),
        value.confidence,
    )
}

pub(crate) fn validate_affect_trigger_claim_structure(body: &ClaimBody) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "affect.trigger subject must be an entity",
        ));
    };
    let value = decode_affect_trigger_value(&body.value)?;
    if value.affected_person != subject {
        return Err(Error::InvalidClaimBody(
            "affect.trigger affectedPerson must match subject",
        ));
    }
    if body.confidence.to_bits() != value.confidence.to_bits() {
        return Err(Error::InvalidClaimBody(
            "affect.trigger wrapper confidence must mirror value confidence",
        ));
    }
    Ok(())
}

pub(crate) fn claim_vad_value(vad: Vad, turn_count: usize) -> Value {
    Value::Map(vec![
        (Value::from(CLAIM_VAD_KEY_VALENCE), Value::F32(vad.valence)),
        (Value::from(CLAIM_VAD_KEY_AROUSAL), Value::F32(vad.arousal)),
        (
            Value::from(CLAIM_VAD_KEY_DOMINANCE),
            Value::F32(vad.dominance),
        ),
        (
            Value::from(CLAIM_VAD_KEY_TURN_COUNT),
            Value::from(turn_count as u64),
        ),
    ])
}

pub(crate) fn claim_vad_evidence_value(evidence: &[ClaimVadTurnEvidence]) -> Value {
    let turns = evidence
        .iter()
        .map(|item| {
            Value::Map(vec![
                (
                    Value::from(CLAIM_VAD_EVIDENCE_KEY_TURN),
                    Value::Binary(item.turn_id.as_bytes().to_vec()),
                ),
                (
                    Value::from(CLAIM_VAD_EVIDENCE_KEY_VAD),
                    vad_value(item.annotation.vad),
                ),
                (
                    Value::from(CLAIM_VAD_EVIDENCE_KEY_SOURCE),
                    Value::from(item.annotation.source.as_str()),
                ),
                (
                    Value::from(CLAIM_VAD_EVIDENCE_KEY_ANNOTATED_AT),
                    Value::from(item.annotation.annotated_at),
                ),
            ])
        })
        .collect();

    Value::Map(vec![
        (
            Value::from(CLAIM_VAD_EVIDENCE_KEY_KIND),
            Value::from(CLAIM_VAD_EVIDENCE_KIND),
        ),
        (
            Value::from(CLAIM_VAD_EVIDENCE_KEY_TURNS),
            Value::Array(turns),
        ),
    ])
}

fn validate_delta_component(value: f32, min: f32, max: f32, name: &'static str) -> Result<()> {
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(Error::InvalidClaimBody(match name {
            "vadDelta valence" => "vadDelta valence must be finite in [-2, 2]",
            "vadDelta arousal" => "vadDelta arousal must be finite in [-1, 1]",
            _ => "vadDelta dominance must be finite in [-1, 1]",
        }));
    }
    Ok(())
}

fn validate_trigger_confidence(confidence: f32) -> Result<()> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(Error::InvalidClaimBody(
            "affect.trigger confidence must be finite in [0, 1]",
        ));
    }
    Ok(())
}

fn reject_duplicate(seen: &mut bool, error: &'static str) -> Result<()> {
    if *seen {
        return Err(Error::InvalidClaimBody(error));
    }
    *seen = true;
    Ok(())
}

fn decode_entity_ref(value: &Value, error: &'static str) -> Result<EntityId> {
    let Some(text) = value.as_str() else {
        return Err(Error::InvalidClaimBody(error));
    };
    let id = EntityId::from_hex(text).map_err(|_| Error::InvalidClaimBody(error))?;
    if id.to_hex() != text {
        return Err(Error::InvalidClaimBody(error));
    }
    Ok(id)
}

fn decode_vad_delta(value: &Value) -> Result<VadDelta> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody("vadDelta must be a map"));
    };

    let mut valence = None;
    let mut arousal = None;
    let mut dominance = None;
    let mut seen_valence = false;
    let mut seen_arousal = false;
    let mut seen_dominance = false;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody("vadDelta keys must be strings"));
        };
        match key {
            AFFECT_TRIGGER_VAD_KEY_VALENCE => {
                reject_duplicate(&mut seen_valence, "duplicate vadDelta value key")?;
                valence = Some(finite_f32_in_range(
                    value,
                    -2.0,
                    2.0,
                    "vadDelta valence must be a number",
                    "vadDelta valence must be finite in [-2, 2]",
                )?);
            }
            AFFECT_TRIGGER_VAD_KEY_AROUSAL => {
                reject_duplicate(&mut seen_arousal, "duplicate vadDelta value key")?;
                arousal = Some(finite_f32_in_range(
                    value,
                    -1.0,
                    1.0,
                    "vadDelta arousal must be a number",
                    "vadDelta arousal must be finite in [-1, 1]",
                )?);
            }
            AFFECT_TRIGGER_VAD_KEY_DOMINANCE => {
                reject_duplicate(&mut seen_dominance, "duplicate vadDelta value key")?;
                dominance = Some(finite_f32_in_range(
                    value,
                    -1.0,
                    1.0,
                    "vadDelta dominance must be a number",
                    "vadDelta dominance must be finite in [-1, 1]",
                )?);
            }
            _ => {
                return Err(Error::InvalidClaimBody(
                    "vadDelta key is not in the pinned set",
                ));
            }
        }
    }

    VadDelta::new(
        valence.ok_or(Error::InvalidClaimBody("missing vadDelta valence"))?,
        arousal.ok_or(Error::InvalidClaimBody("missing vadDelta arousal"))?,
        dominance.ok_or(Error::InvalidClaimBody("missing vadDelta dominance"))?,
    )
}

fn finite_f32_in_range(
    value: &Value,
    min: f64,
    max: f64,
    type_error: &'static str,
    range_error: &'static str,
) -> Result<f32> {
    let parsed = match value {
        Value::F32(value) => f64::from(*value),
        Value::F64(value) => *value,
        Value::Integer(value) => {
            if let Some(value) = value.as_i64() {
                value as f64
            } else {
                return Err(Error::InvalidClaimBody(type_error));
            }
        }
        _ => return Err(Error::InvalidClaimBody(type_error)),
    };
    if !parsed.is_finite() || !(min..=max).contains(&parsed) {
        return Err(Error::InvalidClaimBody(range_error));
    }
    Ok(parsed as f32)
}

fn vad_delta_value(delta: VadDelta) -> Value {
    Value::Map(vec![
        (
            Value::from(AFFECT_TRIGGER_VAD_KEY_VALENCE),
            Value::F32(delta.valence),
        ),
        (
            Value::from(AFFECT_TRIGGER_VAD_KEY_AROUSAL),
            Value::F32(delta.arousal),
        ),
        (
            Value::from(AFFECT_TRIGGER_VAD_KEY_DOMINANCE),
            Value::F32(delta.dominance),
        ),
    ])
}

fn collect_entity_refs_from_value(value: &Value, ids: &mut BTreeSet<EntityId>) {
    match value {
        Value::Binary(bytes) if bytes.len() == ENTITY_ID_LEN => {
            let mut raw = [0_u8; ENTITY_ID_LEN];
            raw.copy_from_slice(bytes);
            if let Ok(id) = EntityId::from_bytes(raw) {
                ids.insert(id);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_entity_refs_from_value(item, ids);
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries {
                collect_entity_refs_from_value(key, ids);
                collect_entity_refs_from_value(value, ids);
            }
        }
        _ => {}
    }
}

fn vad_value(vad: Vad) -> Value {
    Value::Map(vec![
        (Value::from(CLAIM_VAD_KEY_VALENCE), Value::F32(vad.valence)),
        (Value::from(CLAIM_VAD_KEY_AROUSAL), Value::F32(vad.arousal)),
        (
            Value::from(CLAIM_VAD_KEY_DOMINANCE),
            Value::F32(vad.dominance),
        ),
    ])
}
