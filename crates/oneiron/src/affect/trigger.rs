//! Affect trigger claim codec: encoders, strict and lenient decoders, and shared scalar validators.

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject, unit_interval_f32};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::ClaimCandidate;
pub const AFFECT_TRIGGER_PREDICATE: &str = "affect.trigger";
const AFFECT_TRIGGER_KEY_AFFECTED_PERSON: &str = "affectedPerson";
const AFFECT_TRIGGER_KEY_TRIGGER_REF: &str = "triggerRef";
const AFFECT_TRIGGER_KEY_VAD_DELTA: &str = "vadDelta";
const AFFECT_TRIGGER_KEY_CONFIDENCE: &str = "confidence";
const AFFECT_TRIGGER_KEY_K: &str = "k";
const AFFECT_TRIGGER_KEY_OBSERVED_N: &str = "observedN";
const AFFECT_TRIGGER_VAD_KEY_VALENCE: &str = "valence";
const AFFECT_TRIGGER_VAD_KEY_AROUSAL: &str = "arousal";
const AFFECT_TRIGGER_VAD_KEY_DOMINANCE: &str = "dominance";
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
        if k > observed_n {
            return Err(Error::InvalidClaimBody("k must not exceed observedN"));
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
    decode_affect_trigger_value_with_count_mode(value, AffectTriggerCountMode::LegacyCompatible)
}
#[derive(Debug, Clone, Copy)]
enum AffectTriggerCountMode {
    Strict,
    LegacyCompatible,
}
fn decode_affect_trigger_value_strict(value: &Value) -> Result<AffectTriggerValue> {
    decode_affect_trigger_value_with_count_mode(value, AffectTriggerCountMode::Strict)
}
fn decode_affect_trigger_value_with_count_mode(
    value: &Value,
    count_mode: AffectTriggerCountMode,
) -> Result<AffectTriggerValue> {
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

    let affected_person =
        affected_person.ok_or(Error::InvalidClaimBody("missing affectedPerson"))?;
    let trigger_ref = trigger_ref.ok_or(Error::InvalidClaimBody("missing triggerRef"))?;
    let vad_delta = vad_delta.ok_or(Error::InvalidClaimBody("missing vadDelta"))?;
    let confidence =
        confidence.ok_or(Error::InvalidClaimBody("missing affect.trigger confidence"))?;
    let k = k.ok_or(Error::InvalidClaimBody("missing k"))?;
    let observed_n = observed_n.ok_or(Error::InvalidClaimBody("missing observedN"))?;

    match count_mode {
        AffectTriggerCountMode::Strict => AffectTriggerValue::new(
            affected_person,
            trigger_ref,
            vad_delta,
            confidence,
            k,
            observed_n,
        ),
        AffectTriggerCountMode::LegacyCompatible => Ok(AffectTriggerValue {
            affected_person,
            trigger_ref,
            vad_delta,
            confidence,
            k,
            observed_n,
        }),
    }
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
    let value = decode_affect_trigger_value_strict(&body.value)?;
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
pub(crate) fn reject_duplicate(seen: &mut bool, error: &'static str) -> Result<()> {
    if *seen {
        return Err(Error::InvalidClaimBody(error));
    }
    *seen = true;
    Ok(())
}
pub(crate) fn decode_entity_ref(value: &Value, error: &'static str) -> Result<EntityId> {
    let Some(text) = value.as_str() else {
        return Err(Error::InvalidClaimBody(error));
    };
    let id = EntityId::from_hex(text).map_err(|_| Error::InvalidClaimBody(error))?;
    if id.to_hex() != text {
        return Err(Error::InvalidClaimBody(error));
    }
    Ok(id)
}
pub(crate) fn decode_vad_delta(value: &Value) -> Result<VadDelta> {
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
pub(crate) fn finite_f32_in_range(
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
pub(crate) fn vad_delta_value(delta: VadDelta) -> Value {
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
