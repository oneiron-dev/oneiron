use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_128;

use crate::Vault;
use crate::affect::coping::COPING_OUTCOME_PREDICATE;
use crate::affect::coping::CopingOutcomeUpdate;
use crate::affect::coping::coping_outcome_evidence_value;
use crate::affect::coping::coping_outcome_value;
use crate::affect::coping::decode_coping_outcome_claim;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::batch::deindex_entity;
use crate::claim::ClaimApprovalStatus;
use crate::claim::ClaimLifecycleStatus;
use crate::claim::ClaimSource;
use crate::claim::claim_consolidatable;
use crate::claim::encode_claim_body;
use crate::claim::validate_claim_body_bytes;
use crate::claim::{ClaimBody, ClaimSubject, unit_interval_f32};
use crate::edge::EdgeKind;
use crate::edge::EdgeValueLayout;
use crate::edge::edge_value_layout_for_kind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::provenance::EdgeRef;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
use crate::vault::SUPERSEDES_DEFAULT_WEIGHT;
use crate::vault::edge_kind_prefix;
use crate::vault::parse_edge_record;
use crate::write_envelope::ClaimCandidate;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Vad {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

/// VAD coordinate rejected during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VadComponent {
    Valence,
    Arousal,
    Dominance,
}

impl Vad {
    pub const NEUTRAL: Self = Self {
        valence: 0.0,
        arousal: 0.0,
        dominance: 0.0,
    };

    pub fn is_finite(&self) -> bool {
        self.non_finite_component().is_none()
    }

    pub fn is_in_range(&self) -> bool {
        self.out_of_range_component().is_none()
    }

    pub fn validate(&self) -> crate::error::Result<()> {
        if let Some((component, value)) = self.invalid_component() {
            return Err(crate::error::Error::InvalidVad { component, value });
        }
        Ok(())
    }

    pub(crate) fn invalid_component(&self) -> Option<(VadComponent, f32)> {
        self.non_finite_component()
            .or_else(|| self.out_of_range_component())
    }

    fn non_finite_component(&self) -> Option<(VadComponent, f32)> {
        if !self.valence.is_finite() {
            return Some((VadComponent::Valence, self.valence));
        }
        if !self.arousal.is_finite() {
            return Some((VadComponent::Arousal, self.arousal));
        }
        if !self.dominance.is_finite() {
            return Some((VadComponent::Dominance, self.dominance));
        }
        None
    }

    fn out_of_range_component(&self) -> Option<(VadComponent, f32)> {
        if !(-1.0..=1.0).contains(&self.valence) {
            return Some((VadComponent::Valence, self.valence));
        }
        if !(0.0..=1.0).contains(&self.arousal) {
            return Some((VadComponent::Arousal, self.arousal));
        }
        if !(0.0..=1.0).contains(&self.dominance) {
            return Some((VadComponent::Dominance, self.dominance));
        }
        None
    }
}

/// Source that produced a turn/message VAD annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VadAnnotationSource {
    ModelInference,
    UserSelfReport,
}

impl VadAnnotationSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelInference => "model_inference",
            Self::UserSelfReport => "user_self_report",
        }
    }
}

/// Persisted VAD metadata attached to a TURN or MESSAGE entity.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VadAnnotation {
    pub vad: Vad,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
}

impl VadAnnotation {
    pub fn new(
        vad: Vad,
        source: VadAnnotationSource,
        annotated_at: u64,
    ) -> crate::error::Result<Self> {
        vad.validate()?;
        Ok(Self {
            vad,
            source,
            annotated_at,
        })
    }
}

const VAD_ANNOTATION_META_KEY_PREFIX: &[u8] = b"vad_ann:";
const VAD_ANNOTATION_META_KEY_LEN: usize = VAD_ANNOTATION_META_KEY_PREFIX.len() + 1 + ENTITY_ID_LEN;
const VAD_ANNOTATION_CLAIM_PREDICATE: &str = "affect.vad";
const VAD_ANNOTATION_CLAIM_ID_DOMAIN: &[u8] = b"oneiron:vad-annotation-claim:v1";
const VAD_KEY_VALENCE: &str = "valence";
const VAD_KEY_AROUSAL: &str = "arousal";
const VAD_KEY_DOMINANCE: &str = "dominance";
const VAD_KEY_SOURCE: &str = "source";
const VAD_KEY_ANNOTATED_AT: &str = "annotated_at";

pub(crate) fn vad_annotation_meta_key(
    entity_type: u8,
    id: &EntityId,
) -> [u8; VAD_ANNOTATION_META_KEY_LEN] {
    let mut key = [0_u8; VAD_ANNOTATION_META_KEY_LEN];
    key[..VAD_ANNOTATION_META_KEY_PREFIX.len()].copy_from_slice(VAD_ANNOTATION_META_KEY_PREFIX);
    key[VAD_ANNOTATION_META_KEY_PREFIX.len()] = entity_type;
    key[VAD_ANNOTATION_META_KEY_PREFIX.len() + 1..].copy_from_slice(id.as_bytes());
    key
}

pub(crate) fn vad_annotation_claim_id(entity_type: u8, id: &EntityId) -> Result<EntityId> {
    let mut material = Vec::with_capacity(VAD_ANNOTATION_CLAIM_ID_DOMAIN.len() + 1 + ENTITY_ID_LEN);
    material.extend_from_slice(VAD_ANNOTATION_CLAIM_ID_DOMAIN);
    material.push(entity_type);
    material.extend_from_slice(id.as_bytes());

    let mut bytes = xxh3_128(&material).to_le_bytes();
    if EntityId::from_bytes(bytes).is_err() {
        bytes[ENTITY_ID_LEN - 1] ^= 0x01;
    }
    EntityId::from_bytes(bytes)
        .map_err(|_| Error::InvariantViolation("VAD annotation claim id derivation failed"))
}

fn vad_annotation_value(annotation: &VadAnnotation) -> Value {
    Value::Map(vec![
        (
            Value::from(VAD_KEY_VALENCE),
            Value::F32(annotation.vad.valence),
        ),
        (
            Value::from(VAD_KEY_AROUSAL),
            Value::F32(annotation.vad.arousal),
        ),
        (
            Value::from(VAD_KEY_DOMINANCE),
            Value::F32(annotation.vad.dominance),
        ),
        (
            Value::from(VAD_KEY_SOURCE),
            Value::from(annotation.source.as_str()),
        ),
        (
            Value::from(VAD_KEY_ANNOTATED_AT),
            Value::from(annotation.annotated_at),
        ),
    ])
}

fn vad_annotation_claim_body(id: &EntityId, annotation: &VadAnnotation) -> ClaimBody {
    let mut body = ClaimBody::new(
        VAD_ANNOTATION_CLAIM_PREDICATE,
        ClaimSubject::Entity(*id),
        vad_annotation_value(annotation),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(match annotation.source {
        VadAnnotationSource::ModelInference => ClaimSource::Inferred,
        VadAnnotationSource::UserSelfReport => ClaimSource::UserStated,
    });
    body.valid_from = Some(annotation.annotated_at);
    body.valid_to = Some(annotation.annotated_at);
    body
}

fn decode_vad_annotation_claim_body_if_present(raw: &[u8]) -> Result<Option<ClaimBody>> {
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if body.is_empty() {
        return Ok(None);
    }
    crate::claim::decode_claim_body(body, true).map(Some)
}

fn vad_annotation_source_from_str(value: &str) -> Result<VadAnnotationSource> {
    match value {
        "model_inference" => Ok(VadAnnotationSource::ModelInference),
        "user_self_report" => Ok(VadAnnotationSource::UserSelfReport),
        _ => Err(Error::CorruptedIndex("VAD annotation claim")),
    }
}

fn vad_annotation_f32(value: &Value) -> Result<f32> {
    match value {
        Value::F32(value) => Ok(*value),
        Value::F64(value) if value.is_finite() => {
            let narrowed = *value as f32;
            if f64::from(narrowed) == *value {
                Ok(narrowed)
            } else {
                Err(Error::CorruptedIndex("VAD annotation claim"))
            }
        }
        _ => Err(Error::CorruptedIndex("VAD annotation claim")),
    }
}

fn vad_annotation_from_value(value: &Value) -> Result<VadAnnotation> {
    let Value::Map(entries) = value else {
        return Err(Error::CorruptedIndex("VAD annotation claim"));
    };

    let mut valence = None;
    let mut arousal = None;
    let mut dominance = None;
    let mut source = None;
    let mut annotated_at = None;
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::CorruptedIndex("VAD annotation claim"));
        };
        match key {
            VAD_KEY_VALENCE if valence.is_none() => valence = Some(vad_annotation_f32(value)?),
            VAD_KEY_AROUSAL if arousal.is_none() => arousal = Some(vad_annotation_f32(value)?),
            VAD_KEY_DOMINANCE if dominance.is_none() => {
                dominance = Some(vad_annotation_f32(value)?);
            }
            VAD_KEY_SOURCE if source.is_none() => {
                let Some(raw) = value.as_str() else {
                    return Err(Error::CorruptedIndex("VAD annotation claim"));
                };
                source = Some(vad_annotation_source_from_str(raw)?);
            }
            VAD_KEY_ANNOTATED_AT if annotated_at.is_none() => {
                annotated_at = Some(
                    value
                        .as_u64()
                        .ok_or(Error::CorruptedIndex("VAD annotation claim"))?,
                );
            }
            _ => return Err(Error::CorruptedIndex("VAD annotation claim")),
        }
    }

    VadAnnotation::new(
        Vad {
            valence: valence.ok_or(Error::CorruptedIndex("VAD annotation claim"))?,
            arousal: arousal.ok_or(Error::CorruptedIndex("VAD annotation claim"))?,
            dominance: dominance.ok_or(Error::CorruptedIndex("VAD annotation claim"))?,
        },
        source.ok_or(Error::CorruptedIndex("VAD annotation claim"))?,
        annotated_at.ok_or(Error::CorruptedIndex("VAD annotation claim"))?,
    )
}

#[derive(Debug, Default)]
pub(crate) struct VadAnnotationCleanup {
    pub(crate) had_vector: bool,
    pub(crate) had_graph_mutation: bool,
    pub(crate) neighbors: Vec<EntityId>,
}

impl VadAnnotationCleanup {
    fn absorb(
        &mut self,
        deleted_claim_id: EntityId,
        had_vector: bool,
        had_graph_mutation: bool,
        mut neighbors: Vec<EntityId>,
    ) {
        self.had_vector |= had_vector;
        self.had_graph_mutation |= had_graph_mutation;
        self.neighbors.push(deleted_claim_id);
        self.neighbors.append(&mut neighbors);
        self.neighbors.sort_unstable();
        self.neighbors.dedup();
    }
}

pub(crate) fn delete_vad_annotation_metadata_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<VadAnnotationCleanup> {
    let mut cleanup = VadAnnotationCleanup::default();
    delete_vad_annotation_metadata_for_type_in_txn(
        store,
        wtxn,
        id,
        ENTITY_TYPE_TURN,
        &mut cleanup,
    )?;
    delete_vad_annotation_metadata_for_type_in_txn(
        store,
        wtxn,
        id,
        ENTITY_TYPE_MESSAGE,
        &mut cleanup,
    )?;
    Ok(cleanup)
}

pub(crate) fn delete_vad_annotation_metadata_for_type_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    cleanup: &mut VadAnnotationCleanup,
) -> Result<()> {
    if matches!(entity_type, ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE) {
        let key = vad_annotation_meta_key(entity_type, id);
        store.vault_meta.delete(wtxn, &key)?;

        let claim_id = vad_annotation_claim_id(entity_type, id)?;
        if vad_annotation_claim_matches_subject(store, &*wtxn, &claim_id, id)? {
            let (existed, had_vector, had_graph_mutation, neighbors) =
                deindex_entity(store, wtxn, &claim_id)?;
            if existed {
                cleanup.absorb(claim_id, had_vector, had_graph_mutation, neighbors);
            }
        }
    }
    Ok(())
}

fn vad_annotation_claim_matches_subject(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    annotated_id: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let Some(body) = decode_vad_annotation_claim_body_if_present(raw)? else {
        return Ok(false);
    };
    Ok(body.predicate == VAD_ANNOTATION_CLAIM_PREDICATE
        && body.subject == ClaimSubject::Entity(*annotated_id))
}

pub(crate) fn vad_annotation_delete_scope_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    for entity_type in [ENTITY_TYPE_TURN, ENTITY_TYPE_MESSAGE] {
        let key = vad_annotation_meta_key(entity_type, id);
        if store.vault_meta.get(txn, &key)?.is_some() {
            return Ok(true);
        }

        let claim_id = vad_annotation_claim_id(entity_type, id)?;
        if vad_annotation_claim_matches_subject(store, txn, &claim_id, id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

struct StoredClaimVadState {
    id: EntityId,
    header: EntityMetadataHeader,
    body: ClaimBody,
}

impl Vault {
    /// Writes or replaces the VAD annotation metadata for a TURN entity.
    pub fn annotate_turn_vad(
        &self,
        turn_id: &EntityId,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        self.annotate_entity_vad(turn_id, ENTITY_TYPE_TURN, annotation)
    }

    /// Reads the VAD annotation metadata for a TURN entity.
    pub fn get_turn_vad_annotation(&self, turn_id: &EntityId) -> Result<Option<VadAnnotation>> {
        self.get_entity_vad_annotation(turn_id, ENTITY_TYPE_TURN)
    }

    /// Writes or replaces the VAD annotation metadata for a MESSAGE entity.
    pub fn annotate_message_vad(
        &self,
        message_id: &EntityId,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        self.annotate_entity_vad(message_id, ENTITY_TYPE_MESSAGE, annotation)
    }

    /// Reads the VAD annotation metadata for a MESSAGE entity.
    pub fn get_message_vad_annotation(
        &self,
        message_id: &EntityId,
    ) -> Result<Option<VadAnnotation>> {
        self.get_entity_vad_annotation(message_id, ENTITY_TYPE_MESSAGE)
    }

    /// Consolidates turn-level VAD evidence attached to `claim_id` into
    /// claim-level affect state.
    ///
    /// The API is asynchronous so background Dreamer consolidation workers can
    /// await it naturally. The storage work is one LMDB transaction: semantic
    /// edges incident to the claim have only their VAD bytes rewritten,
    /// structural edges are skipped, and a derived `affect.claim_vad` state
    /// claim supersedes the previous active state when evidence changes.
    pub async fn consolidate_claim_vad(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<ClaimVadConsolidation> {
        self.consolidate_claim_vad_in_txn(claim_id, now)
    }

    fn consolidate_claim_vad_in_txn(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<ClaimVadConsolidation> {
        let mut wtxn = self.store.env.write_txn()?;
        let claim_body = self.claim_body_for_claim_vad_in_txn(&wtxn, claim_id)?;
        if !claim_consolidatable(&claim_body) {
            if claim_body.lifecycle != ClaimLifecycleStatus::Active {
                return Err(Error::ClaimAlreadyClosed {
                    status: claim_body.lifecycle,
                });
            }
            let message = if claim_body.stale {
                "claim is stale and not consolidatable"
            } else {
                "claim is not consolidatable"
            };
            self.clear_claim_vad_outputs_in_txn(&mut wtxn, claim_id, now)?;
            wtxn.commit()?;
            return Err(Error::InvalidClaimBody(message));
        }
        if claim_body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE {
            return Err(Error::InvalidClaimBody(
                "claim VAD state claims cannot be consolidated",
            ));
        }
        if claim_body.predicate == VAD_ANNOTATION_CLAIM_PREDICATE {
            return Err(Error::InvalidClaimBody(
                "turn VAD annotation claims cannot be consolidated",
            ));
        }

        let mut evidence_turns = Vec::new();
        for candidate in collect_claim_turn_evidence_refs(&claim_body) {
            if let Some(annotation) = self.turn_vad_annotation_in_txn(&wtxn, &candidate)? {
                evidence_turns.push(ClaimVadTurnEvidence {
                    turn_id: candidate,
                    annotation,
                });
            }
        }

        let (semantic_edges, structural_edges_skipped) =
            self.claim_vad_incident_edges_in_txn(&wtxn, claim_id)?;
        let active_states = self.active_claim_vad_states_in_txn(&wtxn, claim_id)?;
        let mut ops = Vec::new();

        let (vad, reappraisal) = if let Some(vad) = mean_vad(&evidence_turns) {
            vad.validate()?;
            for edge in &semantic_edges {
                ops.push(BatchOp::SetEdgeVad {
                    src: edge.source,
                    kind: edge.kind,
                    tgt: edge.target,
                    vad,
                });
            }

            let value = claim_vad_value(vad, evidence_turns.len());
            let evidence = claim_vad_evidence_value(&evidence_turns);

            let reappraisal = if active_states.len() == 1
                && active_states[0].body.value == value
                && active_states[0].body.evidence.as_ref() == Some(&evidence)
            {
                ClaimVadReappraisal {
                    active_claim_id: Some(active_states[0].id),
                    created_claim_id: None,
                    superseded_claim_ids: Vec::new(),
                }
            } else {
                let state_claim_id = EntityId::now();
                let mut body = ClaimBody::new(
                    CLAIM_VAD_REAPPRAISAL_PREDICATE,
                    ClaimSubject::Entity(*claim_id),
                    value,
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                );
                body.evidence = Some(evidence);
                body.source = Some(ClaimSource::Inferred);
                body.valid_from = Some(now);
                let data = encode_claim_body(&body)?;
                ops.push(BatchOp::Put {
                    id: state_claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: u64::MAX,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                });
                ops.push(BatchOp::Edge {
                    src: state_claim_id,
                    kind: EdgeKind::ClaimOf,
                    tgt: *claim_id,
                    weight: CLAIM_OF_DEFAULT_WEIGHT,
                    vad: Vad::NEUTRAL,
                });

                let superseded_claim_ids = Self::close_claim_vad_states(
                    &mut ops,
                    active_states,
                    now,
                    Some(state_claim_id),
                )?;

                ClaimVadReappraisal {
                    active_claim_id: Some(state_claim_id),
                    created_claim_id: Some(state_claim_id),
                    superseded_claim_ids,
                }
            };

            (Some(vad), reappraisal)
        } else {
            for edge in &semantic_edges {
                ops.push(BatchOp::SetEdgeVad {
                    src: edge.source,
                    kind: edge.kind,
                    tgt: edge.target,
                    vad: Vad::NEUTRAL,
                });
            }

            let superseded_claim_ids =
                Self::close_claim_vad_states(&mut ops, active_states, now, None)?;
            (
                None,
                ClaimVadReappraisal {
                    active_claim_id: None,
                    created_claim_id: None,
                    superseded_claim_ids,
                },
            )
        };

        if !ops.is_empty() {
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
        }
        wtxn.commit()?;

        Ok(ClaimVadConsolidation {
            claim_id: *claim_id,
            vad,
            evidence_turns,
            semantic_edges_updated: semantic_edges.len(),
            structural_edges_skipped,
            reappraisal,
        })
    }

    fn clear_claim_vad_outputs_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        let (semantic_edges, _) = self.claim_vad_incident_edges_in_txn(&*wtxn, claim_id)?;
        let active_states = self.active_claim_vad_states_in_txn(&*wtxn, claim_id)?;
        if semantic_edges.is_empty() && active_states.is_empty() {
            return Ok(());
        }

        let mut ops = Vec::with_capacity(semantic_edges.len() + active_states.len());
        for edge in semantic_edges {
            ops.push(BatchOp::SetEdgeVad {
                src: edge.source,
                kind: edge.kind,
                tgt: edge.target,
                vad: Vad::NEUTRAL,
            });
        }
        Self::close_claim_vad_states(&mut ops, active_states, now, None)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    fn close_claim_vad_states(
        ops: &mut Vec<BatchOp>,
        active_states: Vec<StoredClaimVadState>,
        now: u64,
        successor: Option<EntityId>,
    ) -> Result<Vec<EntityId>> {
        let mut superseded_claim_ids = Vec::with_capacity(active_states.len());
        for state in active_states {
            let mut closed = state.body;
            closed.lifecycle = ClaimLifecycleStatus::Superseded;
            closed.valid_to = Some(now);
            let closed_data = encode_claim_body(&closed)?;
            ops.push(BatchOp::Put {
                id: state.id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: state.header.occurred_start,
                    end: now,
                },
                learned_at: state.header.learned_at,
                data: closed_data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            });
            if let Some(successor) = successor {
                ops.push(BatchOp::EdgeWithCreatedAt {
                    src: successor,
                    kind: EdgeKind::Supersedes,
                    tgt: state.id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                });
            }
            superseded_claim_ids.push(state.id);
        }
        Ok(superseded_claim_ids)
    }

    fn claim_body_for_claim_vad_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<ClaimBody> {
        let raw = self
            .store
            .entities
            .get(txn, claim_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
    }

    fn turn_vad_annotation_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        turn_id: &EntityId,
    ) -> Result<Option<VadAnnotation>> {
        let Some(raw) = self.store.entities.get(txn, turn_id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_TURN {
            return Ok(None);
        }

        let claim_id = vad_annotation_claim_id(ENTITY_TYPE_TURN, turn_id)?;
        if let Some(raw) = self.store.entities.get(txn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            let Some(body) = decode_vad_annotation_claim_body_if_present(raw)? else {
                return Ok(None);
            };
            if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
                || body.subject != ClaimSubject::Entity(*turn_id)
            {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            if body.lifecycle != ClaimLifecycleStatus::Active {
                return Ok(None);
            }
            return vad_annotation_from_value(&body.value).map(Some);
        }

        let key = vad_annotation_meta_key(ENTITY_TYPE_TURN, turn_id);
        let Some(raw) = self.store.vault_meta.get(txn, &key)? else {
            return Ok(None);
        };
        let annotation: VadAnnotation =
            rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("VAD annotation"))?;
        annotation.vad.validate()?;
        Ok(Some(annotation))
    }

    fn claim_vad_incident_edges_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<(Vec<EdgeRef>, usize)> {
        let mut seen = std::collections::HashSet::new();
        let mut semantic_edges = Vec::new();
        let mut structural_edges_skipped = 0;

        for (scanned, entry) in self
            .store
            .edges_out
            .prefix_iter(txn, claim_id.as_bytes())?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_vad_incident_edges"));
            }
            let (key, value) = entry?;
            let info = parse_edge_record(key, value)?;
            Self::record_claim_vad_edge(
                EdgeRef::new(*claim_id, info.kind, info.target),
                &mut seen,
                &mut semantic_edges,
                &mut structural_edges_skipped,
            );
        }

        for (scanned, entry) in self
            .store
            .edges_in
            .prefix_iter(txn, claim_id.as_bytes())?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_vad_incident_edges"));
            }
            let (key, value) = entry?;
            let info = parse_edge_record(key, value)?;
            Self::record_claim_vad_edge(
                EdgeRef::new(info.target, info.kind, *claim_id),
                &mut seen,
                &mut semantic_edges,
                &mut structural_edges_skipped,
            );
        }

        Ok((semantic_edges, structural_edges_skipped))
    }

    fn record_claim_vad_edge(
        edge: EdgeRef,
        seen: &mut std::collections::HashSet<[u8; crate::claim::EDGE_REF_LEN]>,
        semantic_edges: &mut Vec<EdgeRef>,
        structural_edges_skipped: &mut usize,
    ) {
        if !seen.insert(edge.encode()) {
            return;
        }
        if edge_value_layout_for_kind(edge.kind, false) == EdgeValueLayout::Structural {
            *structural_edges_skipped += 1;
        } else {
            semantic_edges.push(edge);
        }
    }

    fn active_claim_vad_states_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<Vec<StoredClaimVadState>> {
        let prefix = edge_kind_prefix(claim_id, EdgeKind::ClaimOf);
        let mut states = Vec::new();
        for (scanned, entry) in self.store.edges_in.prefix_iter(txn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_vad_states"));
            }
            let (key, value) = entry?;
            let state_id = parse_edge_record(key, value)?.target;
            let Some(raw) = self.store.entities.get(txn, state_id.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
                && body.subject == ClaimSubject::Entity(*claim_id)
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                states.push(StoredClaimVadState {
                    id: state_id,
                    header,
                    body,
                });
            }
        }
        states.sort_by_key(|state| state.id);
        Ok(states)
    }

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
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let prior_body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if prior_body.predicate != COPING_OUTCOME_PREDICATE {
            return Err(Error::InvalidClaimBody("claim is not a coping.outcome"));
        }
        if prior_body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::ClaimAlreadyClosed {
                status: prior_body.lifecycle,
            });
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

    fn annotate_entity_vad(
        &self,
        id: &EntityId,
        expected_type: u8,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        annotation.vad.validate()?;
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        let claim_body = vad_annotation_claim_body(id, &annotation);
        let data = encode_claim_body(&claim_body)?;
        validate_claim_body_bytes(&data, false)?;

        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != expected_type {
            return Err(Error::InvalidEntityType(header.entity_type));
        }

        self.guard_vad_annotation_claim_slot(&wtxn, &claim_id, id)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![
                BatchOp::Put {
                    id: claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: annotation.annotated_at,
                        end: annotation.annotated_at,
                    },
                    learned_at: annotation.annotated_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                },
                BatchOp::Edge {
                    src: claim_id,
                    kind: EdgeKind::ClaimOf,
                    tgt: *id,
                    weight: CLAIM_OF_DEFAULT_WEIGHT,
                    vad: Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        let key = vad_annotation_meta_key(expected_type, id);
        self.store.vault_meta.delete(&mut wtxn, &key)?;
        wtxn.commit()?;
        Ok(annotation)
    }

    fn guard_vad_annotation_claim_slot(
        &self,
        rtxn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
        annotated_id: &EntityId,
    ) -> Result<()> {
        let Some(raw) = self.store.entities.get(rtxn, claim_id.as_bytes())? else {
            return Ok(());
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvariantViolation(
                "VAD annotation claim id collision",
            ));
        }
        let Some(body) = decode_vad_annotation_claim_body_if_present(raw)? else {
            return Ok(());
        };
        if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
            || body.subject != ClaimSubject::Entity(*annotated_id)
        {
            return Err(Error::InvariantViolation(
                "VAD annotation claim id collision",
            ));
        }
        Ok(())
    }

    fn get_entity_vad_annotation(
        &self,
        id: &EntityId,
        expected_type: u8,
    ) -> Result<Option<VadAnnotation>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != expected_type {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        if let Some(raw) = self.store.entities.get(&rtxn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            let Some(body) = decode_vad_annotation_claim_body_if_present(raw)? else {
                return Ok(None);
            };
            if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
                || body.subject != ClaimSubject::Entity(*id)
            {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            if body.lifecycle != ClaimLifecycleStatus::Active {
                return Ok(None);
            }
            return vad_annotation_from_value(&body.value).map(Some);
        }

        let key = vad_annotation_meta_key(expected_type, id);
        let Some(raw) = self.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        let annotation: VadAnnotation =
            rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("VAD annotation"))?;
        annotation.vad.validate()?;
        Ok(Some(annotation))
    }
}
