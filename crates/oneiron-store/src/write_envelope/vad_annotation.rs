//! VAD annotation claim values, stable ids, and cleanup result data.

use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use oneiron_contracts::affect::{Vad, VadAnnotation, VadAnnotationSource};
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::VAD_ANNOTATION_CLAIM;
use oneiron_contracts::error::{Error, Result};
use rmpv::Value;

pub const VAD_ANNOTATION_CLAIM_PREDICATE: &str = "affect.vad";
const VAD_KEY_VALENCE: &str = "valence";
const VAD_KEY_AROUSAL: &str = "arousal";
const VAD_KEY_DOMINANCE: &str = "dominance";
const VAD_KEY_SOURCE: &str = "source";
const VAD_KEY_ANNOTATED_AT: &str = "annotated_at";

pub fn vad_annotation_claim_id(entity_type: u8, id: &EntityId) -> Result<EntityId> {
    EntityId::derive(VAD_ANNOTATION_CLAIM, &[&[entity_type], id.as_bytes()])
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
pub fn vad_annotation_claim_body(id: &EntityId, annotation: &VadAnnotation) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        VAD_ANNOTATION_CLAIM_PREDICATE,
        ClaimSubject::Entity(*id),
        vad_annotation_value(annotation),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(match annotation.source {
        VadAnnotationSource::ModelInference => ClaimSource::Inferred,
        VadAnnotationSource::UserSelfReport => ClaimSource::UserStated,
    });
    body.valid_from = Some(annotation.annotated_at);
    body.valid_to = Some(annotation.annotated_at);
    Ok(body)
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
pub fn vad_annotation_from_value(value: &Value) -> Result<VadAnnotation> {
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
pub struct VadAnnotationCleanup {
    pub had_vector: bool,
    pub had_graph_mutation: bool,
    pub neighbors: Vec<EntityId>,
}
impl VadAnnotationCleanup {
    pub fn absorb(
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
