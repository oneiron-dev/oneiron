use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject};
use crate::types::{ENTITY_ID_LEN, EntityId, Vad, VadAnnotation};

pub const CLAIM_VAD_REAPPRAISAL_PREDICATE: &str = "affect.claim_vad";

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

    let len = evidence.len() as f32;
    let mut vad = Vad::NEUTRAL;
    for item in evidence {
        vad.valence += item.annotation.vad.valence / len;
        vad.arousal += item.annotation.vad.arousal / len;
        vad.dominance += item.annotation.vad.dominance / len;
    }
    Some(vad)
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
