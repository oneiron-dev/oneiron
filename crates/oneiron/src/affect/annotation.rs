//! Turn and message VAD annotation persistence: meta keys, claim codec, and metadata deletion helpers.

use rmpv::Value;
use xxhash_rust::xxh3::xxh3_128;

use super::{Vad, VadAnnotation, VadAnnotationSource};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, deindex_entity};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::Store;
const VAD_ANNOTATION_META_KEY_PREFIX: &[u8] = b"vad_ann:";
const VAD_ANNOTATION_META_KEY_LEN: usize = VAD_ANNOTATION_META_KEY_PREFIX.len() + 1 + ENTITY_ID_LEN;
pub(super) const VAD_ANNOTATION_CLAIM_PREDICATE: &str = "affect.vad";
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
pub(super) fn vad_annotation_claim_body(id: &EntityId, annotation: &VadAnnotation) -> ClaimBody {
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
pub(super) fn decode_vad_annotation_claim_body_if_present(raw: &[u8]) -> Result<Option<ClaimBody>> {
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
pub(super) fn vad_annotation_from_value(value: &Value) -> Result<VadAnnotation> {
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
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
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
