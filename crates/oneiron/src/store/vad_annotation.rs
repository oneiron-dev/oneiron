//! Turn and message VAD annotation persistence: meta keys, claim codec, and metadata deletion helpers.

use crate::ports::EntityStoreRead;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, deindex_entity};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
pub(crate) use crate::write_envelope::vad_annotation::{
    VAD_ANNOTATION_CLAIM_PREDICATE, VadAnnotationCleanup, vad_annotation_claim_body,
    vad_annotation_claim_id, vad_annotation_from_value,
};
use oneiron_contracts::affect::VadAnnotation;

/// Legacy pre-CLAIM VAD metadata row, keyed by `entity_type(1) ++ id(16)`.
/// Read (and deleted) only — every write now lands as a `VAD_ANNOTATION_CLAIM_PREDICATE`
/// claim instead, but an old row must still decode and clean up.
pub(crate) const VAD_ANNOTATION_META: SideTable<VadAnnotationMetaKey, VadAnnotation, Named> =
    SideTable::new(&side_table::AFFECT_VAD_ANNOTATION_META);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VadAnnotationMetaKey {
    pub(crate) entity_type: u8,
    pub(crate) id: EntityId,
}

impl SideKey for VadAnnotationMetaKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.entity_type);
        out.extend_from_slice(self.id.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (&entity_type, rest) = bytes.split_first()?;
        Some(Self {
            entity_type,
            id: EntityId::decode_key(rest)?,
        })
    }
}

pub(crate) fn vad_annotation_meta_key(entity_type: u8, id: &EntityId) -> VadAnnotationMetaKey {
    VadAnnotationMetaKey {
        entity_type,
        id: *id,
    }
}
pub(crate) fn decode_vad_annotation_claim_body_if_present(raw: &[u8]) -> Result<Option<ClaimBody>> {
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if body.is_empty() {
        return Ok(None);
    }
    crate::write_envelope::claim_body::decode_claim_body(body, true).map(Some)
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
        VAD_ANNOTATION_META.delete(store, wtxn, &key)?;

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
    let Some(raw) = store
        .port_entity_record(rtxn, claim_id)?
        .map(|row| row.encode())
    else {
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
        if VAD_ANNOTATION_META.contains(store, txn, &key)? {
            return Ok(true);
        }

        let claim_id = vad_annotation_claim_id(entity_type, id)?;
        if vad_annotation_claim_matches_subject(store, txn, &claim_id, id)? {
            return Ok(true);
        }
    }
    Ok(false)
}
