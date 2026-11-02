//! The turn and message VAD annotation door: write, guard and read one
//! entity's annotation.
use crate::Vault;
use crate::affect::{
    VAD_ANNOTATION_CLAIM_PREDICATE, VAD_ANNOTATION_META, Vad, VadAnnotation,
    decode_vad_annotation_claim_body_if_present, vad_annotation_claim_body,
    vad_annotation_claim_id, vad_annotation_from_value, vad_annotation_meta_key,
};
use crate::batch::{BatchOp, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimLifecycleStatus, ClaimSubject, encode_claim_body, validate_claim_body_bytes,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;

impl Vault {
    pub(super) fn annotate_entity_vad(
        &self,
        id: &EntityId,
        expected_type: u8,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        let mut wtxn = self.store.env.write_txn()?;
        let result = self.annotate_entity_vad_in_txn(&mut wtxn, id, expected_type, annotation)?;
        wtxn.commit()?;
        Ok(result)
    }

    /// Transaction-composable form of the ordinary turn/message annotation door.
    pub(crate) fn annotate_entity_vad_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        expected_type: u8,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        annotation.vad.validate()?;
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        let claim_body = vad_annotation_claim_body(id, &annotation)?;
        let data = encode_claim_body(&claim_body)?;
        validate_claim_body_bytes(&data, false)?;

        let raw = self
            .store
            .port_entity_record(wtxn, id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != expected_type {
            return Err(Error::InvalidEntityType(header.entity_type));
        }

        self.guard_vad_annotation_claim_slot(wtxn, &claim_id, id)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
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
                    hub_sync_imported: false,
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
        VAD_ANNOTATION_META.delete(&self.store, wtxn, &key)?;
        Ok(annotation)
    }

    fn guard_vad_annotation_claim_slot(
        &self,
        rtxn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
        annotated_id: &EntityId,
    ) -> Result<()> {
        let Some(raw) = self
            .store
            .port_entity_record(rtxn, claim_id)?
            .map(|row| row.encode())
        else {
            return Ok(());
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvariantViolation(
                "VAD annotation claim id collision",
            ));
        }
        let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
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

    pub(super) fn get_entity_vad_annotation(
        &self,
        id: &EntityId,
        expected_type: u8,
    ) -> Result<Option<VadAnnotation>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .port_entity_record(&rtxn, id)?
            .map(|row| row.encode())
        else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != expected_type {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        if let Some(raw) = self
            .store
            .port_entity_record(&rtxn, &claim_id)?
            .map(|row| row.encode())
        {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
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
        let Some(annotation) = VAD_ANNOTATION_META.get(&self.store, &rtxn, &key)? else {
            if expected_type == ENTITY_TYPE_TURN {
                return super::saved_turn_mood_in_txn(self, &rtxn, id);
            }
            return Ok(None);
        };
        annotation.vad.validate()?;
        Ok(Some(annotation))
    }
}
