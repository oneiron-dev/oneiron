//! A turn's or a message's VAD annotation, written as the caller who made it
//! (FIX 8222). The ordinary annotation door writes its claim under no
//! envelope, as this host; this one writes the same claim through the Gate,
//! under an envelope that names the caller's actor and the annotation's own
//! source, so a below-owner caller's annotation lands at the approval its
//! standing gives and a pending one stays pending. Which source the caller
//! may state (a person's self-report) is the door's to judge before it asks.

use rmpv::Value;

use super::{
    VAD_ANNOTATION_CLAIM_PREDICATE, VAD_ANNOTATION_META, VadAnnotation,
    decode_vad_annotation_claim_body_if_present, vad_annotation_claim_body,
    vad_annotation_claim_id, vad_annotation_meta_key,
};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

impl Vault {
    /// [`Self::annotate_turn_vad`], written as `actor` through the Gate.
    pub fn annotate_turn_vad_as(
        &self,
        turn_id: &EntityId,
        annotation: VadAnnotation,
        actor: WriteActor,
    ) -> Result<VadAnnotation> {
        self.annotate_entity_vad_as(turn_id, ENTITY_TYPE_TURN, annotation, actor)
    }

    /// [`Self::annotate_message_vad`], written as `actor` through the Gate.
    pub fn annotate_message_vad_as(
        &self,
        message_id: &EntityId,
        annotation: VadAnnotation,
        actor: WriteActor,
    ) -> Result<VadAnnotation> {
        self.annotate_entity_vad_as(message_id, ENTITY_TYPE_MESSAGE, annotation, actor)
    }

    fn annotate_entity_vad_as(
        &self,
        id: &EntityId,
        expected_type: u8,
        annotation: VadAnnotation,
        actor: WriteActor,
    ) -> Result<VadAnnotation> {
        annotation.vad.validate()?;
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        let annotated = *id;
        let occurred = TimeRange {
            start: annotation.annotated_at,
            end: annotation.annotated_at,
        };
        let write = |approval: ClaimApprovalStatus| -> Result<()> {
            let body = vad_annotation_claim_body(&annotated, &annotation)?;
            let source = body.source.unwrap_or(ClaimSource::Inferred);
            let candidate =
                ClaimCandidate::new(body.predicate, body.subject, body.value, body.confidence)
                    .with_validity(body.valid_from, body.valid_to);
            let envelope = WriteEnvelope::new(
                actor,
                source,
                WriteProvenance::new(Value::Map(vec![
                    (Value::from("surface"), Value::from("core")),
                    (Value::from("route"), Value::from("turns.annotate")),
                ]))?,
                approval,
            );
            self.put_claim_candidate_with_landing_and_after_apply(
                &claim_id,
                candidate,
                &envelope,
                occurred,
                annotation.annotated_at,
                |txn| {
                    let raw = self
                        .store
                        .port_entity_record(txn, &annotated)?
                        .map(|row| row.encode())
                        .ok_or(Error::EntityNotFound)?;
                    let header = EntityMetadataHeader::parse(&raw)
                        .ok_or(Error::CorruptedIndex("entity header"))?;
                    if header.entity_type != expected_type {
                        return Err(Error::InvalidEntityType(header.entity_type));
                    }
                    annotation_slot_free_in(self, txn, &claim_id, &annotated)
                },
                |vault, wtxn, _| {
                    let key = vad_annotation_meta_key(expected_type, &annotated);
                    VAD_ANNOTATION_META.delete(&vault.store, wtxn, &key)?;
                    Ok(())
                },
            )
        };
        // As the Memory claim door does: a Gate verdict that pends the Auto
        // request lands the annotation parked for review, never refused.
        match write(ClaimApprovalStatus::Auto) {
            Err(error) if gate_rejection_pends(&error) => write(ClaimApprovalStatus::Proposed)?,
            written => written?,
        }
        Ok(annotation)
    }
}

/// The ordinary door's slot check, read in the landing snapshot: the claim
/// id is free, or already holds this target's own VAD annotation.
fn annotation_slot_free_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    annotated: &EntityId,
) -> Result<()> {
    let Some(raw) = vault
        .store
        .port_entity_record(txn, claim_id)?
        .map(|row| row.encode())
    else {
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvariantViolation(
            "VAD annotation claim id collision",
        ));
    }
    let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
        return Ok(());
    };
    if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
        || body.subject != ClaimSubject::Entity(*annotated)
    {
        return Err(Error::InvariantViolation(
            "VAD annotation claim id collision",
        ));
    }
    Ok(())
}

/// Whether `error` is a Gate write rejection whose outcome is Pending.
fn gate_rejection_pends(error: &Error) -> bool {
    matches!(
        error,
        Error::Gate(crate::error::GateError::GateWriteRejected { outcome, .. })
            if crate::error::GateDenialOutcome::parse(outcome)
                == Some(crate::error::GateDenialOutcome::Pending)
    )
}
