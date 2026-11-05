//! The refinement law for an exact already-stored own-device continuation.
//!
//! This owns only refinement admission. Native persistence still needs the
//! original record phases and the complete selected document source.

use heed::{RoTxn, RwTxn};

use super::refinement_admission::{RefinementAdmissionProof, validate_refinement_admission};
use crate::EntityId;
use crate::batch::VerifiedClaimTransition;
use crate::entity_doc::RecordDocumentCandidate;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::store::Store;
use crate::store::claim_refinement_control::{RefinementControl, read_control};
use crate::store::skill_refinement_origin::{
    CLAIM_ORIGIN, SKILL_ORIGIN, declares_skill_refinement,
};

/// No receipt, source hash or foreign revision can construct this admission.
/// The source-specific gate below runs in the actual applying writer.
pub(crate) struct RecordRefinementAdmission<'candidate, 'selected, 'carrier> {
    candidate: &'candidate RecordDocumentCandidate<'selected, 'carrier>,
    entity: EntityId,
    origin: Option<[u8; 32]>,
    prior_origin: Option<[u8; 32]>,
    prior_claim_origin: Option<[u8; 32]>,
    control: Option<RefinementControl>,
}

pub(crate) fn admit_record_document_refinement<'candidate, 'selected, 'carrier>(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    data: &[u8],
    candidate: &'candidate RecordDocumentCandidate<'selected, 'carrier>,
    proof: Option<&RefinementAdmissionProof>,
    transition: Option<&VerifiedClaimTransition>,
) -> Result<RecordRefinementAdmission<'candidate, 'selected, 'carrier>> {
    if !candidate.applies_to(store, entity, data) || !candidate.recheck_in_txn(txn)? {
        return Err(Error::InvariantViolation(
            "record document changed before refinement admission",
        ));
    }
    let prior_origin = SKILL_ORIGIN.get(store, txn, entity)?;
    let prior_claim_origin = CLAIM_ORIGIN.get(store, txn, entity)?;
    let control = read_control(store, txn, entity)?;
    let origin = candidate.source().refinement_origin().copied();
    if let Some(origin) = origin {
        // Preparation keeps an incomplete source pending. Do not substitute
        // today's body, a live revision, or a receiver-local revision id.
        let first = candidate
            .refinement_source()
            .ok_or(Error::InvariantViolation(
                "record refinement source was not prepared",
            ))?;
        let first_body = &first.raw()[crate::batch::ENTITY_METADATA_HEADER_LEN..];
        if blake3::hash(first_body).as_bytes() != &origin
            || prior_origin.is_some_and(|prior| prior != origin)
        {
            return Err(super::package_codec::invalid("refinement origin changed"));
        }
        let current = crate::skill::decode_skill_record(data)?;
        if !declares_skill_refinement(&current) {
            return Err(super::package_codec::invalid(
                "skill refinement origin requires useful-upstream admission",
            ));
        }
        // A source continuation is not a local decision for a pending or
        // refused proposal. Keep every original control/proof axis, including
        // erased ids, missing origins, target kind and exact promoted bytes.
        if control.is_some() || prior_claim_origin.is_some() {
            validate_refinement_admission(
                store,
                txn,
                entity,
                ENTITY_TYPE_SKILL,
                data,
                proof,
                transition,
            )?;
        }
        // With no local control, the actual own-device whole-source owner
        // continues the sender's already-lifecycled record. It does not submit
        // or promote a new local delta, nor change its permanent FIRST.
    } else {
        validate_refinement_admission(
            store,
            txn,
            entity,
            ENTITY_TYPE_SKILL,
            data,
            proof,
            transition,
        )?;
    }
    Ok(RecordRefinementAdmission {
        candidate,
        entity: *entity,
        origin,
        prior_origin,
        prior_claim_origin,
        control,
    })
}

impl RecordRefinementAdmission<'_, '_, '_> {
    pub(crate) fn names_candidate(&self, candidate: &RecordDocumentCandidate<'_, '_>) -> bool {
        std::ptr::eq(self.candidate, candidate)
    }

    fn controls_match(&self, store: &Store, txn: &RoTxn<'_>) -> Result<bool> {
        Ok(
            CLAIM_ORIGIN.get(store, txn, &self.entity)? == self.prior_claim_origin
                && read_control(store, txn, &self.entity)? == self.control,
        )
    }

    /// Only the actual phase continuation can reach this pre-install stage.
    /// Its selected physical row must already be staged in the same writer.
    pub(crate) fn stage_in_txn(
        &self,
        admitted: &crate::batch::AdmittedRecordDocumentPut<'_>,
        txn: &mut RwTxn<'_>,
    ) -> Result<()> {
        let candidate = admitted.candidate();
        let store = candidate.applying_store();
        if !self.names_candidate(candidate)
            || !candidate.recheck_staged_in_txn(txn)?
            || !self.controls_match(store, txn)?
            || SKILL_ORIGIN.get(store, txn, &self.entity)? != self.prior_origin
        {
            return Err(Error::InvariantViolation(
                "record refinement source changed before installation",
            ));
        }
        if let Some(origin) = &self.origin {
            SKILL_ORIGIN.put(store, txn, &self.entity, origin)?;
        }
        Ok(())
    }

    /// This is a post-install table check, not the pre-install HEAD recheck.
    pub(crate) fn installed_origin_matches(&self, store: &Store, txn: &RoTxn<'_>) -> Result<bool> {
        Ok(self.controls_match(store, txn)?
            && SKILL_ORIGIN.get(store, txn, &self.entity)? == self.origin.or(self.prior_origin))
    }

    pub(crate) fn has_source_origin(&self) -> bool {
        self.origin.is_some()
    }
}
