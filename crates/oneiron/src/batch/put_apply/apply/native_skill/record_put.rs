//! The actual record phases, carried to the same-writer native installer.

use heed::RwTxn;

use super::super::admission::FixedPut;
use crate::entity_doc::RecordDocumentCandidate;
use crate::error::{Error, Result};
use crate::skill_hub::RecordRefinementAdmission;
use crate::store::Store;

/// Created only after the original P1..P4 calls returned successfully. This
/// is not a local native publication, actor proof or arbitrary source review.
pub(crate) struct AdmittedRecordDocumentPut<'a> {
    candidate: &'a RecordDocumentCandidate<'a, 'a>,
    refinement: RecordRefinementAdmission<'a, 'a, 'a>,
}

impl<'a> AdmittedRecordDocumentPut<'a> {
    pub(in crate::batch::put_apply::apply) fn after_phases(
        store: &Store,
        txn: &mut RwTxn<'_>,
        fixed: &FixedPut<'a>,
        data: &[u8],
        refinement: Option<RecordRefinementAdmission<'a, 'a, 'a>>,
    ) -> Result<Option<Self>> {
        let Some(candidate) = fixed.record_document else {
            if refinement.is_some() {
                return Err(Error::InvariantViolation(
                    "ordinary put has a record refinement continuation",
                ));
            }
            return Ok(None);
        };
        let refinement = refinement.ok_or(Error::InvariantViolation(
            "record document put has no refinement continuation",
        ))?;
        if !fixed.replicated
            || fixed.skill_state_write.is_some()
            || fixed.entity_type != crate::registry::ENTITY_TYPE_SKILL
            || !candidate.applies_to(store, &fixed.id, data)
            || !refinement.names_candidate(candidate)
            || !candidate.recheck_in_txn(txn)?
        {
            return Err(Error::InvariantViolation(
                "record document differs from its admitted phases",
            ));
        }
        Ok(Some(Self {
            candidate,
            refinement,
        }))
    }

    pub(crate) fn candidate(&self) -> &'a RecordDocumentCandidate<'a, 'a> {
        self.candidate
    }

    pub(crate) fn refinement(&self) -> &RecordRefinementAdmission<'a, 'a, 'a> {
        &self.refinement
    }
}
