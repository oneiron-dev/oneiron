//! Pre-phase data for one actual queued record/document pair.
//!
//! Preparation owns the original operation. Its semantic view is for the
//! ordinary gates, not permission to capture or install the native document.

use heed::RwTxn;

use super::super::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_doc::{DocumentMerge, RecordDocumentCandidate, RecordDocumentPreparation};
use crate::error::Result;
use crate::ports::DocumentSlot;
use crate::sync::SelectedRecordDocument;

/// Every outcome keeps the actual queued operation, including text whose
/// physical rows still need reconciliation. None of these is admission.
pub(super) enum RecordDocumentOp<'selected, 'carrier> {
    Ordinary(BatchOp),
    Prepared(PreparedRecordPut<'selected, 'carrier>),
    UnheadedText {
        operation: BatchOp,
        slots: Vec<DocumentSlot>,
    },
    Stands {
        operation: BatchOp,
        outcome: DocumentMerge,
    },
}

/// The original queued pointer and the joined semantic candidate, owned
/// together before any observer, mask or put phase runs.
pub(super) struct PreparedRecordPut<'selected, 'carrier> {
    operation: BatchOp,
    candidate: RecordDocumentCandidate<'selected, 'carrier>,
}

impl<'selected, 'carrier> RecordDocumentOp<'selected, 'carrier> {
    pub(super) fn prepare_in_txn(
        selected: Option<&'selected SelectedRecordDocument<'carrier>>,
        txn: &mut RwTxn<'_>,
        operation: BatchOp,
    ) -> Result<Self> {
        // Ordinary calls do not decode a new format or read native storage.
        let Some(selected) = selected else {
            return Ok(Self::Ordinary(operation));
        };
        if !names_selected_put(&operation, selected)? {
            return Ok(Self::Ordinary(operation));
        }
        Ok(
            match RecordDocumentCandidate::prepare_in_txn(selected, txn)? {
                RecordDocumentPreparation::Candidate(candidate) => {
                    Self::Prepared(PreparedRecordPut {
                        operation,
                        candidate,
                    })
                }
                RecordDocumentPreparation::TransportEnded => Self::Ordinary(operation),
                RecordDocumentPreparation::UnheadedText { slots } => {
                    Self::UnheadedText { operation, slots }
                }
                RecordDocumentPreparation::Stands(outcome) => Self::Stands { operation, outcome },
            },
        )
    }
}

impl<'selected, 'carrier> PreparedRecordPut<'selected, 'carrier> {
    pub(super) fn physical_operation(&self) -> &BatchOp {
        &self.operation
    }

    /// Changes only the body view. The id, type, timestamps and every actual
    /// queued admission flag stay as supplied by the original ingest door.
    pub(super) fn semantic_operation(&self) -> BatchOp {
        let mut semantic = self.operation.clone();
        if let BatchOp::Put { data, .. } = &mut semantic {
            *data = self.candidate.logical_body().to_vec();
        }
        semantic
    }

    pub(super) fn candidate(&self) -> &RecordDocumentCandidate<'selected, 'carrier> {
        &self.candidate
    }

    pub(super) fn recheck_in_txn(&self, txn: &mut RwTxn<'_>) -> Result<bool> {
        self.candidate.recheck_in_txn(txn)
    }
}

/// A selected transport answers only for the exact queued row, never another
/// put of the same entity, another timestamp, or a transformed inline body.
fn names_selected_put(operation: &BatchOp, selected: &SelectedRecordDocument<'_>) -> Result<bool> {
    let BatchOp::Put {
        id,
        entity_type,
        occurred,
        learned_at,
        data,
        ..
    } = operation
    else {
        return Ok(false);
    };
    if *id != selected.head().entity()? {
        return Ok(false);
    }
    let Some(header) = EntityMetadataHeader::parse(selected.raw()) else {
        return Ok(false);
    };
    Ok(*entity_type == header.entity_type
        && occurred.start == header.occurred_start
        && occurred.end == header.occurred_end
        && *learned_at == header.learned_at
        && data.as_slice() == &selected.raw()[ENTITY_METADATA_HEADER_LEN..])
}
