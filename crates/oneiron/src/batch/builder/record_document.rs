//! Pre-phase data for one actual queued record/document pair.
//!
//! Preparation owns the original operation. Its semantic view is for the
//! ordinary gates, not permission to capture or install the native document.

use heed::RwTxn;

use super::super::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_doc::{RecordDocumentCandidate, RecordDocumentPreparation, RecordDocumentStand};
use crate::error::Result;
use crate::sync::SelectedRecordDocument;

/// The replicated batch's applying outcome. Only the native variant owns an
/// actual installed document that survived all original final checks.
pub(crate) enum IngestedPutOutcome {
    Applied,
    NativeRecordApplied(AppliedRecordDocument),
    DocumentStands(RecordDocumentStand),
}

/// Not a commit receipt: the ingest savepoint and its parent still own commit.
/// The original actor frame, if observed, stays with its actual installed result.
pub(crate) struct AppliedRecordDocument {
    installed: crate::entity_doc::PendingRecordDocument,
    content_writes: Option<super::super::actor_content::ContentWriteSet>,
}

impl AppliedRecordDocument {
    pub(super) fn finish(
        vault: &crate::Vault,
        txn: &mut heed::RwTxn<'_>,
        records: Vec<crate::entity_doc::PendingRecordDocument>,
        candidate: Option<&RecordDocumentCandidate<'_, '_>>,
        content_writes: &mut Option<super::super::actor_content::ContentWriteSet>,
    ) -> Result<Option<Self>> {
        let mut records = records.into_iter();
        match (candidate, records.next(), records.next()) {
            (None, None, None) => Ok(None),
            (Some(candidate), Some(installed), None) => {
                installed.require_in_txn(&vault.store, txn, candidate)?;
                Ok(Some(Self {
                    installed,
                    content_writes: content_writes.take(),
                }))
            }
            _ => Err(crate::error::Error::InvariantViolation(
                "record document result differs from its applying batch",
            )),
        }
    }

    pub(crate) fn require_entity(&self, expected: &crate::EntityId) -> Result<()> {
        if self.installed.entity() != *expected {
            return Err(crate::error::Error::InvariantViolation(
                "native record result names another ingest row",
            ));
        }
        Ok(())
    }

    pub(crate) fn entity(&self) -> crate::EntityId {
        self.installed.entity()
    }

    /// Compare only a real completed batch result with the committed rows.
    /// Its outer materializer still owns commit, failure and retry markers.
    pub(crate) fn matches_stored_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
    ) -> Result<bool> {
        self.installed.matches_stored_in_txn(store, txn)
    }

}

impl std::fmt::Debug for AppliedRecordDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppliedRecordDocument")
            .field("entity", &self.entity())
            .finish_non_exhaustive()
    }
}

/// Every outcome keeps the actual queued operation. Independent local text
/// remains on its own physical route; none of these outcomes is admission.
pub(super) enum RecordDocumentOp<'selected, 'carrier> {
    Ordinary(BatchOp),
    Prepared(PreparedRecordPut<'selected, 'carrier>),
    Stands {
        operation: BatchOp,
        outcome: RecordDocumentStand,
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
        row_version,
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
        && *row_version == Some(header.row_version)
        && data.as_slice() == &selected.raw()[ENTITY_METADATA_HEADER_LEN..])
}
