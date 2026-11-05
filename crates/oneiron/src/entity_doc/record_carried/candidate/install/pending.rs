//! Owned installed rows, carried past the put's borrowed semantic buffer.

use heed::RwTxn;

use super::super::{RecordDocumentCandidate, document_rows_digest};
use super::InstalledRecordDocument;
use crate::EntityId;
use crate::entity_doc::{invalid, storage};
use crate::error::Result;
use crate::ports::{DocumentSlot, EntityStoreRead};
use crate::store::Store;
use crate::store::claim_refinement_control::{RefinementControl, read_control};
use crate::store::skill_refinement_origin::{CLAIM_ORIGIN, SKILL_ORIGIN};

/// Produced by the actual installer after P6, not by a selected candidate.
/// The batch must still run its tail, actor-after and final caller checks.
pub(crate) struct PendingRecordDocument {
    entity: EntityId,
    physical: [u8; 32],
    logical: [u8; 32],
    head: Vec<u8>,
    documents: Vec<(DocumentSlot, [u8; 32])>,
    skill_origin: Option<[u8; 32]>,
    claim_origin: Option<[u8; 32]>,
    control: Option<RefinementControl>,
}

impl InstalledRecordDocument<'_> {
    pub(crate) fn after_projections(
        self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        entity: &EntityId,
        data: &[u8],
    ) -> Result<PendingRecordDocument> {
        self.require_rows_in_txn(store, txn, entity, data)?;
        // P6 may have staged an ordinary first-Candidate origin when the
        // transported source had none. Retain that actual post-P6 result.
        let skill_origin = SKILL_ORIGIN.get(store, txn, entity)?;
        let claim_origin = CLAIM_ORIGIN.get(store, txn, entity)?;
        let control = read_control(store, txn, entity)?;
        Ok(PendingRecordDocument {
            entity: *entity,
            physical: *blake3::hash(self.admitted.candidate().physical_raw()).as_bytes(),
            logical: *blake3::hash(data).as_bytes(),
            head: self.head,
            documents: self.documents,
            skill_origin,
            claim_origin,
            control,
        })
    }
}

impl PendingRecordDocument {
    pub(crate) fn entity(&self) -> EntityId {
        self.entity
    }

    /// Recheck the real installed output after all outer applying checks.
    /// The candidate only renews its source binding; it cannot create this result.
    pub(crate) fn require_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        candidate: &RecordDocumentCandidate<'_, '_>,
    ) -> Result<()> {
        if !candidate.applies_to(store, &self.entity, candidate.logical_body())
            || !candidate.selected.recheck_transport_in_txn(store, txn)?
            || blake3::hash(candidate.physical_raw()).as_bytes() != &self.physical
            || blake3::hash(candidate.logical_body()).as_bytes() != &self.logical
            || store
                .port_entity_raw(txn, &self.entity)?
                .is_none_or(|raw| blake3::hash(&raw).as_bytes() != &self.physical)
            || storage::record_head_bytes(store, txn, &self.entity)?.as_deref()
                != Some(self.head.as_slice())
            || SKILL_ORIGIN.get(store, txn, &self.entity)? != self.skill_origin
            || CLAIM_ORIGIN.get(store, txn, &self.entity)? != self.claim_origin
            || read_control(store, txn, &self.entity)? != self.control
        {
            return Err(invalid(
                "installed record document changed before final apply",
            ));
        }
        for (slot, digest) in &self.documents {
            if document_rows_digest(store, txn, *slot)? != *digest {
                return Err(invalid(
                    "installed record document rows changed before final apply",
                ));
            }
        }
        Ok(())
    }
}
