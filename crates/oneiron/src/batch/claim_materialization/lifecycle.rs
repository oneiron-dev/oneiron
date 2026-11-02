//! The lifecycle close materialization: the exact close of the current active
//! row, its proof, and the closer a typed lifecycle door verified.

use super::{ClaimMaterialization, binding_error, lifecycle_envelope, row_digest};
use crate::batch::{
    BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, VerifiedClaimTransition,
};
use crate::claim::{ClaimLifecycleStatus, decode_claim_body, encode_claim_body};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::WriteActor;

impl ClaimMaterialization {
    /// Only closing the current active row is admitted. No actor or evidence
    /// argument exists. The body must be identical except for life and valid_to.
    /// The doors close through [`Self::verified_lifecycle_closed_by`].
    #[cfg(test)]
    pub(crate) fn lifecycle(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Option<Self>> {
        Self::lifecycle_closed_by(store, txn, op, None)
    }

    /// The exact close of the current active row, carrying the closer its typed door verified, set
    /// before the binding's actor check runs.
    fn lifecycle_closed_by(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
        closer: Option<WriteActor>,
    ) -> Result<Option<Self>> {
        let BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        } = op
        else {
            return Err(binding_error());
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let Some(valid_to) = next.valid_to else {
            return Err(binding_error());
        };
        if valid_to < header.occurred_start {
            return Err(Error::InvalidTimeRange {
                start: header.occurred_start,
                end: valid_to,
            });
        }
        let mut expected = prior.clone();
        expected.lifecycle = next.lifecycle;
        expected.valid_to = next.valid_to;
        if prior.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                next.lifecycle,
                ClaimLifecycleStatus::Retracted | ClaimLifecycleStatus::Superseded
            )
            || encode_claim_body(&expected)? != *data
            || occurred.start != header.occurred_start
            || occurred.end != valid_to
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let Some(envelope) = lifecycle_envelope(store, txn, id, &prior)? else {
            return Ok(None);
        };
        let binding = Self {
            id: *id,
            occurred: *occurred,
            learned_at: *learned_at,
            data: data.clone(),
            reserved: false,
            envelope,
            prior: Some(row_digest(&raw)),
            approval: false,
            closer,
        };
        // Retraction records a gate decision before consuming the Put. Check
        // the reconstructed actor now, before any non-transactional metrics.
        binding.validate_actor(store, txn)?;
        Ok(Some(binding))
    }

    /// Canonical lifecycle validator supplies both an optional author binding
    /// and a sealed confidence-transition proof. Raw claims need no author
    /// binding, but still carry the proof of their exact closure operation.
    #[cfg(test)]
    pub(crate) fn verified_lifecycle(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<(Option<Self>, VerifiedClaimTransition)> {
        let binding = Self::lifecycle(store, txn, op)?;
        let proof = VerifiedClaimTransition::after_validation(store, txn, op)?;
        Ok((binding, proof))
    }

    /// [`Self::verified_lifecycle`] for a typed lifecycle door's close at
    /// `at` (FIX 8655, 10044, 10045): `closer` is the actor that door
    /// verified closing the row, never read off the row. Both the binding and
    /// the proof carry it, so the Gate and the audit name the closer and the
    /// apply stage asks the old author's standing of no one. A raw close
    /// (`None`) carries only its time and keeps every birth-author check.
    pub(crate) fn verified_lifecycle_closed_by(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
        closer: Option<WriteActor>,
        at: u64,
    ) -> Result<(Option<Self>, VerifiedClaimTransition)> {
        let binding = Self::lifecycle_closed_by(store, txn, op, closer)?;
        let proof = VerifiedClaimTransition::after_validation(store, txn, op)?;
        Ok((binding, proof.closed_by(closer, at)))
    }
}
