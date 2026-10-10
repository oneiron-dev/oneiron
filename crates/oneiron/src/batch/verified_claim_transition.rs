//! Sealed operation proof: minted only after the owning consent, curation or
//! lifecycle validator checks the complete operation in its write transaction.
//! This is not actor or Gate authorization and never crosses replicated replay.
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, encode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::temporal::TimeRange;

#[derive(Debug, Clone)]
pub(crate) struct VerifiedClaimTransition {
    id: EntityId,
    prior_hash: [u8; 32],
    next_body: Vec<u8>,
    occurred: TimeRange,
    learned_at: u64,
    // Canonical decay verifies the ClaimOf mutation as part of one bundle.
    // Bind that validated edge op as well as the claim Put.
    edge_delta: Option<(EntityId, crate::edge::EdgeKind, EntityId, u32)>,
    // A succession births a new row: `prior_hash` then pins the predecessor
    // it was derived from, and the successor id must still be unwritten.
    successor_of: Option<EntityId>,
}

impl VerifiedClaimTransition {
    /// Only `batch`'s canonical validation doors may mint this after they
    /// verify the entire operation (including the edge delta for decay).
    pub(in crate::batch) fn after_validation(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Self> {
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
            return Err(Error::InvalidClaimBody(
                "transition requires exact claim put",
            ));
        };
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Err(Error::InvalidClaimBody(
                "transition predecessor is not a claim",
            ));
        }
        Ok(Self {
            id: *id,
            prior_hash: *blake3::hash(&raw).as_bytes(),
            next_body: data.clone(),
            occurred: *occurred,
            learned_at: *learned_at,
            edge_delta: None,
            successor_of: None,
        })
    }

    /// Called only after the succession validator checks the successor body
    /// against its predecessor. The proof binds the unwritten successor Put
    /// to the exact predecessor row it was derived from.
    pub(in crate::batch) fn after_validated_succession(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        predecessor: &EntityId,
        op: &BatchOp,
    ) -> Result<Self> {
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
            return Err(Error::InvalidClaimBody(
                "transition requires exact claim put",
            ));
        };
        let raw = store
            .entities
            .get(txn, predecessor.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if id == predecessor || store.entities.get(txn, id.as_bytes())?.is_some() {
            return Err(Error::InvalidClaimBody("claim successor already exists"));
        }
        Ok(Self {
            id: *id,
            prior_hash: *blake3::hash(&raw).as_bytes(),
            next_body: data.clone(),
            occurred: *occurred,
            learned_at: *learned_at,
            edge_delta: None,
            successor_of: Some(*predecessor),
        })
    }

    /// Called only after `demotion_body` checks the complete Put + optional
    /// ClaimOf delta. Consumption rejects a substituted or omitted edge op.
    pub(in crate::batch) fn after_validated_demotion(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        ops: &[BatchOp],
    ) -> Result<Self> {
        let mut proof = Self::after_validation(
            store,
            txn,
            ops.first()
                .ok_or(Error::InvalidClaimBody("empty demotion"))?,
        )?;
        proof.edge_delta = match ops.get(1) {
            Some(BatchOp::SetEdgeWeight {
                src,
                kind,
                tgt,
                weight,
            }) if ops.len() == 2 => Some((*src, *kind, *tgt, weight.to_bits())),
            None if ops.len() == 1 => None,
            _ => return Err(Error::InvalidClaimBody("invalid verified demotion bundle")),
        };
        Ok(proof)
    }

    fn matches_following_edge(&self, remaining: &[BatchOp]) -> bool {
        match self.edge_delta {
            None => true,
            Some((src, kind, tgt, weight)) => matches!(remaining,
                [BatchOp::SetEdgeWeight { src: next_src, kind: next_kind,
                    tgt: next_tgt, weight: next_weight }]
                if *next_src == src && *next_kind == kind && *next_tgt == tgt
                    && next_weight.to_bits() == weight),
        }
    }

    /// The existing pending-consent binding is the owner-resolution door's
    /// authorization input. We check only the exact transition shape here;
    /// the caller retains owner auth, Gate and receipt obligations.
    pub(crate) fn after_consent(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Self> {
        let BatchOp::Put { id, data, .. } = op else {
            return Err(Error::InvalidClaimBody("consent requires claim put"));
        };
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        if prior.approval != crate::claim::ClaimApprovalStatus::Proposed {
            return Err(Error::InvalidClaimBody(
                "consent predecessor must be Proposed",
            ));
        }
        let pending =
            store
                .pending_gate_consent_in_txn(txn, id)?
                .ok_or(Error::InvalidClaimBody(
                    "consent transition missing pending binding",
                ))?;
        let (diff, frontier) = crate::gate::claim_consent_binding_parts(store, txn, &prior)?;
        if pending.diff_handle != diff || pending.read_frontier_hash != frontier {
            return Err(Error::InvalidClaimBody(
                "consent transition binding changed",
            ));
        }
        let mut expected = prior;
        match next.approval {
            crate::claim::ClaimApprovalStatus::Approved => expected.approval = next.approval,
            crate::claim::ClaimApprovalStatus::Rejected => {
                expected.approval = next.approval;
                // A MACHINE claim's signed fold rejects without retracting.
                if !crate::authority::machine_claim_needs_history(store, txn, &expected)? {
                    expected.lifecycle = crate::claim::ClaimLifecycleStatus::Retracted;
                    expected.valid_to = next.valid_to;
                }
            }
            _ => {
                return Err(Error::InvalidClaimBody(
                    "consent requires terminal approval",
                ));
            }
        }
        if expected != next {
            return Err(Error::InvalidClaimBody("consent body changed"));
        }
        Self::after_validation(store, txn, op)
    }

    /// Inbox has verified the pending binding and an owner edit preserving
    /// predicate and subject before applying this exact Approved body.
    pub(crate) fn after_consented_edit(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Self> {
        let BatchOp::Put { id, data, .. } = op else {
            return Err(Error::InvalidClaimBody("consent edit requires claim put"));
        };
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        store
            .pending_gate_consent_in_txn(txn, id)?
            .ok_or(Error::InvalidClaimBody(
                "consent edit missing pending binding",
            ))?;
        if prior.approval != crate::claim::ClaimApprovalStatus::Proposed
            || next.approval != crate::claim::ClaimApprovalStatus::Approved
            || prior.predicate != next.predicate
            || prior.subject != next.subject
        {
            return Err(Error::InvalidClaimBody(
                "consent edit not bound to proposal",
            ));
        }
        Self::after_validation(store, txn, op)
    }

    /// Session-bundle merge already validated the producer/actor and gated
    /// this exact claim. It may not use a consent proof for Auto promotion.
    pub(crate) fn after_session_merge(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Self> {
        let BatchOp::Put { id, data, .. } = op else {
            return Err(Error::InvalidClaimBody("session merge requires claim put"));
        };
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let mut expected = prior.clone();
        expected.approval = crate::claim::ClaimApprovalStatus::Approved;
        if prior.approval != crate::claim::ClaimApprovalStatus::Proposed
            || prior.session_tag.is_none()
            || expected != next
        {
            return Err(Error::InvalidClaimBody(
                "session merge body or producer changed",
            ));
        }
        Self::after_validation(store, txn, op)
    }

    /// Same-transaction freshness and exact target, bytes and metadata. An
    /// unrelated Put cannot borrow a proof from a previously checked row.
    pub(crate) fn matches_put(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<bool> {
        if self.occurred != occurred || self.learned_at != learned_at {
            return Ok(false);
        }
        self.matches_body(store, txn, id, body)
    }

    pub(crate) fn matches_body(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
    ) -> Result<bool> {
        if *id != self.id || encode_claim_body(body)? != self.next_body {
            return Ok(false);
        }
        let pinned = match self.successor_of {
            Some(predecessor) => {
                if store.entities.get(txn, id.as_bytes())?.is_some() {
                    return Ok(false);
                }
                predecessor
            }
            None => *id,
        };
        Ok(store
            .entities
            .get(txn, pinned.as_bytes())?
            .is_some_and(|raw| blake3::hash(&raw).as_bytes() == &self.prior_hash))
    }

    /// The predecessor a succession proof was derived from; `None` for an
    /// in-place transition of its own row.
    pub(crate) fn predecessor(&self) -> Option<EntityId> {
        self.successor_of
    }

    pub(crate) fn matches_op(&self, op: &BatchOp) -> bool {
        matches!(op, BatchOp::Put { id, entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred, learned_at, data, allow_maintenance: false,
            allow_reserved_predicate: false, hub_sync_imported: false }
            if *id == self.id && *occurred == self.occurred
                && *learned_at == self.learned_at && *data == self.next_body)
    }
}

/// Consume the next sealed operation only at its exact Put. A mismatched
/// claim Put cannot steal a proof intended for a later op.
pub(super) fn consume_next(
    queue: &mut std::collections::VecDeque<VerifiedClaimTransition>,
    op: &BatchOp,
    remaining: &[BatchOp],
) -> Result<Option<VerifiedClaimTransition>> {
    if queue
        .front()
        .is_some_and(|proof| proof.matches_op(op) && proof.matches_following_edge(remaining))
    {
        Ok(queue.pop_front())
    } else if !queue.is_empty()
        && matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        )
    {
        Err(Error::InvalidClaimBody(
            "verified claim transition operation mismatch",
        ))
    } else {
        Ok(None)
    }
}

pub(super) fn require_consumed(
    queue: &std::collections::VecDeque<VerifiedClaimTransition>,
) -> Result<()> {
    if queue.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "unconsumed verified claim transition",
        ))
    }
}
