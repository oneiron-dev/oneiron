//! Sealed operation proof: minted only after the owning consent, curation or
//! lifecycle validator checks the complete operation in its write transaction.
//! This is not actor or Gate authorization and never crosses replicated replay.
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::write_envelope::claim_body::{ClaimBody, encode_claim_body};

#[derive(Debug, Clone, Copy)]
enum TransitionKind {
    Ordinary,
    StoredSectionFitActorErasure {
        actor: EntityId,
        claim_of: Option<EntityId>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedClaimTransition {
    kind: TransitionKind,
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
    // A typed lifecycle door's close (FIX 8655, 10044, 10045): the closer it
    // verified, never the row's birth author, and the time it closed at.
    closer: Option<WriteActor>,
    closed_at: Option<u64>,
}

impl VerifiedClaimTransition {
    /// Derives the complete projection and normal subject edge inside the
    /// accepted erase's borrowed writer. Neither body nor extra operations
    /// can be supplied by the receipt scanner.
    pub(in crate::batch) fn stored_section_fit_actor_erasure(
        erase: &mut crate::deletion::ActorErasureWriter<'_, '_>,
        id: &EntityId,
    ) -> Result<Option<(Vec<BatchOp>, Self)>> {
        let (vault, txn, actor) = erase.parts();
        let store = &vault.store;
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw)
            .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        else {
            return Ok(None);
        };
        let Ok(prior) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            return Ok(None);
        };
        let Some(next) =
            crate::context_board::stored_section_fit_actor_erasure_body(&prior, &actor)
        else {
            return Ok(None);
        };
        let data = encode_claim_body(&next)?;
        crate::claim::validate_claim_body_and_decode_in_txn(store, txn, &data, true)?;
        let claim_of = match next.subject {
            crate::claim::ClaimSubject::Entity(subject) => {
                if crate::ports::EntityStoreRead::port_entity_record(store, txn, &subject)?
                    .is_none()
                {
                    return Err(Error::EntityNotFound);
                }
                Some(subject)
            }
            crate::claim::ClaimSubject::Edge { .. } => None,
        };
        let occurred = TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        };
        let mut ops = vec![BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at: header.learned_at,
            row_version: Some(header.row_version),
            data: data.clone(),
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }];
        if let Some(subject) = claim_of {
            ops.push(BatchOp::Edge {
                src: *id,
                kind: crate::edge::EdgeKind::ClaimOf,
                tgt: subject,
                weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                vad: oneiron_contracts::affect::Vad::NEUTRAL,
            });
        }
        Ok(Some((
            ops,
            Self {
                kind: TransitionKind::StoredSectionFitActorErasure { actor, claim_of },
                id: *id,
                prior_hash: *blake3::hash(&raw).as_bytes(),
                next_body: data,
                occurred,
                learned_at: header.learned_at,
                edge_delta: None,
                successor_of: None,
                closer: None,
                closed_at: None,
            },
        )))
    }

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
            row_version: _,
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Err(Error::InvalidClaimBody(
                "transition predecessor is not a claim",
            ));
        }
        Ok(Self {
            kind: TransitionKind::Ordinary,
            id: *id,
            prior_hash: *blake3::hash(&raw).as_bytes(),
            next_body: data.clone(),
            occurred: *occurred,
            learned_at: *learned_at,
            edge_delta: None,
            successor_of: None,
            closer: None,
            closed_at: None,
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
            row_version: _,
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, predecessor)?
            .ok_or(Error::EntityNotFound)?;
        if id == predecessor || crate::ports::EntityStoreRead::port_entity_present(store, txn, id)?
        {
            return Err(Error::InvalidClaimBody("claim successor already exists"));
        }
        Ok(Self {
            kind: TransitionKind::Ordinary,
            id: *id,
            prior_hash: *blake3::hash(&raw).as_bytes(),
            next_body: data.clone(),
            occurred: *occurred,
            learned_at: *learned_at,
            edge_delta: None,
            successor_of: Some(*predecessor),
            closer: None,
            closed_at: None,
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
        if let TransitionKind::StoredSectionFitActorErasure { claim_of, .. } = self.kind {
            return match claim_of {
                Some(subject) => matches!(remaining,
                    [BatchOp::Edge { src, kind: crate::edge::EdgeKind::ClaimOf, tgt, weight, vad }]
                    if *src == self.id && *tgt == subject
                        && weight.to_bits() == crate::vault::CLAIM_OF_DEFAULT_WEIGHT.to_bits()
                        && *vad == oneiron_contracts::affect::Vad::NEUTRAL),
                None => remaining.is_empty(),
            };
        }
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::write_envelope::claim_body::decode_claim_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            false,
        )?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        if prior.approval != oneiron_contracts::claim::ClaimApprovalStatus::Proposed {
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
            oneiron_contracts::claim::ClaimApprovalStatus::Approved => {
                expected.approval = next.approval
            }
            oneiron_contracts::claim::ClaimApprovalStatus::Rejected => {
                expected.approval = next.approval;
                // A MACHINE claim's signed fold rejects without retracting.
                if !crate::authority::machine_claim_needs_history(store, txn, &expected)? {
                    expected.lifecycle = oneiron_contracts::claim::ClaimLifecycleStatus::Retracted;
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

    /// The owner's reviewed rejection of an ordinary proposal that waits in
    /// no pending-consent row (DOOR-115). With no tray binding to answer, the
    /// settlement door's owner proof, review handle and live Gate replay are
    /// its authorization input; we check only the exact closing shape. The
    /// row must still be an active Proposed claim outside MACHINE signed
    /// history with no tray row, and the Put may only reject and retract it
    /// with `valid_to` at `now`, end its occurred range at `now` (never
    /// before its start) and keep its learned time.
    pub(crate) fn after_reviewed_rejection(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
        now: u64,
    ) -> Result<Self> {
        let BatchOp::Put {
            id,
            occurred,
            learned_at,
            data,
            ..
        } = op
        else {
            return Err(Error::InvalidClaimBody("rejection requires claim put"));
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .filter(|h| h.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
            .ok_or(Error::InvalidClaimBody(
                "rejection predecessor is not a claim",
            ))?;
        let prior = crate::write_envelope::claim_body::decode_claim_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            false,
        )?;
        if prior.approval != oneiron_contracts::claim::ClaimApprovalStatus::Proposed
            || prior.lifecycle != oneiron_contracts::claim::ClaimLifecycleStatus::Active
        {
            return Err(Error::InvalidClaimBody(
                "rejection predecessor must be an active proposal",
            ));
        }
        if crate::authority::machine_claim_needs_history(store, txn, &prior)? {
            return Err(Error::InvalidClaimBody(
                "a MACHINE claim rejects through its signed history",
            ));
        }
        if store.pending_gate_consent_in_txn(txn, id)?.is_some() {
            return Err(Error::InvalidClaimBody(
                "a proposal in the tray rejects through its consent",
            ));
        }
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let mut expected = prior;
        expected.approval = oneiron_contracts::claim::ClaimApprovalStatus::Rejected;
        expected.lifecycle = oneiron_contracts::claim::ClaimLifecycleStatus::Retracted;
        expected.valid_to = Some(now);
        let closed = TimeRange {
            start: header.occurred_start,
            end: now.max(header.occurred_start),
        };
        if expected != next || *occurred != closed || *learned_at != header.learned_at {
            return Err(Error::InvalidClaimBody("rejection body changed"));
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::write_envelope::claim_body::decode_claim_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            false,
        )?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        store
            .pending_gate_consent_in_txn(txn, id)?
            .ok_or(Error::InvalidClaimBody(
                "consent edit missing pending binding",
            ))?;
        if prior.approval != oneiron_contracts::claim::ClaimApprovalStatus::Proposed
            || next.approval != oneiron_contracts::claim::ClaimApprovalStatus::Approved
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::write_envelope::claim_body::decode_claim_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            false,
        )?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let mut expected = prior.clone();
        expected.approval = oneiron_contracts::claim::ClaimApprovalStatus::Approved;
        if prior.approval != oneiron_contracts::claim::ClaimApprovalStatus::Proposed
            || prior.session_tag.is_none()
            || expected != next
        {
            return Err(Error::InvalidClaimBody(
                "session merge body or producer changed",
            ));
        }
        Self::after_validation(store, txn, op)
    }

    /// The owner's not-a-secret ruling on a key found in a claim puts the
    /// value back where the mask left its handle (FIX 11882). The found-key
    /// door holds the owner proof and the Gate record; we check only the
    /// exact restore shape: the next body is the stored one with `value`
    /// back in its value, evidence and scope (the parts the mask reads),
    /// and nothing else changed. A claim whose body its MACHINE signed
    /// history owns cannot be restored here: its proof would fail over the
    /// restored body, and no door re-signs a stored claim.
    pub(crate) fn after_owner_restore(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
        handle: &str,
        value: &[u8],
    ) -> Result<Self> {
        let BatchOp::Put { id, data, .. } = op else {
            return Err(Error::InvalidClaimBody("owner restore requires claim put"));
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let prior = crate::write_envelope::claim_body::decode_claim_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            false,
        )?;
        if crate::authority::machine_claim_needs_history(store, txn, &prior)? {
            return Err(Error::InvalidClaimBody(
                "a MACHINE claim's body is owned by its signed history",
            ));
        }
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let text_form = format!("{}{handle}]", crate::file_secret_marks::HANDLE_TEXT_OPEN);
        let mut expected = prior;
        let mut changed = false;
        for part in [
            Some(&mut expected.value),
            expected.evidence.as_mut(),
            expected.scope.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            changed |= crate::file_secret_marks::unmask_value(part, handle, &text_form, value)
                .map_err(|_| Error::InvalidClaimBody("owner restore body changed"))?;
        }
        if !changed || expected != next {
            return Err(Error::InvalidClaimBody("owner restore body changed"));
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
                if crate::ports::EntityStoreRead::port_entity_present(store, txn, id)? {
                    return Ok(false);
                }
                predecessor
            }
            None => *id,
        };
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &pinned)? else {
            return Ok(false);
        };
        if blake3::hash(&raw).as_bytes() != &self.prior_hash {
            return Ok(false);
        }
        if let TransitionKind::StoredSectionFitActorErasure { actor, .. } = self.kind {
            let Ok(prior) =
                crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
            else {
                return Ok(false);
            };
            let Some(expected) =
                crate::context_board::stored_section_fit_actor_erasure_body(&prior, &actor)
            else {
                return Ok(false);
            };
            return Ok(encode_claim_body(&expected)? == self.next_body);
        }
        Ok(true)
    }

    /// Only this exact stored erasure may omit fresh Auto source-trust.
    /// Masking and other normal transforms must still match the sealed body.
    pub(crate) fn matches_stored_section_fit_actor_erasure(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<bool> {
        if !matches!(
            self.kind,
            TransitionKind::StoredSectionFitActorErasure { .. }
        ) {
            return Ok(false);
        }
        if !self.matches_put(store, txn, id, body, occurred, learned_at)? {
            return Err(Error::InvalidClaimBody(
                "stored actor erasure proof mismatch",
            ));
        }
        Ok(true)
    }

    /// This proof stamped with its lifecycle door's close: `closer` the actor
    /// the door verified (none for a raw close), closing at `at`. Only the
    /// lifecycle materialization stamps it.
    pub(in crate::batch) fn closed_by(mut self, closer: Option<WriteActor>, at: u64) -> Self {
        self.closer = closer;
        self.closed_at = Some(at);
        self
    }

    /// The actor a typed lifecycle door verified closing this claim.
    pub(crate) const fn closer(&self) -> Option<WriteActor> {
        self.closer
    }

    /// The time a lifecycle door closed this claim at.
    pub(crate) const fn closed_at(&self) -> Option<u64> {
        self.closed_at
    }

    /// The predecessor a succession proof was derived from; `None` for an
    /// in-place transition of its own row.
    pub(crate) fn predecessor(&self) -> Option<EntityId> {
        self.successor_of
    }

    pub(crate) fn matches_op(&self, op: &BatchOp) -> bool {
        let reserved = matches!(
            self.kind,
            TransitionKind::StoredSectionFitActorErasure { .. }
        );
        matches!(op, BatchOp::Put { id, entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred, learned_at, row_version: _, data, allow_maintenance: false,
            allow_reserved_predicate, hub_sync_imported: false }
            if *id == self.id && *occurred == self.occurred
                && *learned_at == self.learned_at && *data == self.next_body
                && *allow_reserved_predicate == reserved)
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
