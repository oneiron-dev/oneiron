//! Task proposal claim creation and landing.
//! Entry: `Memory::land_proposal_claim`.
//! Task DTOs stay at their existing `task_verb` paths.

use super::*;

impl Memory<'_> {
    pub(in crate::task_verb) fn persist_task_proposal(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
    ) -> MemoryResult<(EntityId, Option<String>)> {
        self.persist_proposal_claim(predicate, value, subject, now, provenance, |_, _| Ok(()))
    }

    /// [`Self::persist_task_proposal`] for a create (OF-532): a creator a
    /// host bound is re-proved and witnessed under the proposal id in the
    /// proposal's own transaction, before the claim lands, so no settlement
    /// can see the proposal without its origin. A root create keeps a
    /// witness only for the conversation the host stamped (OF-221).
    pub(in crate::task_verb) fn persist_task_proposal_with_origin(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
        creator: Option<&HostBinding>,
    ) -> MemoryResult<(EntityId, Option<String>)> {
        self.persist_proposal_claim(predicate, value, subject, now, provenance, |wtxn, id| {
            if let Some(origin) = task_create_origin_in_txn(self, &*wtxn, creator)? {
                put_proposal_origin_in_txn(self.vault(), wtxn, id, &origin)?;
            }
            Ok(())
        })
    }

    /// One Proposed task CLAIM, and whatever `witness` writes beside it under
    /// its id in the same transaction, before the claim lands.
    pub(in crate::task_verb) fn persist_proposal_claim(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
        witness: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<(EntityId, Option<String>)> {
        let proposal_ref = self.land_proposal_claim(
            predicate,
            value,
            subject,
            now,
            provenance,
            witness,
            |_, _| Ok(()),
        )?;
        let gate_decision_ref = self
            .vault()
            .gate_decisions(TASK_GATE_RECEIPT_SCAN_LIMIT)?
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(proposal_ref.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex())
            .map(|record| format!("gate:{}", record.decision_id.to_hex()));
        Ok((proposal_ref, gate_decision_ref))
    }

    /// [`Self::persist_proposal_claim`]'s write, answering the proposal's id:
    /// `witness` runs before the claim lands and `landed` after it, in the
    /// same transaction, so what `landed` writes commits with the gate's
    /// decision about the claim (FIX 3273).
    #[expect(
        clippy::too_many_arguments,
        reason = "one proposal's predicate, value, subject, time, provenance and its two in-transaction hooks"
    )]
    pub(in crate::task_verb) fn land_proposal_claim(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
        witness: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
        landed: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<EntityId> {
        let proposal_ref = self.vault().store.clock.entity_id()?;
        let mut candidate = ClaimCandidate::new(
            predicate.to_owned(),
            ClaimSubject::Entity(subject),
            value,
            1.0,
        );
        // A parked proposal is born where its writer's TASK would be.
        let position = self.birth_position();
        if let Some(world) = position.claim_world() {
            candidate = candidate.with_world(world);
        }
        if let Some(facet) = position.facet {
            candidate = candidate.with_scope_stamps(facet, crate::claim::default_project_id());
        }
        let envelope = match self.host_envelope(ClaimApprovalStatus::Proposed)? {
            Some(envelope) => envelope,
            None => WriteEnvelope::new(
                WriteActor::new(self.actor(), self.actor_class()),
                ClaimSource::ToolOutput,
                WriteProvenance::new(provenance)?,
                ClaimApprovalStatus::Proposed,
            ),
        };
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.with_verified_actor_write_txn(|wtxn| {
            witness(wtxn, proposal_ref)?;
            apply_ops_with_gate_mode(
                &self.vault().store,
                &self.vault().config,
                &self.vault().analyzer,
                wtxn,
                vec![BatchOp::ClaimCandidate {
                    id: proposal_ref,
                    candidate: Box::new(candidate),
                    envelope,
                    occurred,
                    learned_at: now,
                    internal_lexical_query_hint: false,
                }],
                self.vault().text_index_trusted.load(Ordering::Acquire),
                ApplyOpsGateMode::new(true, true),
            )
            .map_err(MemoryError::from)?;
            landed(wtxn, proposal_ref)
        })?;
        Ok(proposal_ref)
    }

    /// The gate's decision about a proposal, as [`Self::persist_proposal_claim`]
    /// names it (`gate:` and the newest decision's id), read in `txn`: in the
    /// transaction that landed the proposal, the decision it landed under.
    pub(in crate::task_verb) fn proposal_decision_ref_in(
        &self,
        txn: &heed::RoTxn<'_>,
        proposal_ref: EntityId,
    ) -> MemoryResult<Option<String>> {
        Ok(self
            .vault()
            .store
            .gate_decisions_for_claim_in_txn(txn, proposal_ref.as_bytes())?
            .into_iter()
            .max_by_key(|record| record.decision_id.to_hex())
            .map(|record| format!("gate:{}", record.decision_id.to_hex())))
    }
}
