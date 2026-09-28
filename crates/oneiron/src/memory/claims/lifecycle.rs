use super::commit::claim_envelope_actor;
use super::*;

impl Memory<'_> {
    pub(in crate::memory) fn evaluate_deletion_gate(&self) -> MemoryResult<DeletionGateContext> {
        let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &rtxn, self.actor, self.actor_class)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &rtxn)?;
        Ok(DeletionGateContext::new(
            self.actor,
            self.actor_class,
            crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            policy.read_frontier_hash()?,
        ))
    }

    /// Commits claims through the gated candidate path, one individually
    /// gated write per element (C3: per-element decisions; one bad element
    /// never sinks the others). Rejected elements come back with approval
    /// `rejected` and do not persist.
    pub fn commit(&self, claims: &[ClaimInput]) -> MemoryResult<Vec<CommitReceipt>> {
        Ok(self.commit_all(claims, true, None))
    }

    /// Commits one claim with single-cardinality auto-supersede (S3):
    /// prior Active claim matching `subject+scope+predicate` (plus
    /// `value.question_id` for declared multi-cardinality predicates, B1c)
    /// is superseded by the new revision.
    pub fn claim_upsert(&self, input: &ClaimInput) -> MemoryResult<CommitReceipt> {
        self.commit_one(input, true, None)
    }

    /// Proposes an independent claim without implicitly replacing a peer's head.
    /// A conflict review can cite this proposal; the proposal grants no authority.
    pub fn claim_propose(&self, input: &ClaimInput) -> MemoryResult<CommitReceipt> {
        self.commit_one(input, false, Some(ClaimApprovalStatus::Proposed))
    }

    /// Retracts an active claim (deliberate withdrawal; record preserved).
    ///
    /// Authority (fail-closed): the asserted actor is RESOLVED against the
    /// store in the SAME write transaction as the lifecycle change. A verified
    /// `human`-class actor holds the vault owner's memory authority and
    /// may retract any claim; `agent`/`system` actors may retract ONLY
    /// claims whose write-envelope evidence names them as the writing
    /// actor. Everything else is a typed denial — binding an actor key is
    /// not authority (W3).
    ///
    /// Actor binding, authorship, pending-consent closure, gate receipt, and
    /// lifecycle transition share one write transaction, so a same-id
    /// intervening writer cannot turn prior authorization into authority over
    /// the replacement body or recreate actionable pending consent.
    pub fn claim_retract(&self, claim_ref: &str) -> MemoryResult<CommitReceipt> {
        self.claim_retract_with_before_txn(claim_ref, || {})
    }

    fn claim_retract_with_before_txn(
        &self,
        claim_ref: &str,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<CommitReceipt> {
        let id = self.resolve_ref(claim_ref)?;
        let now = self.vault.store.clock.now_recorded_at();
        before_txn();
        let (approval, consent_decision_id) = self
            .with_actor_content_write_txn(|content| content.update_claim(id, |wtxn| {
            let body = self
                .vault
                .get_claim_in_txn(wtxn, &id)?
                .ok_or(Error::EntityNotFound)?;
            // This door does not own `companion.expression.*`, whoever is
            // asking. Closing one of those heads means restoring the
            // predecessor it superseded, and the general retraction below
            // performs only the closing half — leaving the preference chain
            // headless, with every earlier revision still superseded and
            // nothing active in their place. Asked before authorization
            // precisely because it is not an authorization question: an
            // authorized caller breaks the chain exactly as thoroughly.
            if crate::claim::is_expression_preference_predicate(&body.predicate) {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "an expression preference is retracted through its own door, not the general one",
                    &[
                        "Retract the preference through the vault's typed expression-preference door.",
                        "That door restores the predecessor this claim superseded; a general retraction does not.",
                    ],
                ));
            }
            if body.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE {
                self.verify_public_booking_writer_in_txn(wtxn)?;
            }
            let owns_claim = claim_envelope_actor(&body) == Some(self.actor)
                && crate::batch::authenticated_claim_author_in_txn(&self.vault.store, wtxn, &id, &body)?
                    .is_some_and(|author| author.entity_ref() == self.actor);
            if self.actor_class == EdgeActorClass::System || owns_claim {
                super::authorship::require_claim_self_grant_in_txn(
                    self.vault, wtxn, WriteActor::new(self.actor, self.actor_class),
                    id, &body, "memory.claim.retract",
                )?;
            }
            // Retracting your OWN claim is not an owner power and needs no
            // owner binding; retracting SOMEONE ELSE'S is, so it gets the
            // authority-log teeth.
            if !owns_claim && self.actor_class != EdgeActorClass::System {
                if self.actor_class != EdgeActorClass::Human {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!(
                            "actor {} ({}) may not retract a claim it did not write",
                            self.actor.to_hex(),
                            self.actor_class.gate_actor_class(),
                        ),
                        &[
                            "Only the writing actor or a human-class owner actor may retract.",
                            "Bind the owner actor key for cross-actor retraction.",
                        ],
                    ));
                }
                verify_owner_actor_binding_in_txn(self.vault, &*wtxn, self.actor)?;
                let raw = crate::claim::encode_claim_body(&body)?;
                let receipt = super::authorship::decision(
                    WriteActor::new(self.actor, self.actor_class), "memory_claim_override", "approved",
                    "gate.memory.explicit_owner_retraction", Some(id),
                    blake3::hash(&raw).as_bytes().to_vec(), now,
                );
                self.vault.store.append_gate_decision_in_txn(wtxn, &receipt)?;
            }
            if body.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE {
                super::booking_publication::stage_publication_write(self.vault, wtxn, id)?;
            }
            let consent_receipt = self.vault.retract_claim_in_txn(wtxn, &id, now)?;
            super::booking_publication::finish_publication_write(self.vault, wtxn, id)?;
            let approval = self.vault.get_claim_in_txn(wtxn, &id)?.map_or_else(
                || "retracted".to_owned(),
                |body| body.approval.as_str().to_owned(),
            );
            Ok((approval, consent_receipt.map(|record| record.decision_id)))
        }))?;
        let receipt_ref = match consent_decision_id {
            Some(decision_id) => format!("gate:{}", decision_id.to_hex()),
            None => self
                .latest_decision_ref_for(&id)?
                .unwrap_or_else(|| format!("retract:{}", id.to_hex())),
        };
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }

    #[cfg(test)]
    pub(in crate::memory) fn witness_with_pre_txn_hook(
        &self,
        turn: &WitnessTurn,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<WitnessReceipt> {
        self.witness_with_route_and_before_txn(turn, None, before_txn)
    }

    #[cfg(test)]
    pub(in crate::memory) fn claim_retract_with_pre_txn_hook(
        &self,
        claim_ref: &str,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<CommitReceipt> {
        self.claim_retract_with_before_txn(claim_ref, before_txn)
    }

    #[cfg(test)]
    pub(in crate::memory) fn claim_upsert_with_pre_txn_hook(
        &self,
        input: &ClaimInput,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<CommitReceipt> {
        self.commit_one_with_before_txn(input, true, None, before_txn)
    }

    // ── internals ───────────────────────────────────────────────────────
}
