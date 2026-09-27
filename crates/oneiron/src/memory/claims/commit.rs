use super::*;

impl Memory<'_> {
    // ── internals ───────────────────────────────────────────────────────

    pub(in crate::memory) fn commit_all(
        &self,
        claims: &[ClaimInput],
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> Vec<CommitReceipt> {
        let mut receipts = Vec::with_capacity(claims.len());
        for input in claims {
            match self.commit_one(input, auto_supersede, forced_approval) {
                Ok(receipt) => receipts.push(receipt),
                Err(err) => receipts.push(CommitReceipt {
                    claim_short_id: input.id.clone().unwrap_or_default(),
                    approval: "rejected".to_owned(),
                    superseded_short_id: None,
                    receipt_ref: format!("rejected:{}", err.code),
                }),
            }
        }
        receipts
    }

    pub(super) fn commit_one(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_one_with_before_txn(input, auto_supersede, forced_approval, || {})
    }

    /// Upserts one claim, running `before_txn` in the window between the
    /// ADVISORY prior-claim lookup and the write transaction.
    ///
    /// That window is the race the in-txn guard closes: the prior discovered
    /// outside the transaction may have moved by the time the transaction
    /// runs. The seam exists so a test can move it deliberately; production
    /// callers pass a no-op.
    pub(super) fn commit_one_with_before_txn(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<CommitReceipt> {
        // This door does not own `companion.expression.*` any more than
        // `claim_retract` does, and for the mirror-image reason. Writing a new
        // head of that family means superseding the CURRENT head under the
        // family's own precedence rules — source rank, then validity, then
        // recency — and the generic upsert below supersedes on
        // `subject+scope+predicate` alone. Those disagree: a new `Inferred`
        // revision written here closes a `UserStated` head the typed door
        // would have left standing, and the supersession chain the typed
        // retraction walks back is silently wrong from then on. Asked before
        // anything is resolved, because it is not an authorization question —
        // an authorized caller breaks the chain exactly as thoroughly.
        //
        // Every generic claim-write door routes through here (`commit`,
        // `claim_upsert`, `seed_claims` via `commit_all`), so one guard covers
        // all three.
        // Keyed facts bind subject, envelope actor/class, worldless scope,
        // exact address, and replay identity together. A generic upsert's
        // subject+scope match must not supersede another actor's keyed fact.
        if input.predicate == super::key_value::PREDICATE {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "keyed memory is written through key_value_put",
                &[
                    "Use the actor-bound keyed-memory door; generic claims cannot replace keyed facts.",
                ],
            ));
        }
        if crate::claim::is_expression_preference_predicate(&input.predicate) {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "an expression preference is written through its own door, not the general one",
                &[
                    "Write the preference through the vault's typed expression-preference door.",
                    "That door supersedes the head this family's own precedence rules pick; a general write does not.",
                ],
            ));
        }
        self.verified_actor_class()?;
        let id = id_from_optional_hex(self.vault, input.id.as_deref())?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(MemoryError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let source = parse_claim_source(&input.source)?;
        let value = json_to_rmpv(&input.value);
        let world = match &input.world_ref {
            Some(world_ref) => Some(self.resolve_ref(world_ref)?),
            None => None,
        };
        let relationship = input
            .relationship_ref
            .as_deref()
            .map(|r| self.resolve_ref(r))
            .transpose()?;
        let scope_rmpv = input.scope.as_ref().map(json_to_rmpv);
        let now = self.vault.store.clock.now_recorded_at();
        let occurred_at = input.occurred_at.unwrap_or(now);
        let learned_at = input.learned_at.unwrap_or(now);

        // ADVISORY only (ONE-1936): this lookup runs outside the transaction,
        // so the prior it names may already be closed by the time the write
        // txn opens. The authority is `supersede_claim_in_txn`'s guard, inside
        // that txn — and a refusal there rolls the staged replacement back
        // with it.
        let prior = if auto_supersede {
            self.find_prior_claim(&subject, input, &id)?
        } else {
            None
        };
        before_txn();

        // Preserve the owner's typed refusal across the engine transaction
        // closure, whose error type is the storage API's rather than MemoryError.
        let publication_refusal = std::cell::RefCell::new(None);
        let mut approval =
            forced_approval.unwrap_or_else(|| requested_approval(source, input.scope.as_ref()));
        // Every commit is ONE engine transaction: gate decision, claim
        // write, and (with a prior revision) the deferred closure binding
        // commit or roll back together. No phantom receipts (a decision can never
        // outlive a write that failed later validation) and no orphan
        // revisions behind a rejected receipt. The fail-closed trade: a
        // rolled-back write also drops its gate decision.
        let write = |approval: ClaimApprovalStatus| -> Result<bool, Error> {
            let mut candidate = ClaimCandidate::new(
                input.predicate.clone(),
                ClaimSubject::Entity(subject),
                value.clone(),
                input.confidence,
            )
            .with_validity(input.valid_from, input.valid_to);
            if let Some(salience) = input.salience {
                candidate = candidate.with_salience(salience);
            }
            if let Some(world) = world {
                candidate = candidate.with_world(world);
            }
            if let Some(relationship) = relationship {
                candidate = candidate.with_relationship(relationship);
            }
            if let Some(scope) = scope_rmpv.clone() {
                candidate = candidate.with_scope(scope);
            }
            let mut envelope = WriteEnvelope::new(
                WriteActor::new(self.actor, self.actor_class),
                source,
                WriteProvenance::new(facade_provenance("commit"))?,
                approval,
            );
            let occurred = TimeRange {
                start: occurred_at,
                end: occurred_at,
            };
            self.vault.with_write_txn(|wtxn| {
                if input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE
                    && let Err(error) = self.verify_public_booking_writer_in_txn(wtxn)
                {
                    *publication_refusal.borrow_mut() = Some(error);
                    return Err(Error::InvalidClaimBody(
                        "booking publication owner authority refused",
                    ));
                }
                if let Some(raw) = self.vault.get_raw_in(wtxn, &id)?
                    && crate::batch::EntityMetadataHeader::parse(&raw).is_some_and(|header| {
                        header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    })
                    && self
                        .vault
                        .get_claim_in_txn(wtxn, &id)?
                        .is_some_and(|existing| existing.predicate == super::key_value::PREDICATE)
                {
                    return Err(Error::InvalidClaimBody(
                        "keyed claim revisions cannot be overwritten through generic claims",
                    ));
                }
                if self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
                {
                    return Ok(true);
                }
                super::authorship::guard_existing_claim_in_txn(
                    self.vault,
                    wtxn,
                    envelope.actor(),
                    id,
                )?;
                if let Some(old_id) = prior {
                    let old = self
                        .vault
                        .get_claim_in_txn(wtxn, &old_id)?
                        .ok_or(Error::EntityNotFound)?;
                    super::authorship::require_claim_self_grant_in_txn(
                        self.vault,
                        wtxn,
                        envelope.actor(),
                        old_id,
                        &old,
                        "memory.claim.supersede",
                    )?;
                }
                let publication_write =
                    input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE;
                if publication_write {
                    super::booking_publication::stage_publication_write(self.vault, wtxn, id)?;
                    if let Some(old_id) = prior {
                        super::booking_publication::stage_publication_write(
                            self.vault, wtxn, old_id,
                        )?;
                    }
                }
                // A replacement is a create-versus-closure proposal even when its
                // source and actor would qualify for Auto. The later grant is
                // the only door allowed to close the prior head.
                if prior.is_some() {
                    envelope = WriteEnvelope::new(
                        envelope.actor(),
                        source,
                        envelope.provenance().clone(),
                        ClaimApprovalStatus::Proposed,
                    );
                }
                let closure_envelope = envelope.clone();
                apply_ops_with_gate_mode(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    vec![BatchOp::ClaimCandidate {
                        id,
                        candidate: Box::new(candidate),
                        envelope,
                        occurred,
                        learned_at,
                        internal_lexical_query_hint: false,
                    }],
                    self.vault.text_index_trusted.load(Ordering::Acquire),
                    ApplyOpsGateMode::new(true, true),
                )?;
                if let Some(old_id) = prior {
                    self.vault.stage_claim_supersession_in_txn(
                        wtxn,
                        &id,
                        &old_id,
                        &closure_envelope,
                        learned_at,
                    )?;
                }
                if publication_write {
                    crate::booking::publication::index_publication_in_txn(
                        self.vault, wtxn, subject, id,
                    )?;
                    super::booking_publication::finish_publication_write(self.vault, wtxn, id)?;
                    if let Some(old_id) = prior {
                        super::booking_publication::finish_publication_write(
                            self.vault, wtxn, old_id,
                        )?;
                    }
                }
                Ok(false)
            })
        };
        let refused = match write(approval) {
            Ok(refused) => refused,
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                write(approval)
                    .map_err(|err| publication_refusal.take().unwrap_or_else(|| err.into()))?
            }
            Err(err) => return Err(publication_refusal.take().unwrap_or_else(|| err.into())),
        };
        if refused {
            return Err(hard_deleted_refusal(&id));
        }

        let superseded_short_id = match prior {
            Some(old_id)
                if self
                    .vault
                    .get_claim(&old_id)?
                    .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Superseded) =>
            {
                Some(self.short_ref_or_hex(&old_id)?)
            }
            Some(_) => None,
            None => None,
        };
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval: final_approval,
            superseded_short_id,
            receipt_ref,
        })
    }

    /// Prior-claim match for auto-supersede: `subject+scope+predicate`,
    /// extended with `value.question_id` for declared multi-cardinality
    /// predicates (B1c). Deterministic when multiple actives match: the
    /// newest id (UUIDv7 order) wins.
    fn find_prior_claim(
        &self,
        subject: &EntityId,
        input: &ClaimInput,
        exclude: &EntityId,
    ) -> MemoryResult<Option<EntityId>> {
        let multi_key = if MULTI_CARDINALITY_PREDICATES.contains(&input.predicate.as_str()) {
            Some(input.value.get(MULTI_CARDINALITY_VALUE_KEY).cloned())
        } else {
            None
        };
        let new_scope = input.scope.clone();
        let world = input
            .world_ref
            .as_deref()
            .map(|r| self.resolve_ref(r))
            .transpose()?;
        let relationship = input
            .relationship_ref
            .as_deref()
            .map(|r| self.resolve_ref(r))
            .transpose()?;
        let ids = self.vault.claims_for_subject(subject)?;
        let mut best: Option<EntityId> = None;
        for id in ids {
            if id == *exclude {
                continue;
            }
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active
                || !matches!(
                    body.approval,
                    ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                )
                || body.predicate != input.predicate
                || body.world != world
            {
                continue;
            }
            let prior_scope = body.scope.as_ref().map(companion_value_to_json);
            if prior_scope != new_scope || body.world != world || body.rel != relationship {
                continue;
            }
            if let Some(new_qid) = &multi_key {
                let prior_value = companion_value_to_json(&body.value);
                let prior_qid = prior_value.get(MULTI_CARDINALITY_VALUE_KEY).cloned();
                if prior_qid != *new_qid {
                    continue;
                }
            }
            best = match best {
                Some(current) if current.to_hex() >= id.to_hex() => Some(current),
                _ => Some(id),
            };
        }
        Ok(best)
    }
}

/// Extracts the write-envelope actor stamped into a claim's evidence
/// (gated candidate path). `None` for claims written without an envelope.
pub(super) fn claim_envelope_actor(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    for (key, value) in entries {
        if key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
            && let Value::Binary(bytes) = value
        {
            let raw: [u8; 16] = bytes.as_slice().try_into().ok()?;
            return EntityId::from_bytes(raw).ok();
        }
    }
    None
}
