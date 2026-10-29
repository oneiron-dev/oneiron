//! The guarded claim commit: dedupe, supersede, Gate and publication in one write transaction.
//! `Memory::commit_one_guarded_with_birth` is its call surface.
//! `memory::claims::commit` defines `MemoryKey`; `memory::claims` defines the claim inputs.

use super::*;

impl Memory<'_> {
    pub(in crate::memory) fn commit_one_guarded_with_birth(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
        in_writer: &dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
        birth: Option<&crate::provenance::birth::RowBirth>,
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
        // Every generic claim-write door routes through here (`vault.commit`,
        // `vault.claims.upsert`, `vault.claims.seed` via `commit_all`), so one
        // guard covers all three.
        // Keyed facts bind subject, envelope actor/class, worldless scope,
        // exact address, and replay identity together. A generic upsert's
        // subject+scope match must not supersede another actor's keyed fact.
        if input.predicate == super::key_value::PREDICATE {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "keyed memory is written through vault.kv.put",
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
        let source = self.claim_source(&input.source)?;
        // The publisher sponsors the page's anonymous parses (FIX 5288):
        // stamped here, where the publish door already holds the publishing
        // principal as this write's actor.
        let value = if input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE {
            let mut claimed = input.value.clone();
            crate::booking::publication::stamp_publication_sponsor(&mut claimed, self.actor);
            json_to_rmpv(&claimed)
        } else {
            json_to_rmpv(&input.value)
        };
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
        let key = MemoryKey {
            subject,
            input,
            world,
            relationship,
        };
        // OF-023: a want derived from behaviour is minted beside the stated
        // one, never over it. Only the replacing doors (commit, upsert) take
        // this path; the seed and proposal doors replace nothing.
        let beside_stated =
            auto_supersede && crate::claim::is_observed_preference(Some(source), &input.predicate);

        // ADVISORY only (ONE-1936): this lookup runs outside the transaction,
        // so the prior it names may already be closed by the time the write
        // txn opens. The authority is `supersede_claim_in_txn`'s guard, inside
        // that txn — and a refusal there rolls the staged replacement back
        // with it.
        let prior = if auto_supersede {
            self.find_prior_claim(&key, &id, beside_stated)?
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
            if let Some(details) = input.confidence_details {
                candidate = candidate.with_confidence_details(details);
            }
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
            let mut envelope = self.claim_envelope(source, "vault.commit", approval)?;
            let occurred = TimeRange {
                start: occurred_at,
                end: occurred_at,
            };
            self.vault
                .try_with_actor_content_write_txn(envelope.actor(), |content| {
                    in_writer(content.read())?;
                    if input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE
                        && let Err(error) = self.verify_public_booking_writer_in_txn(content.read())
                    {
                        *publication_refusal.borrow_mut() = Some(error);
                        return Err(Error::InvalidClaimBody(
                            "booking publication owner authority refused",
                        ));
                    }
                    if let Some(raw) = self.vault.get_raw_in(content.read(), &id)?
                        && crate::batch::EntityMetadataHeader::parse(&raw).is_some_and(|header| {
                            header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                        })
                        && self
                            .vault
                            .get_claim_in_txn(content.read(), &id)?
                            .is_some_and(|existing| {
                                existing.predicate == super::key_value::PREDICATE
                            })
                    {
                        return Err(Error::InvalidClaimBody(
                            "keyed claim revisions cannot be overwritten through generic claims",
                        ));
                    }
                    if self
                        .vault
                        .local_hard_delete_marker_exists_in_txn(content.read(), &id)?
                    {
                        return Ok(true);
                    }
                    super::authorship::guard_existing_claim_in_txn(
                        self.vault,
                        content.read(),
                        envelope.actor(),
                        id,
                    )?;
                    if let Some(old_id) = prior {
                        let old = self
                            .vault
                            .get_claim_in_txn(content.read(), &old_id)?
                            .ok_or(Error::EntityNotFound)?;
                        content.require_claim(old_id)?;
                        super::authorship::require_claim_self_grant_in_txn(
                            self.vault,
                            content.read(),
                            envelope.actor(),
                            old_id,
                            &old,
                            "memory.claim.supersede",
                        )?;
                    }
                    // OF-023: every standing stated peer on this key, read in
                    // this transaction rather than taken from the advisory
                    // lookup. Each one whose answer differs opens a conflict.
                    let stated_conflicts = if beside_stated {
                        self.stated_preference_conflicts_in_txn(content.read(), &key, id, &value)?
                    } else {
                        Vec::new()
                    };
                    let publication_write =
                        input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE;
                    // OF-187: a promise recorded here owes its reminders, so a
                    // commitment series is indexed in this same transaction.
                    let commitment_write =
                        input.predicate == crate::commitment::PREDICATE_COMMITMENT_RECORD;
                    if commitment_write {
                        content.stage_claim_support(id, |_| Ok(()))?;
                    }
                    if publication_write {
                        content.stage_claim_support(id, |txn| {
                            super::booking_publication::stage_publication_write(self.vault, txn, id)
                        })?;
                        if let Some(old_id) = prior {
                            content.update_claim(old_id, |txn| {
                                super::booking_publication::stage_publication_write(
                                    self.vault, txn, old_id,
                                )
                            })?;
                        }
                    }
                    // A replacement is a create-versus-closure proposal even when its
                    // source and actor would qualify for Auto. The later grant is
                    // the only door allowed to close the prior head.
                    if prior.is_some() {
                        envelope = envelope.with_approval(ClaimApprovalStatus::Proposed);
                    }
                    self.sign_machine_claim_in_txn(content.read(), id, &candidate, &mut envelope)?;
                    let closure_envelope = envelope.clone();
                    let owner_authored = self.owner_authored_write_in_txn(content.read())?;
                    content.apply_claim_ops(
                        vec![BatchOp::ClaimCandidate {
                            id,
                            candidate: Box::new(candidate),
                            envelope,
                            occurred,
                            learned_at,
                            internal_lexical_query_hint: false,
                        }],
                        self.vault.text_index_trusted.load(Ordering::Acquire),
                        ApplyOpsGateMode::new(true, true).with_owner_authored(owner_authored),
                    )?;
                    if let Some(birth) = birth {
                        content.update_claim(id, |txn| {
                            crate::provenance::birth::stamp_birth_if_absent_in_txn(
                                &self.vault.store,
                                txn,
                                &id,
                                birth,
                            )
                        })?;
                    }
                    if let Some(old_id) = prior {
                        content.update_claim(old_id, |txn| {
                            self.vault.stage_claim_supersession_in_txn(
                                txn,
                                &id,
                                &old_id,
                                &closure_envelope,
                                learned_at,
                            )
                        })?;
                    }
                    if !stated_conflicts.is_empty() {
                        self.open_preference_conflicts_in_txn(
                            content,
                            id,
                            &stated_conflicts,
                            &closure_envelope,
                            learned_at,
                        )?;
                    }
                    if commitment_write {
                        content.finish_claim_support(id, |txn| {
                            self.vault
                                .index_landed_commitment_series_in_txn(txn, &id, now)
                        })?;
                    }
                    if publication_write {
                        content.finish_claim_support(id, |txn| {
                            crate::booking::publication::index_publication_in_txn(
                                self.vault, txn, subject, id,
                            )?;
                            super::booking_publication::finish_publication_write(
                                self.vault, txn, id,
                            )
                        })?;
                        if let Some(old_id) = prior {
                            content.update_claim(old_id, |txn| {
                                super::booking_publication::finish_publication_write(
                                    self.vault, txn, old_id,
                                )
                            })?;
                        }
                    }
                    Ok(false)
                })
        };
        // Only a Gate verdict that PENDS an Auto request is resubmitted as
        // Proposed: that write would park for review, so it lands parked. A
        // Gate deny (an unresolved record reference among them, FIX 1220) is
        // never resubmitted; no approval lane makes it land.
        let refused = match write(approval) {
            Ok(refused) => refused,
            Err(err) if approval == ClaimApprovalStatus::Auto && gate_rejection_pends(&err) => {
                approval = ClaimApprovalStatus::Proposed;
                write(approval)
                    .map_err(|err| publication_refusal.take().unwrap_or_else(|| err.into()))?
            }
            Err(err) => return Err(publication_refusal.take().unwrap_or_else(|| err.into())),
        };
        if refused {
            return Err(hard_deleted_refusal(&id));
        }

        let superseded = match prior {
            Some(old_id)
                if self
                    .vault
                    .get_claim(&old_id)?
                    .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Superseded) =>
            {
                Some((old_id, self.short_ref_of(&old_id)?))
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
        let short = self.short_ref_of(&id)?;
        let claim_ref = |id: &EntityId, short: Option<&str>| {
            crate::lens::RecordRef::from_id(crate::registry::ENTITY_TYPE_CLAIM, id, short)
        };
        Ok(CommitReceipt {
            claim: Some(claim_ref(&id, short.as_deref())),
            claim_short_id: short.unwrap_or_else(|| id.to_hex()),
            approval: final_approval,
            superseded: superseded
                .as_ref()
                .map(|(old_id, short)| claim_ref(old_id, short.as_deref())),
            superseded_short_id: superseded
                .map(|(old_id, short)| short.unwrap_or_else(|| old_id.to_hex())),
            receipt_ref,
        })
    }
}

/// Whether `err` is a Gate write rejection whose outcome is Pending, the one
/// rejection an Auto request may be resubmitted as Proposed after. A Deny,
/// and any error that is not a Gate rejection, is not.
fn gate_rejection_pends(err: &Error) -> bool {
    matches!(
        err,
        Error::Gate(crate::error::GateError::GateWriteRejected { outcome, .. })
            if crate::error::GateDenialOutcome::parse(outcome)
                == Some(crate::error::GateDenialOutcome::Pending)
    )
}
