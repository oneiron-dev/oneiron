//! A claim commit inside its write: admission, support staging, the candidate's gated apply,
//! and the birth, supersession, conflicts and support that finish it.

use super::resolve::ClaimWrite;
use super::*;

/// The support rows a claim commit stages before its candidate applies and
/// finishes after.
pub(super) struct ClaimSupport {
    pub(super) stated_conflicts: Vec<EntityId>,
    pub(super) publication_write: bool,
    pub(super) commitment_write: bool,
}

impl Memory<'_> {
    /// The caller's in-writer check, the publication owner's authority, the
    /// keyed-claim and authorship guards and the prior head's grant; `true`
    /// means a hard-delete marker refused the id.
    pub(super) fn admit_claim_write_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
        envelope: &crate::WriteEnvelope,
    ) -> Result<bool, Error> {
        let ClaimWrite {
            input,
            id,
            prior,
            in_writer,
            ref publication_refusal,
            ..
        } = *write;
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
                    existing.predicate == super::super::key_value::PREDICATE
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
        super::super::authorship::guard_existing_claim_in_txn(
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
            super::super::authorship::require_claim_self_grant_in_txn(
                self.vault,
                content.read(),
                envelope.actor(),
                old_id,
                &old,
                "memory.claim.supersede",
            )?;
        }
        Ok(false)
    }

    pub(super) fn stage_claim_support_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
    ) -> Result<ClaimSupport, Error> {
        let ClaimWrite {
            input,
            id,
            ref key,
            ref value,
            beside_stated,
            prior,
            ..
        } = *write;
        // OF-023: every standing stated peer on this key, read in
        // this transaction rather than taken from the advisory
        // lookup. Each one whose answer differs opens a conflict.
        let stated_conflicts = if beside_stated {
            self.stated_preference_conflicts_in_txn(content.read(), key, id, value)?
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
                super::super::booking_publication::stage_publication_write(self.vault, txn, id)
            })?;
            if let Some(old_id) = prior {
                content.update_claim(old_id, |txn| {
                    super::super::booking_publication::stage_publication_write(
                        self.vault, txn, old_id,
                    )
                })?;
            }
        }
        Ok(ClaimSupport {
            stated_conflicts,
            publication_write,
            commitment_write,
        })
    }

    /// Applies the candidate through the Gate; returns the envelope the
    /// closure binding and conflicts are written under.
    pub(super) fn apply_claim_candidate_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
        candidate: ClaimCandidate,
        mut envelope: crate::WriteEnvelope,
        occurred: TimeRange,
    ) -> Result<crate::WriteEnvelope, Error> {
        let ClaimWrite {
            id,
            prior,
            learned_at,
            ..
        } = *write;
        // A replacement is a create-versus-closure proposal even when its
        // source and actor would qualify for Auto. The later grant is
        // the only door allowed to close the prior head.
        if prior.is_some() {
            envelope = envelope.with_approval(ClaimApprovalStatus::Proposed);
        }
        self.sign_machine_claim_in_txn(content.read(), id, &candidate, &mut envelope)?;
        let closure_envelope = envelope.clone();
        let owner_authored = self.owner_authored_write_in_txn(content.read())?;
        // A claim that stands at commit is lexically live in the same batch,
        // as a promoted Dreamer claim is (FIX 11914): a light recall finds it
        // at once, with no idle pass or embedder. A held (proposed) claim
        // stages no text. Its text is the claim's as the embedder projects a
        // claim (`embed::claim_text`): a string value as it is, any other
        // value rendered whole.
        let surfaces = matches!(
            envelope.approval(),
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        );
        let text = write
            .value
            .as_str()
            .map_or_else(|| write.value.to_string(), str::to_owned);
        let mut ops = vec![BatchOp::ClaimCandidate {
            id,
            candidate: Box::new(candidate),
            envelope,
            occurred,
            learned_at,
            internal_lexical_query_hint: false,
        }];
        if surfaces && !text.is_empty() {
            ops.push(BatchOp::Text {
                id,
                fields: vec![("val".to_owned(), text)],
            });
        }
        content.apply_claim_ops(
            ops,
            self.vault.text_index_trusted.load(Ordering::Acquire),
            ApplyOpsGateMode::new(true, true).with_owner_authored(owner_authored),
        )?;
        Ok(closure_envelope)
    }

    pub(super) fn finish_claim_write_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
        support: ClaimSupport,
        closure_envelope: &crate::WriteEnvelope,
    ) -> Result<(), Error> {
        let ClaimWrite {
            id,
            subject,
            prior,
            birth,
            learned_at,
            now,
            ..
        } = *write;
        let ClaimSupport {
            stated_conflicts,
            publication_write,
            commitment_write,
        } = support;
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
                    closure_envelope,
                    learned_at,
                )
            })?;
        }
        if !stated_conflicts.is_empty() {
            self.open_preference_conflicts_in_txn(
                content,
                id,
                &stated_conflicts,
                closure_envelope,
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
                super::super::booking_publication::finish_publication_write(
                    self.vault, txn, id,
                )
            })?;
            if let Some(old_id) = prior {
                content.update_claim(old_id, |txn| {
                    super::super::booking_publication::finish_publication_write(
                        self.vault, txn, old_id,
                    )
                })?;
            }
        }
        Ok(())
    }
}
