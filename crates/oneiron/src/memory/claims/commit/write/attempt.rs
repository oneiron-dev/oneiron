//! One write attempt of a claim commit: its candidate and envelope, then one content write
//! that admits, stages, applies and finishes the claim.

use super::resolve::ClaimWrite;
use super::*;

impl Memory<'_> {
    /// Every commit is ONE engine transaction: gate decision, claim
    /// write, and (with a prior revision) the deferred closure binding
    /// commit or roll back together. No phantom receipts (a decision can never
    /// outlive a write that failed later validation) and no orphan
    /// revisions behind a rejected receipt. The fail-closed trade: a
    /// rolled-back write also drops its gate decision.
    pub(super) fn attempt_claim_write(
        &self,
        write: &ClaimWrite<'_>,
        approval: ClaimApprovalStatus,
        skip_exact_hook_replay: bool,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<Option<EntityId>, Error> {
        let candidate = claim_candidate(write);
        let envelope = self.claim_envelope(write.source, "vault.commit", approval)?;
        let occurred = claim_occurred(write);
        self.vault
            .try_with_actor_content_write_txn(envelope.actor(), lane, |content| {
                self.write_claim_in_txn(
                    content,
                    write,
                    candidate,
                    envelope,
                    occurred,
                    skip_exact_hook_replay,
                )
            })
    }

    /// The write transaction's body; returns the identity refused by a
    /// hard-delete marker, or `None` when admitted. An atomic batch runs it
    /// once per element in one transaction (FIX 9403).
    pub(super) fn write_claim_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
        candidate: ClaimCandidate,
        envelope: crate::WriteEnvelope,
        occurred: TimeRange,
        skip_exact_hook_replay: bool,
    ) -> Result<Option<EntityId>, Error> {
        if let Some(refused) = self.admit_claim_write_in_txn(content, write, &envelope)? {
            return Ok(Some(refused));
        }
        if skip_exact_hook_replay
            && self.exact_hook_proposal_replay_in_txn(content, write, &envelope)?
        {
            return Ok(None);
        }
        let support = self.stage_claim_support_in_txn(content, write)?;
        let closure_envelope =
            self.apply_claim_candidate_in_txn(content, write, candidate, envelope, occurred)?;
        self.finish_claim_write_in_txn(content, write, support, &closure_envelope)?;
        Ok(None)
    }

    fn exact_hook_proposal_replay_in_txn(
        &self,
        content: &crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
        envelope: &crate::WriteEnvelope,
    ) -> Result<bool, Error> {
        if !super::resolve::in_place_replay(write)
            || write.prior.is_some()
            || write.signed_replay_origin.is_some()
            || envelope.source() != crate::claim::ClaimSource::Generated
            || write.input.salience.is_some()
            || write.input.predicate == crate::commitment::PREDICATE_COMMITMENT_RECORD
            || write.input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE
        {
            return Ok(false);
        }
        let Some(existing) = self.vault.get_claim_in_txn(content.read(), &write.id)? else {
            return Ok(false);
        };
        // Belief equality alone omits evidence. The full stamp binds this
        // exact actor, class, binding and RunKey, including every extra stamp.
        if !super::resolve::claim_replay_content_matches(&existing, write)
            || existing.salience.is_some()
            || existing.session_tag.is_some()
            || existing.evidence.as_ref()
                != Some(&crate::write_envelope::write_envelope_evidence(
                    envelope, None,
                ))
        {
            return Ok(false);
        }
        // Recheck the existing record's live shared-vault authority even
        // though no candidate will reach the batch effect checks.
        content.require_claim(write.id)?;
        Ok(true)
    }
}

/// The candidate one write of `write` applies through the Gate.
pub(super) fn claim_candidate(write: &ClaimWrite<'_>) -> ClaimCandidate {
    let ClaimWrite {
        input,
        subject,
        ref value,
        world,
        ref relationship,
        ref scope_rmpv,
        ..
    } = *write;
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
    candidate = candidate.with_relationships(relationship.clone());
    if let Some(scope) = scope_rmpv.clone() {
        candidate = candidate.with_scope(scope);
    }
    candidate
}

/// The occurred range one write of `write` stamps.
pub(super) fn claim_occurred(write: &ClaimWrite<'_>) -> TimeRange {
    TimeRange {
        start: write.occurred_at,
        end: write.occurred_at,
    }
}
