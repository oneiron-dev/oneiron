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
    ) -> Result<bool, Error> {
        let ClaimWrite {
            input,
            subject,
            ref value,
            world,
            relationship,
            ref scope_rmpv,
            source,
            occurred_at,
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
        if let Some(relationship) = relationship {
            candidate = candidate.with_relationship(relationship);
        }
        if let Some(scope) = scope_rmpv.clone() {
            candidate = candidate.with_scope(scope);
        }
        let envelope = self.claim_envelope(source, "vault.commit", approval)?;
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        self.vault
            .try_with_actor_content_write_txn(envelope.actor(), |content| {
                self.write_claim_in_txn(content, write, candidate, envelope, occurred)
            })
    }

    /// The write transaction's body; `true` means a hard-delete marker
    /// refused the id.
    fn write_claim_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        write: &ClaimWrite<'_>,
        candidate: ClaimCandidate,
        envelope: crate::WriteEnvelope,
        occurred: TimeRange,
    ) -> Result<bool, Error> {
        if self.admit_claim_write_in_txn(content, write, &envelope)? {
            return Ok(true);
        }
        let support = self.stage_claim_support_in_txn(content, write)?;
        let closure_envelope =
            self.apply_claim_candidate_in_txn(content, write, candidate, envelope, occurred)?;
        self.finish_claim_write_in_txn(content, write, support, &closure_envelope)?;
        Ok(false)
    }
}
