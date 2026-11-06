//! One atomic claim batch (FIX 9403): every element resolved first, then one actor content
//! write that admits, stages, applies and finishes each element in batch order. A refused
//! element rolls every element back; each element is still gated on its own.

use std::cell::Cell;

use super::attempt::{claim_candidate, claim_occurred};
use super::resolve::{ClaimWrite, in_place_replay, refuse_typed_claim_family};
use super::*;

/// One element of an atomic claim batch: its input, the check its door runs in
/// the batch's writer, and the birth its door stamps.
pub(in crate::memory) struct BatchClaim<'a> {
    pub(in crate::memory) input: &'a ClaimInput,
    pub(in crate::memory) in_writer: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
    pub(in crate::memory) birth: Option<&'a crate::provenance::birth::RowBirth>,
}

/// Why an atomic batch landed nothing: the element whose refusal rolled it
/// back (`None` when the batch's own write failed) and that refusal.
pub(in crate::memory) struct BatchRefusal {
    pub(in crate::memory) index: Option<usize>,
    pub(in crate::memory) error: MemoryError,
}

/// One failed attempt of the batch's write: the element it failed at, its
/// error, and the identity a hard-delete marker refused there, if any.
struct BatchFailure {
    index: Option<usize>,
    error: Error,
    hard_deleted: Option<EntityId>,
}

impl Memory<'_> {
    /// Commits `claims` as one atomic batch through `row` (FIX 9403; ARCH-0040,
    /// ARCH-0045: `vault.commit` batches individually gated puts in one atomic
    /// transaction). Each element replaces the standing head on its key, as
    /// [`Self::commit_one`] with auto-supersede does, and takes its own Gate
    /// decision: an Auto request the Gate pends lands Proposed, as on the
    /// single door. Every element lands, or none does: a refused element
    /// answers its typed refusal and every other element answers that it was
    /// rolled back with it, all under the one refusal receipt.
    ///
    /// # Errors
    /// A landed batch whose receipts cannot be read back.
    pub(in crate::memory) fn commit_claim_batch(
        &self,
        row: &'static str,
        claims: &[BatchClaim<'_>],
    ) -> MemoryResult<Vec<CommitOutcome>> {
        match self.write_claim_batch(row, claims) {
            Ok(landed) => landed
                .into_iter()
                .map(|(id, prior, approval)| {
                    self.commit_receipt(id, prior, approval)
                        .map(CommitOutcome::Landed)
                })
                .collect(),
            Err(refusal) => Ok(self.refused_batch_outcomes(row, claims.len(), refusal)),
        }
    }

    /// The outcomes of a batch refused as `refusal` says: the refusing
    /// element's typed refusal, and for every other element a refusal that
    /// names it, each under the one receipt written for the refusing element.
    pub(in crate::memory) fn refused_batch_outcomes(
        &self,
        row: &'static str,
        len: usize,
        refusal: BatchRefusal,
    ) -> Vec<CommitOutcome> {
        let BatchRefusal { index, error } = refusal;
        let cause_field =
            index.map_or_else(|| "/claims".to_owned(), |index| format!("/claims/{index}"));
        let cause = RecordRefusal::from_error(&error, cause_field.clone());
        let receipt_ref = cause.receipt(self, row);
        let rolled_back = MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("rolled back with its batch: {cause_field} was refused"),
            &[
                "The batch lands whole or not at all.",
                "Fix or drop the refused element, then commit the batch again.",
            ],
        );
        (0..len)
            .map(|element| {
                let field = format!("/claims/{element}");
                let refusal = match index {
                    Some(index) if index == element => cause.clone(),
                    Some(_) => RecordRefusal::from_error(&rolled_back, field),
                    None => RecordRefusal::from_error(&error, field),
                };
                CommitOutcome::Refused {
                    refusal,
                    receipt_ref: receipt_ref.clone(),
                }
            })
            .collect()
    }

    /// The batch's resolution and its one write; answers each landed
    /// element's identity, the head it replaces and its requested approval.
    fn write_claim_batch(
        &self,
        row: &'static str,
        claims: &[BatchClaim<'_>],
    ) -> Result<Vec<(EntityId, Option<EntityId>, ClaimApprovalStatus)>, BatchRefusal> {
        let refused_at = |index: usize| {
            move |error: MemoryError| BatchRefusal {
                index: Some(index),
                error,
            }
        };
        let mut writes = Vec::with_capacity(claims.len());
        for (index, claim) in claims.iter().enumerate() {
            refuse_typed_claim_family(claim.input).map_err(refused_at(index))?;
            writes.push(
                self.resolve_claim_write(claim.input, true, claim.in_writer, claim.birth)
                    .map_err(refused_at(index))?,
            );
        }
        // An element on an earlier element's key replaces the head standing
        // there once the earlier one is written, read in the batch's writer;
        // the advisory head both resolved before the write would leave two
        // standing heads. A changed-belief replay keeps the row it replaces.
        let rekeyed: Vec<bool> = (0..writes.len())
            .map(|index| {
                let write = &writes[index];
                (in_place_replay(write) || write.input.id.is_none())
                    && write.signed_replay_origin.is_none()
                    && writes[..index]
                        .iter()
                        .any(|earlier| earlier.key.same_key(&write.key))
            })
            .collect();
        let mut approvals: Vec<ClaimApprovalStatus> = writes
            .iter()
            .map(|write| requested_approval(write.source, write.input.scope.as_ref()))
            .collect();
        loop {
            let failure = match self.attempt_claim_batch(row, &mut writes, &rekeyed, &approvals) {
                Ok(()) => break,
                Err(failure) => failure,
            };
            if let Some(refused) = failure.hard_deleted {
                return Err(BatchRefusal {
                    index: failure.index,
                    error: hard_deleted_refusal(&refused),
                });
            }
            // Only a Gate verdict that PENDS an element's Auto request
            // resubmits the batch with that element Proposed; each retry
            // turns one more element Proposed, so the loop ends.
            if let Some(index) = failure.index
                && approvals[index] == ClaimApprovalStatus::Auto
                && gate_rejection_pends(&failure.error)
            {
                approvals[index] = ClaimApprovalStatus::Proposed;
                continue;
            }
            let error = failure
                .index
                .and_then(|index| writes[index].publication_refusal.take())
                .unwrap_or_else(|| failure.error.into());
            return Err(BatchRefusal {
                index: failure.index,
                error,
            });
        }
        Ok(writes
            .iter()
            .zip(approvals)
            .map(|(write, approval)| (write.id, write.prior, approval))
            .collect())
    }

    /// One attempt of the batch's write: one actor content transaction that
    /// writes every element in order, each under its approval, and commits
    /// only when every element was admitted.
    fn attempt_claim_batch(
        &self,
        row: &'static str,
        writes: &mut [ClaimWrite<'_>],
        rekeyed: &[bool],
        approvals: &[ClaimApprovalStatus],
    ) -> Result<(), BatchFailure> {
        let mut envelopes = Vec::with_capacity(writes.len());
        for (index, write) in writes.iter().enumerate() {
            envelopes.push(
                self.claim_envelope(write.source, row, approvals[index])
                    .map_err(|error| BatchFailure {
                        index: Some(index),
                        error,
                        hard_deleted: None,
                    })?,
            );
        }
        let Some(actor) = envelopes.first().map(crate::WriteEnvelope::actor) else {
            return Ok(());
        };
        let failed_at = Cell::new(None::<usize>);
        let hard_deleted = Cell::new(None::<EntityId>);
        self.vault
            .try_with_actor_content_write_txn(actor, |content| {
                for (index, (write, envelope)) in writes.iter_mut().zip(envelopes).enumerate() {
                    failed_at.set(Some(index));
                    if envelope.actor() != actor {
                        return Err(Error::InvariantViolation(
                            "a claim batch writes under one actor",
                        ));
                    }
                    if rekeyed[index] {
                        write.prior = self.find_prior_claim_in_txn(
                            content.read(),
                            &write.key,
                            &write.id,
                            write.beside_stated,
                        )?;
                    }
                    let candidate = claim_candidate(write);
                    let occurred = claim_occurred(write);
                    if let Some(refused) = self
                        .write_claim_in_txn(content, write, candidate, envelope, occurred, false)?
                    {
                        hard_deleted.set(Some(refused));
                        return Err(Error::InvalidClaimBody(
                            "a claim batch element is refused by a hard-delete marker",
                        ));
                    }
                }
                failed_at.set(None);
                Ok(())
            })
            .map_err(|error| BatchFailure {
                index: failed_at.get(),
                error,
                hard_deleted: hard_deleted.get(),
            })
    }
}
