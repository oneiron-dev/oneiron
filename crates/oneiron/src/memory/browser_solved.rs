//! The browser's solved-run capture door (CUA E8a; DESIGN-2 "The Coach",
//! row E8): a source caller's checked solved run, kept as its own
//! `browser.solved_run` claim under the host origin its call came in on,
//! with its group ref, its group's generation and its source authority's
//! reference, in one write. No raw transaction leaves this door.
//!
//! The source authority is kept beside the evidence, never in it: the exact
//! credential instrument and door the call was admitted on, and the signed
//! binding it presented with its BLAKE3 (CUA E8b), kept as a queued turn
//! action keeps its slip. A later admission job verifies the binding again
//! against current authority at use, and drops it once it ends.
//!
//! An off-record call captures nothing here: the base vault keeps no
//! evidence of it.

use super::{HostWriteOrigin, Memory, MemoryResult};
use crate::authority::InvocationSlipBinding;
use crate::browser_library::{
    SOLVED_RUN_PREDICATE, SavedBrowserCaller, SolvedCaptureGap, SolvedCaptureReceipt,
    SolvedRunCapture, SolvedRunEvidence, SolvedRunScope, index_capture_in_txn,
};
use crate::{ClaimApprovalStatus, ClaimCandidate, ClaimSubject, Error, TimeRange};

impl Memory<'_> {
    /// This caller's solved-run scope (CUA E8a): its actor and class, and
    /// the digest of the credential reference its call was admitted on,
    /// when a host verifies that credential again.
    ///
    /// # Errors
    ///
    /// A credential reference that does not encode.
    pub fn solved_run_scope(&self) -> MemoryResult<SolvedRunScope> {
        let credential = self.verb_ask_credential();
        let reference = credential.as_ref().map(|credential| credential.reference());
        Ok(SolvedRunScope::new(
            self.actor,
            self.actor_class,
            reference,
        )?)
    }

    /// Keeps `capture`, a solved run this caller's call reached, as its
    /// evidence (CUA E8a): one `browser.solved_run` claim under `origin`,
    /// the host origin the call came in on, and in the same write its group
    /// ref, its group's generation and its source authority's reference.
    /// The same capture again lands nothing new and moves no generation.
    ///
    /// # Errors
    ///
    /// The caller's binding or write grant failing in the write, an origin
    /// that is not this caller's, or storage errors.
    pub fn capture_browser_solved_run(
        &self,
        origin: HostWriteOrigin,
        capture: SolvedRunCapture,
    ) -> MemoryResult<SolvedCaptureReceipt> {
        if self.off_record_session.is_some() {
            return Ok(SolvedCaptureReceipt::Unavailable(
                SolvedCaptureGap::OffRecord,
            ));
        }
        let credential = self.verb_ask_credential();
        let reference = credential
            .as_ref()
            .map(|credential| credential.reference().clone());
        let witness = reference.as_ref().and(self.invocation_slip()).cloned();
        let witness_digest = witness.as_ref().map(witness_digest).transpose()?;
        let scope = SolvedRunScope::new(self.actor, self.actor_class, reference.as_ref())?;
        let evidence = SolvedRunEvidence::new(scope.clone(), capture)?;
        let group = evidence.group().digest();
        let caller = SavedBrowserCaller {
            scope,
            group,
            run_id: evidence.run_id,
            call_id: evidence.call_id,
            credential: reference,
            witness_digest,
            witness,
        };
        let value = serde_json::to_string(&evidence)
            .map_err(|_| Error::InvalidClaimBody("solved run evidence"))?;
        let bound = self.clone().with_host_origin(origin);
        let source = bound.claim_source("generated")?;
        let envelope =
            bound.claim_envelope(source, SOLVED_RUN_PREDICATE, ClaimApprovalStatus::Auto)?;
        let now = self.vault.store.clock.now_recorded_at();
        bound.with_verified_actor_write_txn(|txn| {
            if self.vault.get_raw_in(txn, &evidence.id)?.is_some() {
                return Ok(SolvedCaptureReceipt::Captured {
                    id: evidence.id,
                    group,
                    fresh: false,
                });
            }
            let candidate = ClaimCandidate::new(
                SOLVED_RUN_PREDICATE,
                ClaimSubject::Entity(self.actor),
                rmpv::Value::from(value),
                1.0,
            );
            self.vault
                .batch_in()
                .claim_candidate(
                    &evidence.id,
                    candidate,
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(txn)?;
            index_capture_in_txn(self.vault, txn, &evidence, &caller)?;
            Ok(SolvedCaptureReceipt::Captured {
                id: evidence.id,
                group,
                fresh: true,
            })
        })
    }
}

/// BLAKE3 of the signed binding a call was admitted on: what the source
/// authority keeps of it.
fn witness_digest(binding: &InvocationSlipBinding) -> crate::Result<[u8; 32]> {
    let bytes =
        serde_json::to_vec(binding).map_err(|_| Error::InvalidClaimBody("invocation slip"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
