//! The seal task's runner (ARCH-0064 section 7: the seal "runs as a task,
//! never inline in a request"). It claims each queued `esign.seal` attempt
//! and seals it through the host's sealer. A seal that fails leaves its
//! attempt failed with the reason, and the backstop sweep queues the
//! document again: a retryable op, never a nominally complete document.

use super::seal::{EsignSealAttemptResult, EsignSealError, RESULT, live_attempt};
use super::{ESIGN_SEAL_ATTEMPT_KIND, EsignSealer, EsignSealerError, SealProfile};
use crate::attempt_queue::{AttemptQueue, ClaimOutcome, FailOutcome};
use crate::store::attempt_inputs::ClaimAttempt;
use crate::store::attempt_inputs::FailAttempt;
use crate::{EntityId, Result, Vault};

/// The most bytes of a failure a failed attempt keeps.
const REASON_MAX_BYTES: usize = 512;

/// What one claimed seal came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsignSealRun {
    /// Sealed: the document is COMPLETED or REJECTED, its sealed PDFs landed.
    Sealed { document: Option<EntityId> },
    /// Not sealed this time; the attempt failed with `reason` and the
    /// backstop queues the document again.
    Failed {
        document: Option<EntityId>,
        reason: String,
    },
}

impl Vault {
    /// Seals up to `max` queued documents, one claimed attempt at a time,
    /// as `lease_owner`. The sealer runs outside the writer lock; call from
    /// a blocking thread. Each seal prints `qr_page_url` with its own QR
    /// capability as the fragment ([`Self::seal_esign_attempt`]).
    ///
    /// # Errors
    /// The attempt queue could not be read or written.
    pub fn run_esign_seals(
        &self,
        sealer: &dyn EsignSealer,
        profile: SealProfile,
        qr_page_url: &str,
        lease_owner: &str,
        max: usize,
    ) -> Result<Vec<EsignSealRun>> {
        let queue = AttemptQueue::new(self);
        let mut runs = Vec::new();
        while runs.len() < max {
            let claim = ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now: self.now_recorded_at(),
            };
            let attempt = match queue.claim_kind(ESIGN_SEAL_ATTEMPT_KIND, claim)? {
                ClaimOutcome::Claimed(attempt) => attempt,
                _ => break,
            };
            let document = <[u8; 16]>::try_from(attempt.payload.as_slice())
                .ok()
                .and_then(|bytes| EntityId::from_bytes(bytes).ok());
            match self.seal_esign_attempt(&attempt, sealer, profile, qr_page_url) {
                Ok(_) => runs.push(EsignSealRun::Sealed { document }),
                Err(error) => {
                    let verify_reasons = match &error {
                        EsignSealError::Sealer(EsignSealerError::VerifyFailed { verdict }) => {
                            Some(verdict.reasons.clone())
                        }
                        EsignSealError::Verification { verify_reasons } => {
                            Some(verify_reasons.clone())
                        }
                        _ => None,
                    };
                    let mut reason = error.to_string();
                    if reason.len() > REASON_MAX_BYTES {
                        let mut end = REASON_MAX_BYTES;
                        while !reason.is_char_boundary(end) {
                            end -= 1;
                        }
                        reason.truncate(end);
                    }
                    let now = self.now_recorded_at();
                    let outcome = self.with_write_txn_grouped(|txn| {
                        live_attempt(self, txn, &attempt)?;
                        if RESULT.contains(&self.store, txn, attempt.id.as_bytes())? {
                            return Err(super::model::invalid("seal attempt result already kept"));
                        }
                        if let Some(verify_reasons) = verify_reasons {
                            RESULT.put(
                                &self.store,
                                txn,
                                attempt.id.as_bytes(),
                                &EsignSealAttemptResult::VerificationFailed { verify_reasons },
                            )?;
                        }
                        queue.fail_in_txn(
                            txn,
                            FailAttempt {
                                id: attempt.id,
                                lease_owner: lease_owner.to_owned(),
                                attempt_count: attempt.attempt_count,
                                reason: reason.clone(),
                                now,
                            },
                        )
                    })?;
                    if let FailOutcome::Failed(record) = outcome {
                        self.store.notify_task_updates(
                            record
                                .task_ref
                                .as_deref()
                                .and_then(|task| EntityId::from_hex(task).ok()),
                        );
                    }
                    runs.push(EsignSealRun::Failed { document, reason });
                }
            }
        }
        Ok(runs)
    }
}
