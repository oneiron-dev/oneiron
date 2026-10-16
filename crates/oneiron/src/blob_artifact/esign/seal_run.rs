//! The seal task's runner (ARCH-0064 section 7: the seal "runs as a task,
//! never inline in a request"). It claims each queued `esign.seal` attempt
//! and seals it through the host's sealer. A seal that fails leaves its
//! attempt failed with the reason, and the backstop sweep queues the
//! document again: a retryable op, never a nominally complete document.

use super::{ESIGN_SEAL_ATTEMPT_KIND, EsignSealer, SealProfile};
use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome, FailAttempt};
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
    /// a blocking thread.
    ///
    /// # Errors
    /// The attempt queue could not be read or written.
    pub fn run_esign_seals(
        &self,
        sealer: &dyn EsignSealer,
        profile: SealProfile,
        canonical_url: &str,
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
            match self.seal_esign_attempt(&attempt, sealer, profile, canonical_url) {
                Ok(_) => runs.push(EsignSealRun::Sealed { document }),
                Err(error) => {
                    let mut reason = error.to_string();
                    if reason.len() > REASON_MAX_BYTES {
                        let mut end = REASON_MAX_BYTES;
                        while !reason.is_char_boundary(end) {
                            end -= 1;
                        }
                        reason.truncate(end);
                    }
                    queue.fail(FailAttempt {
                        id: attempt.id,
                        lease_owner: lease_owner.to_owned(),
                        attempt_count: attempt.attempt_count,
                        reason: reason.clone(),
                        now: self.now_recorded_at(),
                    })?;
                    runs.push(EsignSealRun::Failed { document, reason });
                }
            }
        }
        Ok(runs)
    }
}
