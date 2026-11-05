//! The nightly drafter retrain, `coach.drafter_retrain` (FIX 12569,
//! I5-DRAFTER = A): Coach-owned work on the shared night scheduler. Its
//! prepare step pins the policy revision and the night's cutoff and records
//! how the night ended.
//!
//! No trainer recipe is wired on any host yet (corpus export, the trainer
//! and its recipe are later work), so a night with the policy on always
//! holds with `no_trainer_recipe`: nothing trains, no version is written and
//! every binding stays as it is. A night never reports a successful empty
//! retrain.

use super::{
    DrafterActor, DrafterEventKind, DrafterHoldReason, DrafterRetrainOutcome, DrafterSkipReason,
    EVENTS, policy_in_txn, record_event_in_txn,
};
use crate::Vault;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_runner::maintenance::coach::COACH_DRAFTER_RETRAIN_FACET;
use crate::error::Result;

impl Vault {
    /// `coach.drafter_retrain` as the Coach, under a leased Coach-stamped
    /// attempt: pins the policy revision and `now` as the cutoff and records
    /// the night's outcome as one event, in one write. Off: skipped, with
    /// its reason. On: held, `no_trainer_recipe`. The same attempt again
    /// returns the outcome it recorded and writes nothing.
    ///
    /// # Errors
    /// An attempt that is not this facet's under the Coach's stamp, and
    /// storage faults.
    pub fn run_coach_drafter_retrain(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<DrafterRetrainOutcome> {
        self.require_coach_attempt(attempt, COACH_DRAFTER_RETRAIN_FACET)?;
        let attempt_id = attempt.status.attempt.id;
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            // A row that does not decode is no record of this attempt.
            for row in EVENTS.iter_raw_from(store, &*txn, &[])? {
                let (_, value) = row?;
                if let Ok(event) = EVENTS.decode_value(&value)
                    && let DrafterEventKind::Retrain {
                        attempt: recorded,
                        outcome,
                        ..
                    } = event.kind
                    && recorded == attempt_id
                {
                    return Ok(outcome);
                }
            }
            let policy = policy_in_txn(store, txn)?;
            let outcome = if policy.enabled {
                DrafterRetrainOutcome::Held {
                    reason: DrafterHoldReason::NoTrainerRecipe,
                }
            } else {
                DrafterRetrainOutcome::Skipped {
                    reason: DrafterSkipReason::PolicyOff,
                }
            };
            record_event_in_txn(
                store,
                txn,
                DrafterActor::Coach,
                DrafterEventKind::Retrain {
                    attempt: attempt_id,
                    policy_revision: policy.revision,
                    cutoff: now,
                    outcome,
                },
                None,
                now,
            )?;
            Ok(outcome)
        })
    }
}
