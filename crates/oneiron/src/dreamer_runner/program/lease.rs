//! The program kind's own lease and reservation (DOOR-141): the runner's one
//! admission chain over program attempts alone, never another lane's work.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DREAMER_TURN_PROGRAM_ATTEMPT_KIND, DreamerAdmissionOutcome,
    DreamerParkCause, DreamerRunnerStore,
};
use crate::error::Result;

use super::super::store::PARKED;
use super::{PR1_PARK_REASON, PROGRAM_PARK_OWNER};

impl DreamerRunnerStore<'_> {
    /// Atomically leases the next queued turn-woken program with its budget
    /// reservation and landing slice, through the runner's one admission
    /// chain. Never drains the generic `dreamer` queue or any other kind.
    ///
    /// A program parked is never leased. A program DOOR-141 PR1 parked for
    /// want of its runtime, and a program the runtime holds whose condition
    /// is now met (`resume`), are resumed first, as the same try, by the
    /// runtime that asks: this chain runs only where a program runtime is
    /// bound.
    ///
    /// # Errors
    ///
    /// Storage errors; the queue's own admission errors.
    pub fn admit_next_turn_program(
        &self,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(DREAMER_TURN_PROGRAM_ATTEMPT_KIND, input)
    }

    /// The next ready program attempt that holds no park, for the admission
    /// chain to claim by id. The parks DOOR-141 PR1 left for want of the
    /// runtime (its exact owner and reason) are resumed first, in this
    /// writer, each as the same try under its own kind's lease, and so is
    /// each hold of the program runtime's own whose condition is met
    /// (DOOR-141 PR3b, FIX 5711); every other park (a trapped step's signal
    /// park, a pass's Checkpoint park) holds.
    pub(in crate::dreamer_runner) fn ready_unparked_program_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        now: u64,
    ) -> Result<Option<AttemptId>> {
        let held: Vec<(AttemptId, DreamerParkCause, String)> = PARKED
            .scan(&self.vault.store, &*txn)?
            .into_iter()
            .filter(|(_, park)| park.park_owner == PROGRAM_PARK_OWNER)
            .map(|(attempt, park)| (attempt, park.cause, park.reason))
            .collect();
        for (attempt, cause, reason) in held {
            if reason == PR1_PARK_REASON {
                self.resume_parked_in_txn(txn, attempt, PROGRAM_PARK_OWNER, now)?;
            } else if cause == DreamerParkCause::Other {
                self.resume_ready_program_hold_in_txn(txn, attempt, &reason, now);
            }
        }
        let parked = PARKED.scan_keys(&self.vault.store, &*txn, &[])?;
        self.attempts.ready_kind_matching_in_txn(
            txn,
            DREAMER_TURN_PROGRAM_ATTEMPT_KIND,
            now,
            |row| Ok(!parked.contains(&row.id)),
        )
    }
}
