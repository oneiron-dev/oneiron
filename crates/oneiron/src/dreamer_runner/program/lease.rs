//! The program kind's own lease and reservation (DOOR-141): the runner's one
//! admission chain over program attempts alone, never another lane's work.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DREAMER_TURN_PROGRAM_ATTEMPT_KIND, DreamerAdmissionOutcome,
    DreamerRunnerStore,
};
use crate::error::Result;

use super::super::store::PARKED;

impl DreamerRunnerStore<'_> {
    /// Atomically leases the next queued turn-woken program with its budget
    /// reservation and landing slice, through the runner's one admission
    /// chain. Never drains the generic `dreamer` queue or any other kind.
    ///
    /// A program parked for want of its runtime is never leased: the runtime
    /// resumes it first. Every program DOOR-141 PR1 admits is parked so, so
    /// until the runtime lands this admits none.
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
    /// chain to claim by id.
    pub(in crate::dreamer_runner) fn ready_unparked_program_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        now: u64,
    ) -> Result<Option<AttemptId>> {
        let parked = PARKED.scan_keys(&self.vault.store, &*txn, &[])?;
        self.attempts.ready_kind_matching_in_txn(
            txn,
            DREAMER_TURN_PROGRAM_ATTEMPT_KIND,
            now,
            |row| Ok(!parked.contains(&row.id)),
        )
    }
}
