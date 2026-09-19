//! JobQueue adapter over the existing lease state machine.
use super::*;
use crate::error::Result;
use crate::ports::{JobQueue, Transactions};
impl Transactions for AttemptQueue<'_> {
    type Read<'a> = heed::RoTxn<'a>;
    type Write<'a> = heed::RwTxn<'a>;
}
impl JobQueue for AttemptQueue<'_> {
    fn port_job_enqueue(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: EnqueueAttempt,
    ) -> Result<EnqueueOutcome> {
        self.port_job_enqueue_scoped(txn, input, crate::ports::JobScope::default())
    }
    fn port_job_enqueue_scoped(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mut input: EnqueueAttempt,
        scope: crate::ports::JobScope<'_>,
    ) -> Result<EnqueueOutcome> {
        input.now = crate::ports::recorded_at_in_txn(self.store, txn)?;
        let outcome =
            self.enqueue_scoped_storage_in_txn(txn, input, scope.task_ref, scope.dedupe_actor_ref)?;
        crate::ports::recorded_at_in_txn(self.store, txn)?;
        Ok(outcome)
    }
    fn port_job_claim(
        &self,
        txn: &mut heed::RwTxn<'_>,
        kind: Option<&str>,
        mut input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        input.now = crate::ports::recorded_at_in_txn(self.store, txn)?;
        self.claim_kind_storage_in_txn(txn, kind, input)
    }
    fn port_job_complete(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mut input: CompleteAttempt,
    ) -> Result<CompleteOutcome> {
        input.now = crate::ports::recorded_at_in_txn(self.store, txn)?;
        self.complete_storage_in_txn(txn, input)
    }
    fn port_job_fail(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mut input: FailAttempt,
    ) -> Result<FailOutcome> {
        input.now = crate::ports::recorded_at_in_txn(self.store, txn)?;
        self.fail_storage_in_txn(txn, input)
    }
}
