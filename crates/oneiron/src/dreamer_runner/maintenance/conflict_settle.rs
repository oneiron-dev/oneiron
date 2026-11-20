//! Conflict settlement runs on the maintenance lane with a host's lent runner.

use rmpv::Value;

use super::super::{
    DreamerAttemptPayload, DreamerParkCause, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::Result;
use crate::dreamer_wake::DreamerAttemptExecution;

/// The maintenance job type for settling parked conflicts.
pub const CONFLICT_SETTLE_FACET: &str = "dreamer.conflict_settle";

/// A conflict-settlement job waits for a host to lend its job runner.
#[must_use]
pub fn unlent() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Park {
        reason: "no host lends this pass the conflict settlement job".to_owned(),
        cause: DreamerParkCause::Retry,
    }
}

impl DreamerRunnerStore<'_> {
    /// Enqueues one conflict-settlement attempt in the caller's transaction.
    /// A pending attempt holds the fixed key until its chain ends, so another
    /// may be enqueued after completion or terminal parking.
    ///
    /// # Errors
    ///
    /// The queue's, authority-stamp, run-tree and storage errors.
    pub fn enqueue_conflict_settle_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<bool> {
        let outcome = self.enqueue_kind_in_txn(
            txn,
            super::MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: CONFLICT_SETTLE_FACET.into(),
                input: Value::Nil,
                parent_attempt: None,
            },
            Some(CONFLICT_SETTLE_FACET.into()),
            run_id,
            now,
        )?;
        Ok(matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_)))
    }
}
