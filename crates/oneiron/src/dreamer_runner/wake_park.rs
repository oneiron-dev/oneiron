//! The runner side of the normal Checkpoint resume (DOOR-144): the parks it
//! reads, and the projection the deadline lane arms on.

use crate::attempt_queue::AttemptRecord;
use crate::error::Result;

use super::store::{DreamerRunnerStore, PARKED};
use super::types::DreamerParkedAttemptRecord;

/// A Checkpoint or Retry park the next local wake pass resumes once it is
/// due: the pass that cut it ended, and its queue row still holds that
/// pass's lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerCheckpointDue {
    /// The parked try's queue row.
    pub attempt: AttemptRecord,
    /// When it parked, in Unix seconds.
    pub parked_at: u64,
    /// When the next local pass may resume it, in Unix seconds: when it
    /// parked, or its retry delay later for a Retry park.
    pub due_at: u64,
}

impl DreamerParkedAttemptRecord {
    /// When a later wake pass may resume this park as the same try, in
    /// store-clock seconds; `None` for a park no later pass resumes.
    #[must_use]
    pub fn later_pass_due_at(&self) -> Option<u64> {
        self.cause
            .later_pass_resume_delay()
            .map(|delay| self.parked_at.saturating_add(delay))
    }
}

impl DreamerRunnerStore<'_> {
    /// Every Checkpoint park the next wake pass's root would resume, read on
    /// one snapshot. A projection only: placement and the MACRO home are the
    /// caller's to check, the resume rechecks all of it in its own write, and
    /// a due park grants no ownership.
    pub fn checkpoint_resumes_due(&self) -> Result<Vec<DreamerCheckpointDue>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut due = Vec::new();
        for park in self.checkpoint_parks_in_txn(&rtxn)? {
            let Some(attempt) = self.attempts.get_in_txn(&rtxn, park.attempt_id)? else {
                continue;
            };
            if crate::dreamer_wake::checkpoint_resumable_in_txn(self.vault, &rtxn, &park, &attempt)?
                .is_some()
            {
                due.push(DreamerCheckpointDue {
                    attempt,
                    parked_at: park.parked_at,
                    due_at: park.later_pass_due_at().unwrap_or(park.parked_at),
                });
            }
        }
        Ok(due)
    }

    /// Every Checkpoint and Retry park at `txn`'s revision.
    fn checkpoint_parks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<DreamerParkedAttemptRecord>> {
        let mut parks = Vec::new();
        for row in PARKED.iter_from(&self.vault.store, txn, &[])? {
            let (_, park) = row?;
            if park.cause.later_pass_resume_delay().is_some() {
                parks.push(park);
            }
        }
        Ok(parks)
    }
}
