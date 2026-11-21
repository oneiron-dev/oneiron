//! A person's pause of a run parked on a durable wait (FIX
//! PAUSE-BOUNDARY-PARKED-RUN): the park is the step boundary the pause
//! waits for, and the pause's writer or the park's takes it there.

use super::{RunSignalKind, RunSignalState};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::error::Result;
use crate::run_tree::RunTreeAdapter;

/// Whether `park` holds its run on a durable wait: the consent, peer or
/// person's answer its step parked on, which its trap's delivery wakes.
fn parks_on_durable_wait(park: &crate::dreamer_runner::DreamerParkedAttemptRecord) -> bool {
    park.wait.as_ref().is_some_and(|parked| {
        matches!(
            parked.wait,
            crate::dreamer_runner::DreamerParkWait::Consent { .. }
                | crate::dreamer_runner::DreamerParkWait::Peer { .. }
                | crate::dreamer_runner::DreamerParkWait::Human { .. }
        )
    })
}

impl RunTreeAdapter<'_> {
    /// Takes the pending Pause on `branch` at once when the branch is
    /// parked on a durable wait (FIX PAUSE-BOUNDARY-PARKED-RUN): its run
    /// committed its step's checkpoint before it parked, and runs no step
    /// until the wait's reply wakes it, so the park is the boundary the
    /// pause waits for. In the caller's writer the signal settles and the
    /// row moves to `Paused` under the park's own lease, as at the run's
    /// step boundary, and the park is cleared, so no wake releases a lease
    /// a later claim takes. The wait's trap stays bound: a reply that lands
    /// while the run is paused consumes it, wakes no park, and is kept for
    /// the resume, whose run re-enters the wait. Answers whether it paused;
    /// a branch that is not parked on a durable wait, or holds no pending
    /// Pause, is left as it is.
    ///
    /// # Errors
    ///
    /// The queue's refusal; storage errors.
    pub(crate) fn pause_parked_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        branch: AttemptId,
    ) -> Result<bool> {
        let Some(record) = self.queue.get_in_txn(txn, branch)? else {
            return Ok(false);
        };
        let (Some(run_id), Some(lease_owner)) = (&record.run_id, &record.lease_owner) else {
            return Ok(false);
        };
        let Some(key) = record.signals.iter().find_map(|signal| {
            (signal.state == RunSignalState::Pending
                && matches!(signal.kind, RunSignalKind::Pause { .. }))
            .then(|| signal.key.clone())
        }) else {
            return Ok(false);
        };
        let store = crate::dreamer_runner::DreamerRunnerStore::new(self.vault);
        let Some(park) = store
            .parked_attempt_in_txn(txn, branch)?
            .filter(parks_on_durable_wait)
        else {
            return Ok(false);
        };
        if record.state != AttemptState::Leased
            || !self.pause_at_boundary_in_txn(
                txn,
                branch,
                run_id,
                lease_owner,
                record.attempt_count,
                &key,
            )?
        {
            return Ok(false);
        }
        let now = self.vault.store.clock.now_recorded_at();
        store.resume_parked_in_txn(txn, branch, &park.park_owner, now)?;
        Ok(true)
    }
}
