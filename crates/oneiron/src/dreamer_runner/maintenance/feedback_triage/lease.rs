//! The feedback sweep's lease on a long GitHub walk (FIX 7628). The walk
//! renews its `coach.feedback_sweep` lease before each request, and again in
//! the writer that commits a page or a source's error, with the recording
//! clock and fenced on the exact lease the walk was admitted under: its
//! owner and its lease generation (the row's `attempt_count`). Once another
//! walker holds the sweep, this one writes nothing more and stops; its
//! source's continuation stays owed to the current walker. No lease grows
//! longer and no timer is added: a renewal only moves the held lease's
//! expiry clock, through the attempt queue's own renewal.
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::entity_id::bytes_to_hex_lower;
use crate::feedback::COACH_FEEDBACK_SWEEP_FACET;
use crate::{Result, Vault};

impl Vault {
    /// Renews the leased `coach.feedback_sweep` attempt's lease in a write of
    /// its own, with the recording clock: what a GitHub walk calls before
    /// each request. Answers `false`, writing nothing, once the try is no
    /// longer held by the lease it was admitted under; the walk then stops.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt; storage errors.
    pub fn renew_feedback_triage_sweep(&self, attempt: &DreamerAdmittedAttempt) -> Result<bool> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_SWEEP_FACET)?;
        self.with_write_txn_grouped(|txn| self.renew_feedback_sweep_in_txn(txn, attempt))
    }

    /// The sweep's lease fence in the caller's writer: `true` while the try
    /// is still leased, or landing, to the owner and generation `attempt`
    /// was admitted under, its lease renewed here when it is leased (a
    /// landing keeps its one window, and is never renewed); `false`, writing
    /// nothing, once it was claimed again, settled or released. A check made
    /// before this writer would still race a re-lease.
    pub(crate) fn renew_feedback_sweep_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: &DreamerAdmittedAttempt,
    ) -> Result<bool> {
        let admitted = &attempt.status.attempt;
        let Some(owner) = admitted.lease_owner.as_deref() else {
            return Ok(false);
        };
        let queue = AttemptQueue::new(self);
        let held = queue.get_in_txn(txn, admitted.id)?.filter(|live| {
            live.state.is_running()
                && live.lease_owner.as_deref() == Some(owner)
                && live.attempt_count == admitted.attempt_count
        });
        let Some(live) = held else {
            tracing::info!(
                attempt_id = %bytes_to_hex_lower(admitted.id.as_bytes()),
                "a feedback sweep stopped: another walker holds its lease"
            );
            return Ok(false);
        };
        if live.state == AttemptState::Leased {
            queue.renew_lease_in_txn(
                txn,
                admitted.id,
                owner,
                admitted.attempt_count,
                self.now_recorded_at(),
            )?;
        }
        Ok(true)
    }
}
