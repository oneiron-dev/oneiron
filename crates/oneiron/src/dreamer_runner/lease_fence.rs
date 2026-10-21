//! The lease a wake pass ran an admitted try under, and the park fenced on it
//! (FIX 6057): a held program resumed between the try's own hold and the
//! pass's park is queued again (or newly leased), and the pass's park must not
//! land on it then.

use crate::attempt_queue::AttemptRecord;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;

use super::store::DreamerRunnerStore;
use super::types::{DreamerParkedAttemptRecord, ParkDreamerAttempt};

/// The lease an admitted try ran under: its owner and its lease generation
/// (the queue row's `attempt_count`, which every claim advances).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DreamerTryLease<'a> {
    pub(crate) owner: &'a str,
    pub(crate) generation: u32,
}

impl DreamerTryLease<'_> {
    /// Whether a park under this lease still lands on `record`: the lease
    /// still holds the live row, or the row is terminal, which no resume or
    /// claim takes back (it parks as it always did). A row queued again,
    /// paused, or leased to another owner or generation is no longer this
    /// lease's to park.
    fn still_holds(self, record: &AttemptRecord) -> bool {
        record.state.is_terminal()
            || (record.state.is_running()
                && record.lease_owner.as_deref() == Some(self.owner)
                && record.attempt_count == self.generation)
    }
}

impl DreamerRunnerStore<'_> {
    /// [`Self::park_attempt_in_txn`], fenced on `lease` in the same writer:
    /// `Ok(None)`, nothing written, when the try was resumed or claimed again
    /// since that lease ran it. A read before this writer would still race.
    pub(crate) fn park_if_current_lease_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ParkDreamerAttempt,
        lease: DreamerTryLease<'_>,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        if let Some(record) = self.attempts.get_in_txn(wtxn, input.attempt_id)?
            && !lease.still_holds(&record)
        {
            tracing::info!(
                attempt_id = %bytes_to_hex_lower(input.attempt_id.as_bytes()),
                state = record.state.as_str(),
                "a stale pass's park was skipped; the try was resumed or claimed again"
            );
            return Ok(None);
        }
        self.park_attempt_in_txn(wtxn, input).map(Some)
    }

    /// [`Self::park_if_current_lease_in_txn`] in its own writer.
    pub(crate) fn park_if_current_lease(
        &self,
        input: ParkDreamerAttempt,
        lease: DreamerTryLease<'_>,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let record = self.park_if_current_lease_in_txn(&mut wtxn, input, lease)?;
        wtxn.commit()?;
        if record.is_some() {
            self.vault.store.notify_attempt_observers();
        }
        Ok(record)
    }
}
