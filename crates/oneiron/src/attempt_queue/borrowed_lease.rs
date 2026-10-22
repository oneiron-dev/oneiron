//! A parent attempt's lease as a child borrows it (FIX 7507): the attempt,
//! its lease owner and its lease generation, judged live by the queue's own
//! lease check (`AttemptQueue::holds_lease_in_txn`). Borrowing never
//! renews the lease, enqueues nothing and carries no payload: a child holds
//! only the identity it may stand on while the lease holds.

use serde::{Deserialize, Serialize};

use super::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::Result;

/// The lease one leased attempt held when its host lent it: ids and a
/// generation, no payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BorrowedAttemptLease {
    attempt: AttemptId,
    owner: String,
    generation: u32,
}

impl BorrowedAttemptLease {
    /// The lease `leased`, the record its host holds, stands on: `None` for
    /// a record that is not leased or names no owner.
    #[must_use]
    pub fn of(leased: &AttemptRecord) -> Option<Self> {
        if leased.state != AttemptState::Leased {
            return None;
        }
        Some(Self {
            attempt: leased.id,
            owner: leased.lease_owner.clone()?,
            generation: leased.attempt_count,
        })
    }

    /// The attempt whose lease this is.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Whether the lease still holds in `txn`: the attempt is leased, to
    /// the same owner, at the same generation, by the queue's one lease
    /// check. A lease that lapsed, was cleaned up or moved never holds again.
    pub(crate) fn holds_in(&self, queue: &AttemptQueue<'_>, txn: &heed::RoTxn<'_>) -> Result<bool> {
        queue.holds_lease_in_txn(txn, self.attempt, &self.owner, self.generation)
    }
}
