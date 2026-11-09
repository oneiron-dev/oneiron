//! OF-541: the budget hold (ARCH-0079 #budget). A suspension is a hold, not
//! a kill.
//!
//! When a run reaches its spend cap, the worker holding a live attempt parks
//! it here: the lease-fenced door moves the leased (or landing) row to
//! `Paused` with the checkpoint it resumes from, under the reserved
//! [`BUDGET_HOLD_ACTOR`]. Nothing is cancelled and no TASK terminal report is
//! written; the ordinary `Resume` intervention puts the same logical work
//! back in the queue, and its next lease reads the recorded resume point.

use super::AttemptQueue;
use super::AttemptResumePoint;
use super::lifecycle::{EngineHold, HoldWrite};
use super::types::{AttemptId, AttemptPause, AttemptRecord, AttemptState};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;

pub use crate::store::attempt_hold::BUDGET_HOLD_ACTOR;

/// Refusal for an intervention that names [`BUDGET_HOLD_ACTOR`].
pub(in crate::attempt_queue) const ERR_BUDGET_HOLD_ACTOR_RESERVED: &str =
    "intervention actor is reserved for the budget hold";

/// The note of a budget hold's pause event.
const BUDGET_HOLD_NOTE: &str = "budget hold; resumes from its recorded checkpoint";

/// The lease holder's request to hold its attempt at the spend cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldAttemptForBudget {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Where the same work picks up on resume.
    pub resume_point: AttemptResumePoint,
    pub now: u64,
}

impl AttemptRecord {
    /// Whether this row is paused by a budget hold: paused, and held under
    /// the engine's hold. A row a person paused afterwards reads `false`.
    /// Read from the row's held pause, never from its pruned event history
    /// (FIX 9579).
    #[must_use]
    pub fn budget_hold(&self) -> bool {
        self.state == AttemptState::Paused && self.active_pause == Some(AttemptPause::Budget)
    }
}

impl AttemptQueue<'_> {
    /// Holds a running attempt at its spend cap: lease-fenced like
    /// complete/fail, it parks the row `Paused` with its checkpoint and
    /// releases the lease. Idempotent for a row already held.
    ///
    /// # Errors
    ///
    /// A missing row, a row that is not running, a stale lease or an invalid
    /// resume point; storage errors.
    pub fn hold_for_budget(&self, input: HoldAttemptForBudget) -> Result<AttemptRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record = self.hold_for_budget_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(record)
    }

    /// [`Self::hold_for_budget`] with the vault's Owners told in the same
    /// write (FIX 6148, FIX 7210): the hold, then each Owner's Ask notice
    /// ([`crate::Vault::notify_attempt_budget_hold`]) in a savepoint of that
    /// writer, so no crash commits the hold without its notice. A notice that
    /// is not recorded rolls back its savepoint alone and is logged; the hold
    /// still commits. A store-only handle holds without a notice.
    ///
    /// # Errors
    ///
    /// As [`Self::hold_for_budget`].
    pub fn hold_for_budget_with_owner_notice(
        &self,
        input: HoldAttemptForBudget,
    ) -> Result<AttemptRecord> {
        let Some(vault) = self.vault else {
            return self.hold_for_budget(input);
        };
        let now = input.now;
        vault.with_write_txn_grouped(|wtxn| {
            let record = self.hold_for_budget_in_txn(wtxn, input)?;
            let noticed = (|| -> Result<()> {
                let mut savepoint = self.store.env.nested_write_txn(wtxn)?;
                vault.notify_attempt_budget_hold_in_txn(&mut savepoint, record.id, now)?;
                savepoint.commit()?;
                // FIX 3084: the committed notice joins this write's post-commit
                // notification wake.
                crate::batch::queue_notification_change(vault, wtxn);
                Ok(())
            })();
            if let Err(error) = noticed {
                tracing::warn!(
                    kind = ?error.kind(),
                    attempt = %bytes_to_hex_lower(record.id.as_bytes()),
                    "a budget hold's owner notice was not recorded; the hold commits"
                );
            }
            Ok(record)
        })
    }

    /// Transaction-composable [`Self::hold_for_budget`]: the engine holds'
    /// one write ([`Self::hold_in_txn`]) under the budget hold. A hold is not
    /// a landing: a landing row leaves Landing for Paused, keeps its
    /// checkpoint, and owes no outstanding stop request an answer.
    pub(crate) fn hold_for_budget_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: HoldAttemptForBudget,
    ) -> Result<AttemptRecord> {
        self.hold_in_txn(
            wtxn,
            HoldWrite {
                id: input.id,
                lease_owner: input.lease_owner,
                attempt_count: input.attempt_count,
                resume_point: input.resume_point,
                hold: EngineHold::Budget,
                actor: BUDGET_HOLD_ACTOR,
                note: BUDGET_HOLD_NOTE.to_owned(),
                now: input.now,
            },
        )
    }
}
