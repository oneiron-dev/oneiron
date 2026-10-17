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
use super::encoding::decode_record;
use super::telemetry::invalid_transition;
use super::types::{AttemptId, AttemptInterventionKind, AttemptRecord, AttemptState};
use super::validate::{
    append_attempt_event, validate_lease_owner, validate_resume_point, validate_transition_lease,
};
use crate::error::Result;

/// The intervention actor of a budget hold. Reserved: no other intervention
/// may name it, so a person's pause never reads as a hold.
pub const BUDGET_HOLD_ACTOR: &str = "engine:budget_hold";

/// Refusal for an intervention that names [`BUDGET_HOLD_ACTOR`].
pub(in crate::attempt_queue) const ERR_BUDGET_HOLD_ACTOR_RESERVED: &str =
    "intervention actor is reserved for the budget hold";

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
    /// Whether this row is paused by a budget hold: paused, and its newest
    /// pause is the engine's hold. A row a person paused afterwards reads
    /// `false`.
    #[must_use]
    pub fn budget_hold(&self) -> bool {
        if self.state != AttemptState::Paused {
            return false;
        }
        self.events
            .iter()
            .rev()
            .find(|event| {
                matches!(
                    event.kind,
                    AttemptInterventionKind::Pause | AttemptInterventionKind::Resume
                )
            })
            .is_some_and(|event| {
                event.kind == AttemptInterventionKind::Pause && event.actor == BUDGET_HOLD_ACTOR
            })
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

    /// Transaction-composable [`Self::hold_for_budget`].
    pub(crate) fn hold_for_budget_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: HoldAttemptForBudget,
    ) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        validate_resume_point(&input.resume_point)?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("budget_hold", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Paused if record.budget_hold() => return Ok(record),
            AttemptState::Leased | AttemptState::Landing => {}
            state => return Err(invalid_transition("budget_hold", state.as_str())),
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "budget_hold",
        )?;
        let note = format!("checkpoint {}", input.resume_point.marker);
        // A held row is not claimable; resume restores its readiness.
        self.delete_ready_entry_for_record(wtxn, &record)?;
        // A hold is not a landing: the row leaves Landing for Paused, keeps
        // its checkpoint, and owes no outstanding stop request an answer.
        record.cancel_state.landing = None;
        record.cancel_state.pressure.pending = 0;
        record.cancel_state.resume_point = Some(input.resume_point);
        append_attempt_event(
            &mut record,
            AttemptInterventionKind::Pause,
            BUDGET_HOLD_ACTOR.to_owned(),
            Some(note),
            input.now,
        )?;
        record.state = AttemptState::Paused;
        record.lease_owner = None;
        record.updated_at = input.now;
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}
