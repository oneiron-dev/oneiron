//! OF-393: the fan-out launch hold. A cut that waits on its launch approval
//! parks its planning attempt here; it is never a budget hold.
//!
//! When a gated wave apply holds its cut for the owner's ruling, the worker
//! holding the planning attempt parks it here, in the transaction that
//! records the held launch: the lease-fenced door moves the leased row to
//! `Paused` with the checkpoint naming that launch, under the reserved
//! [`FANOUT_HOLD_ACTOR`]. Nothing is cancelled or completed. The approval
//! resumes the same row through the ordinary `Resume` intervention, re-leases
//! it and completes it as the cut lands, all in one transaction; a denial
//! leaves it parked and visible.

use super::AttemptQueue;
use super::AttemptResumePoint;
use super::encoding::decode_record;
use super::telemetry::invalid_transition;
use super::types::{AttemptId, AttemptInterventionKind, AttemptRecord, AttemptState};
use super::validate::{
    append_attempt_event, validate_lease_owner, validate_resume_point, validate_transition_lease,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The intervention actor of a fan-out launch hold. Reserved: only the
/// lease-fenced hold door writes it, so a person's pause never reads as a
/// hold and an approval never releases a person's pause.
pub const FANOUT_HOLD_ACTOR: &str = "engine:fanout_hold";

/// Refusal for an intervention that names [`FANOUT_HOLD_ACTOR`].
pub(in crate::attempt_queue) const ERR_FANOUT_HOLD_ACTOR_RESERVED: &str =
    "intervention actor is reserved for the fan-out launch hold";

/// The prefix of a fan-out hold's event note; the launch ref follows.
const HOLD_NOTE_PREFIX: &str = "fanout launch ";

/// The lease holder's request to hold its attempt for a launch approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldAttemptForFanout {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// The held launch the owner rules on.
    pub launch_ref: EntityId,
    /// Where the same work picks up on resume.
    pub resume_point: AttemptResumePoint,
    pub now: u64,
}

impl AttemptRecord {
    /// Whether this row is paused by the fan-out hold of `launch_ref`:
    /// paused, and its newest pause is the engine's hold for that launch. A
    /// row a person paused or resumed afterwards reads `false`.
    #[must_use]
    pub fn fanout_hold_for(&self, launch_ref: EntityId) -> bool {
        if self.state != AttemptState::Paused {
            return false;
        }
        let note = format!("{HOLD_NOTE_PREFIX}{}", launch_ref.to_hex());
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
                event.kind == AttemptInterventionKind::Pause
                    && event.actor == FANOUT_HOLD_ACTOR
                    && event
                        .note
                        .as_deref()
                        .is_some_and(|text| text.starts_with(&note))
            })
    }
}

impl AttemptQueue<'_> {
    /// Holds a leased attempt for a launch approval: lease-fenced like
    /// complete/fail, it parks the row `Paused` with its checkpoint and
    /// releases the lease. Idempotent for a row already held for the same
    /// launch.
    ///
    /// # Errors
    ///
    /// A missing row, a row that is not leased, a stale lease or an invalid
    /// resume point; storage errors.
    pub(crate) fn hold_for_fanout_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: HoldAttemptForFanout,
    ) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        validate_resume_point(&input.resume_point)?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("fanout_hold", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Paused if record.fanout_hold_for(input.launch_ref) => return Ok(record),
            AttemptState::Leased => {}
            state => return Err(invalid_transition("fanout_hold", state.as_str())),
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "fanout_hold",
        )?;
        let note = format!(
            "{HOLD_NOTE_PREFIX}{}; checkpoint {}",
            input.launch_ref.to_hex(),
            input.resume_point.marker
        );
        // A held row is not claimable; the approval's resume restores it.
        self.delete_ready_entry_for_record(wtxn, &record)?;
        // A hold owes no outstanding stop request an answer.
        record.cancel_state.landing = None;
        record.cancel_state.pressure.pending = 0;
        record.cancel_state.resume_point = Some(input.resume_point);
        append_attempt_event(
            &mut record,
            AttemptInterventionKind::Pause,
            FANOUT_HOLD_ACTOR.to_owned(),
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
