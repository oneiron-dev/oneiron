//! The step-boundary pause: a run's own lease holder moves its running row
//! to `Paused` once the step that took a pending Pause signal has
//! committed its checkpoint (`run_tree::signal`, the run's `Pause` signal).
//! It is a person's pause, not an engine hold: the signal's actor is named
//! on the pause event, so that person's resume releases it, as the vault
//! owner's does, and no hold's release does (FIX 9579). Resume queues the
//! same try, and its next lease runs on from the run's replay record, as a
//! reclaimed lease does (FIX 9932).

use super::AttemptQueue;
use super::encoding::decode_record;
use super::lifecycle::{RunEvent, RunLifecycle, RunRow, RunStep};
use super::telemetry::invalid_transition;
use super::types::{AttemptId, AttemptInterventionKind, AttemptRecord};
use super::validate::{
    append_attempt_event, validate_intervention_actor, validate_lease_owner,
    validate_optional_intervention_note, validate_transition_lease,
};
use crate::Result;

/// The refusal's action name.
const BOUNDARY_PAUSE: &str = "boundary_pause";

/// One step-boundary pause, as the run's lease holder asks for it.
pub(crate) struct PauseAtBoundary {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// The Pause signal's actor: the person who paused the branch.
    pub actor: String,
    /// The Pause signal's note, kept on the pause event.
    pub note: Option<String>,
    pub now: u64,
}

impl AttemptQueue<'_> {
    /// Moves the lease holder's running row to `Paused` under a person's
    /// pause and releases the lease, in the caller's writer, which settles
    /// the Pause signal it took in the same transaction.
    ///
    /// # Errors
    ///
    /// A missing row, a row that is not running, a stale lease, an empty
    /// actor or note; storage errors.
    pub(crate) fn pause_at_boundary_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: PauseAtBoundary,
    ) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        validate_intervention_actor(&input.actor)?;
        validate_optional_intervention_note(input.note.as_deref())?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition(BOUNDARY_PAUSE, "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        let (to, pause) = match RunLifecycle::step(RunRow::of(&record), RunEvent::PauseAtBoundary) {
            RunStep::Move { to, pause } => (to, pause),
            RunStep::Note { .. } | RunStep::Replay | RunStep::Keep | RunStep::Refuse => {
                return Err(invalid_transition(BOUNDARY_PAUSE, record.state.as_str()));
            }
        };
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            BOUNDARY_PAUSE,
        )?;
        // A paused row is not claimable; resume restores its readiness.
        self.delete_ready_entry_for_record(wtxn, &record)?;
        append_attempt_event(
            &mut record,
            AttemptInterventionKind::Pause,
            input.actor,
            input.note,
            input.now,
        )?;
        record.state = to;
        record.active_pause = pause;
        record.lease_owner = None;
        record.updated_at = input.now;
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}
