//! Cancel-receipt shape table, landing validators, and receipt/event append mutators.

use crate::attempt_queue::cancel::{
    AttemptResumePoint, CancelStanding, ForceCancelGrounds, LandingTrigger,
};
use crate::attempt_queue::types::{
    AttemptEvent, AttemptInterventionKind, AttemptRecord, AttemptState,
    MAX_ATTEMPT_EVENTS_PER_RECORD,
};
use crate::error::{Error, Result};

use super::field_validators::{validate_intervention_actor, validate_optional_intervention_note};
pub(in crate::attempt_queue) use crate::store::attempt_record_codec::cancel_validators::validate_cancel_state;

/// One append-only cancel receipt row, never drained and never refused on a
/// count.
#[derive(Debug, Default)]
pub(in crate::attempt_queue) struct CancelReceiptDraft {
    pub(in crate::attempt_queue) standing: Option<CancelStanding>,
    pub(in crate::attempt_queue) trigger: Option<LandingTrigger>,
    pub(in crate::attempt_queue) grounds: Option<ForceCancelGrounds>,
    pub(in crate::attempt_queue) status: Option<String>,
    pub(in crate::attempt_queue) reason: Option<String>,
    pub(in crate::attempt_queue) resume_point: Option<AttemptResumePoint>,
    pub(in crate::attempt_queue) reserve_units: u64,
    pub(in crate::attempt_queue) request_sequence: Option<u64>,
}

pub(in crate::attempt_queue) fn append_attempt_event(
    record: &mut AttemptRecord,
    kind: AttemptInterventionKind,
    actor: String,
    note: Option<String>,
    now: u64,
) -> Result<()> {
    // Checked as the decoder checks it, so no appended event poisons the row
    // it is appended to (FIX 9580).
    validate_intervention_actor(&actor)?;
    validate_optional_intervention_note(note.as_deref())?;
    let sequence = match record.events.last() {
        Some(event) => event
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("attempt event sequence"))?,
        None => 1,
    };
    record.events.push(AttemptEvent {
        sequence,
        at: now,
        actor,
        kind,
        note,
    });
    if record.events.len() > MAX_ATTEMPT_EVENTS_PER_RECORD {
        let excess = record.events.len() - MAX_ATTEMPT_EVENTS_PER_RECORD;
        // A paused row keeps the event of the pause it stands under, however
        // many later events follow it: who placed the pause decides who
        // resumes it, and that event is the only record of the pauser
        // (review 6974 P1). It stays first, so the sequences still rise.
        let standing_pause = (record.state == AttemptState::Paused)
            .then(|| {
                record
                    .events
                    .iter()
                    .rposition(|event| event.kind == AttemptInterventionKind::Pause)
            })
            .flatten()
            .filter(|at| *at < excess);
        match standing_pause {
            Some(at) => {
                let pause = record.events.remove(at);
                record.events.drain(0..excess);
                record.events.insert(0, pause);
            }
            None => {
                record.events.drain(0..excess);
            }
        }
    }
    Ok(())
}
