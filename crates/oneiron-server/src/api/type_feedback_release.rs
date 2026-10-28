//! One program step's type feedback, released for one destination apart
//! from the answer it rides with (FIX 10390, FIX 10389): the projection the
//! MCP gateway and the HTTP facade share. The answer is released as it
//! stands without its feedback; each step's feedback is then judged alone
//! for the same destination, by the rows the answer was derived from and
//! every row the feedback names. A hold, or a check that cannot run,
//! withholds only that feedback's text, as its typed withheld projection;
//! the step's row stays whole.
//!
//! A door whose answer carries its run's step feedback as `program_steps`
//! (`self.off_record.execute`) gives each item released whole; its carrier
//! is known by the verb, never by its JSON's shape.

use oneiron::code_run::{FeedbackWithheldReason, ProgramStepFeedback, ProgramStepFeedbackRelease};
use oneiron::settings::ReadDestination;
use oneiron::{EntityId, Vault};
use serde_json::Value;

/// A session-bound run's entry: its answer carries the run's step feedback
/// as `program_steps`.
pub(crate) const OFF_RECORD_EXECUTE_VERB: &str = "self.off_record.execute";

/// How a carrier's feedback was read inside its answer, and is read alone
/// now: as JSON whose whole strings may be short refs, and by its bytes for
/// whole ids; or, for one its answer carries as an opaque string, by its
/// bytes alone.
#[derive(Clone, Copy)]
pub(crate) enum FeedbackScan {
    Named,
    Bytes,
}

/// `feedback` as `destination` is given it: whole on this device; off it,
/// whole when none of `rows` (the rows its answer was derived from) nor any
/// row it names is one a device-local world keeps from that destination
/// now, else withheld, with the hold's content-free reason. Rows that are
/// unknown, a short ref naming no row, or a check that cannot run withhold
/// it too. Never fails: only this feedback changes.
pub(crate) fn release_step_feedback(
    vault: &Vault,
    destination: &ReadDestination,
    rows: Option<&[EntityId]>,
    feedback: ProgramStepFeedback,
    scan: FeedbackScan,
) -> ProgramStepFeedbackRelease {
    match feedback_hold(vault, destination, rows, &feedback, scan) {
        None => ProgramStepFeedbackRelease::Released(feedback),
        Some(reason) => ProgramStepFeedbackRelease::withheld(&feedback, reason),
    }
}

/// Why `feedback` may not leave for `destination` now, or `None`.
fn feedback_hold(
    vault: &Vault,
    destination: &ReadDestination,
    rows: Option<&[EntityId]>,
    feedback: &ProgramStepFeedback,
    scan: FeedbackScan,
) -> Option<FeedbackWithheldReason> {
    if !destination.is_off_device() {
        return None;
    }
    let Some(rows) = rows else {
        return Some(FeedbackWithheldReason::ProducersUnknown);
    };
    let Ok(value) = serde_json::to_value(feedback) else {
        return Some(FeedbackWithheldReason::ReleaseCheckFailed);
    };
    let mut named = match scan {
        FeedbackScan::Named => match crate::device_local::short_refs_named(vault, &value) {
            Some(named) => named,
            None => return Some(FeedbackWithheldReason::Placement),
        },
        FeedbackScan::Bytes => Vec::new(),
    };
    named.extend_from_slice(rows);
    let Ok(bytes) = serde_json::to_vec(&value) else {
        return Some(FeedbackWithheldReason::ReleaseCheckFailed);
    };
    match crate::device_local::retained_hold(vault, destination, &named, &bytes) {
        Ok(hold) => hold.map(FeedbackWithheldReason::from),
        Err(_) => Some(FeedbackWithheldReason::ReleaseCheckFailed),
    }
}

/// The step feedback an answer of `verb` carries as `program_steps`: the
/// answer without it, and each item its door gave released whole, by its
/// slot. `None` for a verb whose answer carries none, or an answer with no
/// such item.
pub(crate) fn take_program_steps(
    verb: &str,
    value: &Value,
) -> Option<(Value, Vec<(usize, ProgramStepFeedback)>)> {
    if verb != OFF_RECORD_EXECUTE_VERB {
        return None;
    }
    let steps: Vec<ProgramStepFeedbackRelease> =
        serde_json::from_value(value.get("program_steps")?.clone()).ok()?;
    let feedback: Vec<(usize, ProgramStepFeedback)> = steps
        .into_iter()
        .enumerate()
        .filter_map(|(slot, step)| match step {
            ProgramStepFeedbackRelease::Released(feedback) => Some((slot, feedback)),
            ProgramStepFeedbackRelease::Withheld { .. } => None,
        })
        .collect();
    if feedback.is_empty() {
        return None;
    }
    let mut base = value.clone();
    base.as_object_mut()?.shift_remove("program_steps");
    Some((base, feedback))
}

/// Puts `released`, a step's feedback as one destination is given it, in
/// place of the item at `slot` of `value`'s `program_steps`.
pub(crate) fn put_program_step(value: &mut Value, slot: usize, released: Value) {
    if let Some(item) = value
        .get_mut("program_steps")
        .and_then(|steps| steps.get_mut(slot))
    {
        *item = released;
    }
}
