//! The replay put after a put fence (FIX FENCE-ERASED-FORM-THROUGH-WALL).
//!
//! A put fence erases, in its writer, the record of a run whose actor is
//! gone or whose replies an erase took
//! ([`super::super::response_erase::fence_replay_in_txn`],
//! [`super::super::overlay_erase::fence_overlay_replay_in_txn`]), and the
//! record then lands. The side-row wall must read what the record keeps new:
//! a call's kept outcome, an output's preview, its names and its live run
//! binding. It must not read what the erase wrote. An erased request, an
//! erased outcome and an erased preview hold the erase's own words (`state`,
//! `response_erased`, `failed`, the erased preview text), and the wall's
//! known-value sweep reads map keys and any span of a text: a value base
//! custody holds equal to one of those words masked the erased form, so the
//! row was refused, or landed no longer reading erased.
//!
//! The wall reads a projection of the record with each erased part taken
//! out. The parts go back into the copy the wall admitted, which must then
//! read as a record, and that copy lands past the wall
//! ([`Erased::code_run_fenced`]). An erased part the fence's erase did not
//! write is taken out only when the stored row holds it at the same call,
//! as that row's own; every erased preview is the one erased text.

use std::borrow::Cow;

use oneiron_contracts::msgpack;
use rmpv::Value;

use super::super::super::codec::{
    decode_code_run_replay_unvalidated, replay_record_value, validate_code_run_replay_record,
};
use super::super::replay_bodies::ErasedReplies;
use super::{REPLAY_RECORDS, get_lenient};
use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_ERASED, CodeRunReplayRecord, RESPONSE_ERASED, SelfDispatchOutcome,
};
use crate::error::{Error, Result};
use crate::side_table::{Erased, SideTableDbs};

/// A replay record a put fence passed: as its writer gave it, or with its
/// run's replies erased and the calls that erase wrote. [`put_fenced`]
/// lands it.
pub(crate) struct FencedReplay<'r> {
    record: Cow<'r, CodeRunReplayRecord>,
    erased: Option<ErasedReplies>,
}

impl<'r> FencedReplay<'r> {
    /// `record` as its writer gave it: its replies are kept.
    pub(in crate::code_run::storage) fn kept(record: Cow<'r, CodeRunReplayRecord>) -> Self {
        Self {
            record,
            erased: None,
        }
    }

    /// `record` with its replies erased, `written` the calls that erase
    /// wrote.
    pub(in crate::code_run::storage) fn erased(
        record: Cow<'r, CodeRunReplayRecord>,
        written: ErasedReplies,
    ) -> Self {
        Self {
            record,
            erased: Some(written),
        }
    }

    /// The record as it lands.
    pub(crate) fn record(&self) -> &CodeRunReplayRecord {
        &self.record
    }
}

/// A fenced record the side-row wall admitted, but for its erase's own
/// parts, which are as the erase wrote them: what
/// [`Erased::code_run_fenced`] lands past the wall. Only [`put_fenced`]
/// makes one.
pub(crate) struct AdmittedFencedReplay(CodeRunReplayRecord);

impl AdmittedFencedReplay {
    /// The record that lands.
    pub(crate) fn into_record(self) -> CodeRunReplayRecord {
        self.0
    }
}

/// Persists `fenced` as its run's replay row: a kept record through the
/// side-row wall, as [`super::put`] does; an erased one with the wall
/// reading every part but the erase's own, which land as the erase wrote
/// them.
///
/// # Errors
///
/// Storage errors, and the wall's refusal of a part it reads.
pub(crate) fn put_fenced(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    fenced: &FencedReplay<'_>,
) -> Result<()> {
    let record = fenced.record();
    let Some(written) = &fenced.erased else {
        return super::put(dbs, wtxn, &record.run_id, record);
    };
    let read: &heed::RoTxn<'_> = wtxn;
    let stored = get_lenient(dbs, read, &record.run_id)?;
    let parts = ErasedParts::of(record, written, stored.as_ref());
    let projection = msgpack::encode(&replay_record_value(&parts.taken_out_of(record)));
    let admitted =
        REPLAY_RECORDS.admit_projection(dbs, wtxn, &record.run_id, &projection, |masked| {
            parts.put_back(masked).is_ok()
        })?;
    let landed = match admitted {
        Some(masked) => parts.put_back(&masked)?,
        None => record.clone(),
    };
    #[cfg(oneiron_test_support)]
    super::note_written(REPLAY_RECORDS.encode_value(&landed)?.len());
    REPLAY_RECORDS.put_erased(
        dbs,
        wtxn,
        &record.run_id,
        Erased::code_run_fenced(AdmittedFencedReplay(landed)),
    )
}

/// The parts of a fenced record the side-row wall does not read, by
/// position, as the record holds them.
struct ErasedParts {
    calls: usize,
    outputs: usize,
    /// A call's erased request and its erased rewrite.
    requests: Vec<(usize, Value, Option<Value>)>,
    outcomes: Vec<(usize, Value)>,
    previews: Vec<usize>,
}

impl ErasedParts {
    /// The parts of `record` the wall does not read: each request and
    /// outcome `written` names; each erased request and erased outcome
    /// `stored`, the run's stored row, holds at the same call; and each
    /// erased preview.
    fn of(
        record: &CodeRunReplayRecord,
        written: &ErasedReplies,
        stored: Option<&CodeRunReplayRecord>,
    ) -> Self {
        let mut parts = Self {
            calls: record.bridge_calls.len(),
            outputs: record.outputs.len(),
            requests: Vec::new(),
            outcomes: Vec::new(),
            previews: Vec::new(),
        };
        for (index, call) in record.bridge_calls.iter().enumerate() {
            let held = stored
                .and_then(|stored| stored.bridge_calls.get(index))
                .filter(|held| held.seq == call.seq);
            let held_request = held.is_some_and(|held| {
                held.request == call.request && held.rewritten_request == call.rewritten_request
            });
            if call.request_erased() && (written.requests.contains(&index) || held_request) {
                parts
                    .requests
                    .push((index, call.request.clone(), call.rewritten_request.clone()));
            }
            let held_outcome = held.is_some_and(|held| held.outcome == call.outcome);
            if written.outcomes.contains(&index) || (held_outcome && erased_outcome(&call.outcome))
            {
                parts.outcomes.push((index, call.outcome.clone()));
            }
        }
        for (index, output) in record.outputs.iter().enumerate() {
            if output.preview.text == CODE_RUN_OUTPUT_PREVIEW_ERASED {
                parts.previews.push(index);
            }
        }
        parts
    }

    /// `record` with each part taken out, the projection the wall reads: a
    /// request and its rewrite, and an outcome, as nil; a preview as empty
    /// text. It is no valid record.
    fn taken_out_of(&self, record: &CodeRunReplayRecord) -> CodeRunReplayRecord {
        let mut projection = record.clone();
        for (index, _, _) in &self.requests {
            if let Some(call) = projection.bridge_calls.get_mut(*index) {
                call.request = Value::Nil;
                call.rewritten_request = None;
            }
        }
        for (index, _) in &self.outcomes {
            if let Some(call) = projection.bridge_calls.get_mut(*index) {
                call.outcome = Value::Nil;
            }
        }
        for index in &self.previews {
            if let Some(output) = projection.outputs.get_mut(*index) {
                output.preview.text.clear();
            }
        }
        projection
    }

    /// The record the wall admitted, read from `masked`, the bytes of its
    /// masked projection: each part back in its place, which the projection
    /// left empty, and the whole then a valid record.
    fn put_back(&self, masked: &[u8]) -> Result<CodeRunReplayRecord> {
        let mut record = decode_code_run_replay_unvalidated(masked)?;
        if record.bridge_calls.len() != self.calls || record.outputs.len() != self.outputs {
            return Err(part_moved());
        }
        for (index, request, rewritten) in &self.requests {
            let call = record.bridge_calls.get_mut(*index).ok_or_else(part_moved)?;
            if call.request != Value::Nil || call.rewritten_request.is_some() {
                return Err(part_moved());
            }
            call.request = request.clone();
            call.rewritten_request = rewritten.clone();
        }
        for (index, outcome) in &self.outcomes {
            let call = record.bridge_calls.get_mut(*index).ok_or_else(part_moved)?;
            if call.outcome != Value::Nil {
                return Err(part_moved());
            }
            call.outcome = outcome.clone();
        }
        for index in &self.previews {
            let output = record.outputs.get_mut(*index).ok_or_else(part_moved)?;
            if !output.preview.text.is_empty() {
                return Err(part_moved());
            }
            CODE_RUN_OUTPUT_PREVIEW_ERASED.clone_into(&mut output.preview.text);
        }
        validate_code_run_replay_record(&record)?;
        Ok(record)
    }
}

/// Whether `outcome` is the failure an erase left in a call's place.
fn erased_outcome(outcome: &Value) -> bool {
    matches!(
        decode_self_dispatch_outcome(outcome),
        Ok(SelfDispatchOutcome::Failed(failed)) if failed.error == RESPONSE_ERASED
    )
}

fn part_moved() -> Error {
    Error::InvariantViolation("the wall's copy of a fenced record moved an erased part")
}
