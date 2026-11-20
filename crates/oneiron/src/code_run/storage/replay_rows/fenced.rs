//! The replay put after a put fence (FIX FENCE-ERASED-FORM-THROUGH-WALL).
//!
//! A put fence erases, in its writer, the record of a run whose actor is
//! gone or whose replies an erase took
//! ([`super::super::response_erase::fence_replay_in_txn`],
//! [`super::super::overlay_erase::fence_overlay_replay_in_txn`]), and takes
//! each fold answer a withdrawal took; the record then lands. An erased
//! request, an erased outcome and an erased preview hold the erase's own
//! words (`state`, `erased`, `response_erased`, `failed`, the call's effect,
//! the erased preview text), and the side-row wall's known-value sweep
//! reads map keys and any span of a text: a value base custody holds equal
//! to one of those words masked the erased form, so the row was refused, or
//! landed no longer reading erased.
//!
//! The wall reads a projection of the record with those fixed words taken
//! out of each part the record holds in its exact erased form, whoever
//! wrote it: an erased request keeps only its identity there, an erased
//! outcome only what its erase kept past the failure it wrote (the rows a
//! verb's answer was served from, the folds an answer named, a row
//! receipt), and an erased preview nothing. The words are the same for
//! every record, so taking them out hides no value a writer chose, and
//! every other byte is read: the kept identity, the kept entries, and each
//! part in any other shape, a failure naming the erase's cause beside a
//! code of its own among them. The words go back into the copy the wall
//! admitted, which must then read as a record with each part still in its
//! erased form, and that copy lands past the wall
//! ([`Erased::code_run_fenced`]). A record holding no part in an erased
//! form goes through the wall whole.

use oneiron_contracts::msgpack;
use rmpv::Value;

use super::super::super::codec::{
    decode_code_run_replay_unvalidated, replay_record_value, validate_code_run_replay_record,
};
use super::super::super::replay::erased_identity_field;
use super::REPLAY_RECORDS;
use crate::code_run::payload::self_dispatch_outcome_value;
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_ERASED, CodeRunBridgeCall, CodeRunReplayRecord, RESPONSE_ERASED,
    SelfDispatchOutcome, SelfFailedResult,
};
use crate::error::{Error, Result};
use crate::side_table::{Erased, SideTableDbs};

/// A fenced record the side-row wall admitted, but for the erase's fixed
/// words in each part it holds in its erased form, which are as the record
/// held them: what [`Erased::code_run_fenced`] lands past the wall. Only
/// [`put_fenced`] makes one.
pub(crate) struct AdmittedFencedReplay(CodeRunReplayRecord);

impl AdmittedFencedReplay {
    /// The record that lands.
    pub(crate) fn into_record(self) -> CodeRunReplayRecord {
        self.0
    }
}

/// Persists `record`, a record a put fence passed, as its run's replay row:
/// with the side-row wall reading all of it but the erase's fixed words in
/// each part it holds in its erased form, which land as they are. A record
/// holding no such part goes through the wall whole, as [`super::put`]
/// puts it.
///
/// # Errors
///
/// Storage errors, an erased failure that does not encode, and the wall's
/// refusal of a part it reads, or of a copy in which a part no longer
/// holds its erased form.
pub(crate) fn put_fenced(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
) -> Result<()> {
    let parts = ErasedParts::of(record)?;
    if parts.is_empty() {
        return super::put(dbs, wtxn, &record.run_id, record);
    }
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

/// The request of a call a part sits in: the guest's own, or a hook's
/// rewrite of it.
#[derive(Debug, Clone, Copy)]
enum RequestSlot {
    Guest,
    Rewrite,
}

impl RequestSlot {
    /// The request this slot of `call` holds.
    fn read(self, call: &CodeRunBridgeCall) -> Option<&Value> {
        match self {
            Self::Guest => Some(&call.request),
            Self::Rewrite => call.rewritten_request.as_ref(),
        }
    }

    /// Puts `request` in this slot of `call`.
    fn write(self, call: &mut CodeRunBridgeCall, request: Value) {
        match self {
            Self::Guest => call.request = request,
            Self::Rewrite => call.rewritten_request = Some(request),
        }
    }
}

/// A request a fenced record holds in the erased form (FIX 6534).
struct ErasedRequestPart {
    call: usize,
    slot: RequestSlot,
    /// The form as the record holds it.
    form: Value,
    /// The place of the identity it keeps among its fields
    /// ([`erased_identity_field`]): the one the wall reads.
    identity: usize,
}

impl ErasedRequestPart {
    /// The identity the form keeps.
    fn kept(&self) -> Option<&Value> {
        match &self.form {
            Value::Map(fields) => fields.get(self.identity).map(|(_, identity)| identity),
            _ => None,
        }
    }

    /// The form with `identity`, the wall's reading of the identity it
    /// keeps, in that identity's place; `None` when it no longer holds the
    /// erased form.
    fn with_identity(&self, identity: Value) -> Option<Value> {
        let mut form = self.form.clone();
        let Value::Map(fields) = &mut form else {
            return None;
        };
        fields.get_mut(self.identity)?.1 = identity;
        (erased_identity_field(&form) == Some(self.identity)).then_some(form)
    }
}

/// An outcome a fenced record holds in the erased form (FIX 5718, FIX
/// 18924): the call, and the entries of the failure its erase wrote, which
/// lead it.
struct ErasedOutcomePart {
    call: usize,
    failure: Vec<(Value, Value)>,
}

/// The erase's fixed words in a fenced record, by the place of each part
/// that holds them: what the projection the wall reads takes out, and what
/// goes back into the copy it admitted.
struct ErasedParts {
    calls: usize,
    outputs: usize,
    requests: Vec<ErasedRequestPart>,
    outcomes: Vec<ErasedOutcomePart>,
    previews: Vec<usize>,
}

impl ErasedParts {
    /// Each part of `record` in its erased form: a request or a rewrite
    /// holding the erased form, an outcome led by the erase's failure, and
    /// a preview reading the erased text.
    fn of(record: &CodeRunReplayRecord) -> Result<Self> {
        let mut parts = Self {
            calls: record.bridge_calls.len(),
            outputs: record.outputs.len(),
            requests: Vec::new(),
            outcomes: Vec::new(),
            previews: Vec::new(),
        };
        for (index, call) in record.bridge_calls.iter().enumerate() {
            for slot in [RequestSlot::Guest, RequestSlot::Rewrite] {
                let Some(form) = slot.read(call) else {
                    continue;
                };
                if let Some(identity) = erased_identity_field(form) {
                    parts.requests.push(ErasedRequestPart {
                        call: index,
                        slot,
                        form: form.clone(),
                        identity,
                    });
                }
            }
            if let Some(failure) = erased_failure(call)? {
                parts.outcomes.push(ErasedOutcomePart {
                    call: index,
                    failure,
                });
            }
        }
        for (index, output) in record.outputs.iter().enumerate() {
            if output.preview.text == CODE_RUN_OUTPUT_PREVIEW_ERASED {
                parts.previews.push(index);
            }
        }
        Ok(parts)
    }

    fn is_empty(&self) -> bool {
        self.requests.is_empty() && self.outcomes.is_empty() && self.previews.is_empty()
    }

    /// `record` with the fixed words taken out, the projection the wall
    /// reads: an erased request as the identity it keeps, an erased outcome
    /// as the entries past its failure, an erased preview as empty text. It
    /// is no valid record.
    fn taken_out_of(&self, record: &CodeRunReplayRecord) -> CodeRunReplayRecord {
        let mut projection = record.clone();
        for part in &self.requests {
            if let (Some(call), Some(identity)) =
                (projection.bridge_calls.get_mut(part.call), part.kept())
            {
                part.slot.write(call, identity.clone());
            }
        }
        for part in &self.outcomes {
            if let Some(call) = projection.bridge_calls.get_mut(part.call)
                && let Value::Map(entries) = &mut call.outcome
            {
                *entries = entries.split_off(part.failure.len());
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
    /// masked projection: the fixed words back in each part, each request
    /// part still holding the erased form, and the whole then a valid
    /// record.
    fn put_back(&self, masked: &[u8]) -> Result<CodeRunReplayRecord> {
        let mut record = decode_code_run_replay_unvalidated(masked)?;
        if record.bridge_calls.len() != self.calls || record.outputs.len() != self.outputs {
            return Err(part_moved());
        }
        for part in &self.requests {
            let call = record
                .bridge_calls
                .get_mut(part.call)
                .ok_or_else(part_moved)?;
            let identity = part.slot.read(call).cloned().ok_or_else(part_moved)?;
            let form = part.with_identity(identity).ok_or_else(part_moved)?;
            part.slot.write(call, form);
        }
        for part in &self.outcomes {
            let call = record
                .bridge_calls
                .get_mut(part.call)
                .ok_or_else(part_moved)?;
            let Value::Map(kept) = &mut call.outcome else {
                return Err(part_moved());
            };
            let mut outcome = part.failure.clone();
            outcome.append(kept);
            *kept = outcome;
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

/// The entries of the failure an erase writes in `call`'s place (FIX 5718,
/// FIX 18924) when `call`'s outcome leads with them exactly: `failed`,
/// the call's own effect, `response_erased`, no code and no disk floor.
/// They hold the erase's fixed words alone; what the erase kept past them
/// follows. `None` for any other outcome, a failure naming that cause
/// beside a code or a disk floor of its own among them.
fn erased_failure(call: &CodeRunBridgeCall) -> Result<Option<Vec<(Value, Value)>>> {
    let Value::Map(entries) = &call.outcome else {
        return Ok(None);
    };
    let failure = self_dispatch_outcome_value(&SelfDispatchOutcome::Failed(SelfFailedResult {
        effect: call.effect,
        error: RESPONSE_ERASED.to_owned(),
        code: None,
        disk_floor: None,
    }))?;
    Ok(match failure {
        Value::Map(failure) if entries.starts_with(&failure) => Some(failure),
        _ => None,
    })
}

fn part_moved() -> Error {
    Error::InvariantViolation("the wall's copy of a fenced record moved an erased part")
}
