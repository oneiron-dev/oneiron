//! The replay put after a put fence (FIX FENCE-ERASED-FORM-THROUGH-WALL).
//!
//! A put fence erases, in its writer, the record of a run whose actor is
//! gone or whose replies an erase took
//! ([`super::super::response_erase::fence_replay_in_txn`],
//! [`super::super::overlay_erase::fence_overlay_replay_in_txn`]), takes
//! each fold answer a withdrawal took, and takes the ask of each spawn
//! whose target an erase took; the record then lands. An erased request, an
//! erased outcome and a spawn's erased ask hold the erase's own words
//! (`state`, `erased`, `response_erased`, `failed`, the call's effect,
//! `agent_spawn`, `target_erased`, `asker_erased`), and the side-row wall's
//! known-value sweep reads map keys and any span of a text: a value base
//! custody holds equal to one of those words masked the erased form, so the
//! row was refused, or landed no longer reading erased.
//!
//! The wall reads a projection of the record with those fixed words taken
//! out of each part the record holds in its exact erased form, whoever
//! wrote it: an erased request keeps only its identity there, a spawn's
//! erased ask is gone from its request, and an erased outcome keeps only
//! what its erase kept past the failure or the typed spawn answer it wrote
//! (the rows a verb's answer was served from, the folds an answer named, a
//! row receipt). The words are the same for every record, so taking them
//! out hides no value a writer chose, and every other byte is read: the
//! kept identity, the kept entries, and each part in any other shape, a
//! failure naming the erase's cause beside a code of its own among them.
//! The words go back into the copy the wall admitted, which must then read
//! as a record with each part still in its erased form, and that copy lands
//! past the wall ([`Erased::code_run_fenced`]). A record holding no part in
//! an erased form goes through the wall whole.
//!
//! An output preview is text the run wrote, and a live one can read as the
//! erased preview's text, so the wall reads every preview: one whose text
//! custody holds takes its handle, an erased one too.

use oneiron_contracts::msgpack;
use rmpv::Value;

use super::super::super::codec::{
    decode_code_run_replay_unvalidated, replay_record_value, validate_code_run_replay_record,
};
use super::super::super::replay::erased_identity_field;
use super::super::super::spawn_replay::erased_ask_field;
use super::REPLAY_RECORDS;
use crate::code_run::payload::self_dispatch_outcome_value;
use crate::code_run::{
    CodeRunBridgeCall, CodeRunReplayRecord, RESPONSE_ERASED, SelfAgentSpawnResult,
    SelfDispatchOutcome, SelfEffect, SelfFailedResult,
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
/// Storage errors, an erased outcome that does not encode, and the wall's
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

    /// The fields of the request this slot of `call` holds, when it is a
    /// map.
    fn fields_mut(self, call: &mut CodeRunBridgeCall) -> Option<&mut Vec<(Value, Value)>> {
        let request = match self {
            Self::Guest => Some(&mut call.request),
            Self::Rewrite => call.rewritten_request.as_mut(),
        };
        match request {
            Some(Value::Map(fields)) => Some(fields),
            _ => None,
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

/// The ask an erase took from a spawn whose target it took (FIX 9180, FIX
/// 9183), in a request that keeps its other fields: its typed marker, and
/// its place among them ([`erased_ask_field`]).
struct ErasedAskPart {
    call: usize,
    slot: RequestSlot,
    field: usize,
    entry: (Value, Value),
}

/// An outcome a fenced record holds in an erased form ([`erased_outcome`]):
/// the call, and the entries its erase wrote, which lead it.
struct ErasedOutcomePart {
    call: usize,
    erasure: Vec<(Value, Value)>,
}

/// The erase's fixed words in a fenced record, by the place of each part
/// that holds them: what the projection the wall reads takes out, and what
/// goes back into the copy it admitted.
struct ErasedParts {
    calls: usize,
    requests: Vec<ErasedRequestPart>,
    asks: Vec<ErasedAskPart>,
    outcomes: Vec<ErasedOutcomePart>,
}

impl ErasedParts {
    /// Each part of `record` in its erased form: a request or a rewrite
    /// holding the erased form, a spawn's request or rewrite holding the
    /// erased ask, and an outcome led by what an erase writes.
    fn of(record: &CodeRunReplayRecord) -> Result<Self> {
        let mut parts = Self {
            calls: record.bridge_calls.len(),
            requests: Vec::new(),
            asks: Vec::new(),
            outcomes: Vec::new(),
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
                } else if call.effect == SelfEffect::AgentsSpawn
                    && let Value::Map(fields) = form
                    && let Some(field) = erased_ask_field(fields)
                    && let Some(entry) = fields.get(field)
                {
                    parts.asks.push(ErasedAskPart {
                        call: index,
                        slot,
                        field,
                        entry: entry.clone(),
                    });
                }
            }
            if let Some(erasure) = erased_outcome(call)? {
                parts.outcomes.push(ErasedOutcomePart {
                    call: index,
                    erasure,
                });
            }
        }
        Ok(parts)
    }

    fn is_empty(&self) -> bool {
        self.requests.is_empty() && self.asks.is_empty() && self.outcomes.is_empty()
    }

    /// `record` with the fixed words taken out, the projection the wall
    /// reads: an erased request as the identity it keeps, a spawn's request
    /// without its erased ask, an erased outcome as the entries past what
    /// its erase wrote. It is no valid record.
    fn taken_out_of(&self, record: &CodeRunReplayRecord) -> CodeRunReplayRecord {
        let mut projection = record.clone();
        for part in &self.requests {
            if let (Some(call), Some(identity)) =
                (projection.bridge_calls.get_mut(part.call), part.kept())
            {
                part.slot.write(call, identity.clone());
            }
        }
        for part in &self.asks {
            if let Some(fields) = projection
                .bridge_calls
                .get_mut(part.call)
                .and_then(|call| part.slot.fields_mut(call))
                && part.field < fields.len()
            {
                fields.remove(part.field);
            }
        }
        for part in &self.outcomes {
            if let Some(call) = projection.bridge_calls.get_mut(part.call)
                && let Value::Map(entries) = &mut call.outcome
            {
                *entries = entries.split_off(part.erasure.len());
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
        if record.bridge_calls.len() != self.calls {
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
        for part in &self.asks {
            let fields = record
                .bridge_calls
                .get_mut(part.call)
                .and_then(|call| part.slot.fields_mut(call))
                .ok_or_else(part_moved)?;
            if part.field > fields.len() {
                return Err(part_moved());
            }
            fields.insert(part.field, part.entry.clone());
        }
        for part in &self.outcomes {
            let call = record
                .bridge_calls
                .get_mut(part.call)
                .ok_or_else(part_moved)?;
            let Value::Map(kept) = &mut call.outcome else {
                return Err(part_moved());
            };
            let mut outcome = part.erasure.clone();
            outcome.append(kept);
            *kept = outcome;
        }
        validate_code_run_replay_record(&record)?;
        Ok(record)
    }
}

/// The entries an erase writes in `call`'s place when `call`'s outcome
/// leads with them exactly: the failure `response_erased` of the call's own
/// effect with no code and no disk floor (FIX 5718, FIX 18924), or, for a
/// spawn, the typed `target_erased` or `asker_erased` answer (FIX 9180, FIX
/// 9183). They hold the erase's fixed words alone; what the erase kept past
/// them follows. `None` for any other outcome, a failure naming that cause
/// beside a code or a disk floor of its own among them.
fn erased_outcome(call: &CodeRunBridgeCall) -> Result<Option<Vec<(Value, Value)>>> {
    let Value::Map(entries) = &call.outcome else {
        return Ok(None);
    };
    let mut erasures = vec![SelfDispatchOutcome::Failed(SelfFailedResult {
        effect: call.effect,
        error: RESPONSE_ERASED.to_owned(),
        code: None,
        disk_floor: None,
    })];
    if call.effect == SelfEffect::AgentsSpawn {
        erasures.extend(
            [
                SelfAgentSpawnResult::TargetErased,
                SelfAgentSpawnResult::AskerErased,
            ]
            .map(SelfDispatchOutcome::AgentSpawn),
        );
    }
    for erasure in &erasures {
        if let Value::Map(erasure) = self_dispatch_outcome_value(erasure)?
            && entries.starts_with(&erasure)
        {
            return Ok(Some(erasure));
        }
    }
    Ok(None)
}

fn part_moved() -> Error {
    Error::InvariantViolation("the wall's copy of a fenced record moved an erased part")
}
