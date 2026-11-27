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
//! as a call with each part still in its erased form, and that copy lands
//! past the wall. The parts sit in bridge calls alone, so the wall reads each
//! call item so as the item is written ([`put_call_item`]): an append walls
//! only the calls it writes, and its bytes stay flat in the run's length
//! (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT). The head and every other item go
//! through the wall whole, as does a call holding no part in an erased form.
//!
//! An output preview is text the run wrote, and a live one can read as the
//! erased preview's text, so the wall reads every preview: one whose text
//! custody holds takes its handle, an erased one too.
//!
//! A writer that reads a stored row again before it derives a row or a body
//! from it has the wall read it the same way (FIX
//! ERASED-FORM-UNFENCED-REPLAY-PUTS): [`admit_fenced`] reads the row, and a
//! body carrying the row (a step start's prefix) has the wall read the
//! row's [`ErasedFormProjection`] in its place.

use oneiron_contracts::msgpack;
use rmpv::Value;

use super::super::super::codec::{
    decode_bridge_call, decode_code_run_replay_unvalidated, replay_record_value,
    validate_bridge_call, validate_code_run_replay_record,
};
use super::super::super::replay::erased_identity_field;
use super::super::super::spawn_replay::erased_ask_field;
use super::{
    CallWall, HEADS, ReplayItemKey, encode_call_item, item_value, put_admitted_item, put_raw_item,
};
use crate::EntityId;
use crate::code_run::payload::self_dispatch_outcome_value;
use crate::code_run::{
    CodeRunBridgeCall, CodeRunReplayRecord, RESPONSE_ERASED, SelfAgentSpawnResult,
    SelfDispatchOutcome, SelfEffect, SelfFailedResult,
};
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDbs};

/// Persists `record`, a record a put fence passed or a stored row a writer
/// read again, as its run's replay rows: with the side-row wall reading all
/// of each call item but the erase's fixed words in each part it holds in
/// its erased form, which land as they are. The head and every other item go
/// through the wall whole, as [`super::put`] puts them. Every full key
/// written or deleted.
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
) -> Result<Vec<Vec<u8>>> {
    super::put_record(dbs, wtxn, &record.run_id, record, CallWall::Fenced)
}

/// Writes `call`, whose item bytes are `bytes`, at the call item `key`
/// through its head's wall origin `head_key`, as `wall` reads it: under
/// [`CallWall::Fenced`] the wall reads all of it but the erase's fixed words
/// in each part it holds in its erased form, which land as they are; a call
/// holding no such part, or any call under [`CallWall::Whole`], goes through
/// the wall whole. The full key written.
///
/// # Errors
///
/// As [`put_fenced`]'s.
pub(super) fn put_call_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    head_key: &[u8],
    key: &ReplayItemKey,
    call: &CodeRunBridgeCall,
    bytes: &[u8],
    wall: CallWall,
) -> Result<Vec<u8>> {
    let parts = match wall {
        CallWall::Whole => None,
        CallWall::Fenced => Some(ErasedParts::of(std::slice::from_ref(call))?),
    };
    let Some(parts) = parts.filter(|parts| !parts.is_empty()) else {
        return put_admitted_item(dbs, wtxn, head_key, key, bytes);
    };
    let mut projection = [call.clone()];
    parts.take_out(&mut projection);
    let [projection] = projection;
    let projection = encode_call_item(&projection)?;
    let admitted = crate::batch::secret_scan::admit_side_row(
        dbs,
        wtxn,
        &side_table::CODE_RUN_REPLAY,
        head_key,
        &projection,
        |masked| parts.put_back_call(masked).is_ok(),
    )?;
    match admitted {
        Some(masked) => {
            let landed = encode_call_item(&parts.put_back_call(&masked)?)?;
            put_raw_item(dbs, wtxn, key, &landed)
        }
        None => put_raw_item(dbs, wtxn, key, bytes),
    }
}

/// Reads `record`, a stored row a writer derives a row or a body from, as
/// [`put_fenced`] stores it: the wall reads all of it but the erase's fixed
/// words in each part it holds in its erased form, and each secret it
/// places becomes its handle in `record` too. A record holding no such part
/// is read whole, as [`super::admit`] reads it.
///
/// # Errors
///
/// As [`put_fenced`]'s; it writes no replay row.
pub(crate) fn admit_fenced(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    record: &mut CodeRunReplayRecord,
) -> Result<()> {
    let run = record.run_id;
    let Some(erased) = ErasedFormProjection::of(record)? else {
        return super::admit(dbs, wtxn, &run, record);
    };
    if let Some(admitted) = erased.admitted(dbs, wtxn, &run)? {
        *record = admitted;
    }
    Ok(())
}

/// What the side-row wall reads of a replay record that holds a part in an
/// erased form: the record's pinned MessagePack with the erase's fixed
/// words taken out, and the place of each, which goes back into the copy
/// the wall admitted.
pub(crate) struct ErasedFormProjection {
    parts: ErasedParts,
    projection: Vec<u8>,
}

impl ErasedFormProjection {
    /// `record`'s projection; `None` when it holds no part in an erased
    /// form, and the wall reads it whole.
    ///
    /// # Errors
    ///
    /// An erased outcome that does not encode.
    pub(crate) fn of(record: &CodeRunReplayRecord) -> Result<Option<Self>> {
        let parts = ErasedParts::of(&record.bridge_calls)?;
        if parts.is_empty() {
            return Ok(None);
        }
        let projection = msgpack::encode(&replay_record_value(&parts.taken_out_of(record)));
        Ok(Some(Self { parts, projection }))
    }

    /// The bytes the wall reads in the record's place. They are no valid
    /// record.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.projection
    }

    /// The record the wall admitted, read from `masked`, the projection's
    /// bytes as the wall left them: the fixed words back in each part, each
    /// part still in its erased form, and the whole a valid record.
    ///
    /// # Errors
    ///
    /// A copy in which a part moved or no longer holds its erased form, or
    /// which is no valid record.
    pub(crate) fn put_back(&self, masked: &[u8]) -> Result<CodeRunReplayRecord> {
        self.parts.put_back(masked)
    }

    /// The record as the wall admits it at `run`'s row, writing no replay
    /// row; `None` when the wall changes nothing.
    fn admitted(
        &self,
        dbs: &impl SideTableDbs,
        wtxn: &mut heed::RwTxn<'_>,
        run: &EntityId,
    ) -> Result<Option<CodeRunReplayRecord>> {
        HEADS
            .admit_projection(dbs, wtxn, run, &self.projection, |masked| {
                self.parts.put_back(masked).is_ok()
            })?
            .map(|masked| self.parts.put_back(&masked))
            .transpose()
    }
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

/// The erase's fixed words in a fenced record's calls, or in one call, by
/// the place of each part that holds them: what the projection the wall
/// reads takes out, and what goes back into the copy it admitted.
struct ErasedParts {
    calls: usize,
    requests: Vec<ErasedRequestPart>,
    asks: Vec<ErasedAskPart>,
    outcomes: Vec<ErasedOutcomePart>,
}

impl ErasedParts {
    /// Each part of `calls` in its erased form: a request or a rewrite
    /// holding the erased form, a spawn's request or rewrite holding the
    /// erased ask, and an outcome led by what an erase writes.
    fn of(calls: &[CodeRunBridgeCall]) -> Result<Self> {
        let mut parts = Self {
            calls: calls.len(),
            requests: Vec::new(),
            asks: Vec::new(),
            outcomes: Vec::new(),
        };
        for (index, call) in calls.iter().enumerate() {
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
    /// reads. It is no valid record.
    fn taken_out_of(&self, record: &CodeRunReplayRecord) -> CodeRunReplayRecord {
        let mut projection = record.clone();
        self.take_out(&mut projection.bridge_calls);
        projection
    }

    /// Takes the fixed words out of `calls`, the calls the parts were read
    /// from: an erased request as the identity it keeps, a spawn's request
    /// without its erased ask, an erased outcome as the entries past what
    /// its erase wrote.
    fn take_out(&self, calls: &mut [CodeRunBridgeCall]) {
        for part in &self.requests {
            if let (Some(call), Some(identity)) = (calls.get_mut(part.call), part.kept()) {
                part.slot.write(call, identity.clone());
            }
        }
        for part in &self.asks {
            if let Some(fields) = calls
                .get_mut(part.call)
                .and_then(|call| part.slot.fields_mut(call))
                && part.field < fields.len()
            {
                fields.remove(part.field);
            }
        }
        for part in &self.outcomes {
            if let Some(call) = calls.get_mut(part.call)
                && let Value::Map(entries) = &mut call.outcome
            {
                *entries = entries.split_off(part.erasure.len());
            }
        }
    }

    /// The record the wall admitted, read from `masked`, the bytes of its
    /// masked projection: the fixed words back in each part, each request
    /// part still holding the erased form, and the whole then a valid
    /// record.
    fn put_back(&self, masked: &[u8]) -> Result<CodeRunReplayRecord> {
        let mut record = decode_code_run_replay_unvalidated(masked)?;
        self.put_back_into(&mut record.bridge_calls)?;
        validate_code_run_replay_record(&record)?;
        Ok(record)
    }

    /// The call the wall admitted, read from `masked`, the bytes of the
    /// masked projection of the one call the parts were read from: the
    /// fixed words back in each part, each request part still holding the
    /// erased form, and the call then valid.
    fn put_back_call(&self, masked: &[u8]) -> Result<CodeRunBridgeCall> {
        let mut calls = [decode_bridge_call(&item_value(masked)?)?];
        self.put_back_into(&mut calls)?;
        let [call] = calls;
        validate_bridge_call(&call)?;
        Ok(call)
    }

    /// Puts the fixed words back into `calls`, the masked copies of the
    /// calls the parts were read from; an error when a part moved or no
    /// longer holds its erased form.
    fn put_back_into(&self, calls: &mut [CodeRunBridgeCall]) -> Result<()> {
        if calls.len() != self.calls {
            return Err(part_moved());
        }
        for part in &self.requests {
            let call = calls.get_mut(part.call).ok_or_else(part_moved)?;
            let identity = part.slot.read(call).cloned().ok_or_else(part_moved)?;
            let form = part.with_identity(identity).ok_or_else(part_moved)?;
            part.slot.write(call, form);
        }
        for part in &self.asks {
            let fields = calls
                .get_mut(part.call)
                .and_then(|call| part.slot.fields_mut(call))
                .ok_or_else(part_moved)?;
            if part.field > fields.len() {
                return Err(part_moved());
            }
            fields.insert(part.field, part.entry.clone());
        }
        for part in &self.outcomes {
            let call = calls.get_mut(part.call).ok_or_else(part_moved)?;
            let Value::Map(kept) = &mut call.outcome else {
                return Err(part_moved());
            };
            let mut outcome = part.erasure.clone();
            outcome.append(kept);
            *kept = outcome;
        }
        Ok(())
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
