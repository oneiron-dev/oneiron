//! A replay row's and a step start's parts under checkpoint custody (FIX
//! 9180, Engine C2; coord-b slice d).
//!
//! A checkpoint carries a decoded replay row whose spawns reached resolved
//! targets as parts, each sealed under an instance of its own: its reply,
//! the row with each such spawn's ask taken out (nil in its place), and
//! each such ask, owed to every target its host resolved for the call. The
//! image row holds its skeleton, the stub a retired reply leaves, with no
//! carried ask in it. A step start whose prefix holds such a spawn travels
//! the same way: its rest, and each ask. Erasing one target retires only
//! the asks of the calls it seats, so every other part stays restorable;
//! two calls that reach one target are two parts.
//!
//! A restore recomposes each row or start once, after every part's
//! disposition is known ([`recompose_replay_record`]). A row or start that
//! does not decode, or whose record does not encode again to its exact
//! bytes, is never partitioned: it travels whole as before, an undecodable
//! one opaque (FIX 6227).

use rmpv::Value;

use super::codec::{
    decode_code_run_replay_record, encode_code_run_replay_record, encode_code_run_replay_value,
};
use super::replay::{CodeRunBridgeCall, CodeRunReplayRecord};
use super::replay_capsule::StepStartBody;
use super::spawn_replay::{
    decode_spawn_targets, erase_spawn_call, spawn_ask_part, spawn_targets_value, swap_spawn_ask,
};
use super::storage::replay_carriage;
use super::support::invalid_code_run_replay;
use super::types::SelfEffect;
use crate::store::{ResponseCarriage, ResponseScan};
use crate::{EntityId, Error, Result};

/// The extent of the nil a carried ask leaves in its place: one byte, 0xc0.
const NIL_EXTENT: (u64, u64) = (1, 1);

/// One part a checkpoint carries of a replay row or a step start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayPart {
    /// `None` for the rest (a row's reply, a start's rest); a request part's
    /// call, by its place among the record's calls and its seq.
    pub(crate) request: Option<(u32, u64)>,
    /// What it carries sealed: the rest, or the call's encoded ask.
    pub(crate) bytes: Vec<u8>,
    /// A request part's owners: every seat its host resolved for the call.
    pub(crate) seats: Vec<EntityId>,
    /// A request part's call in its erased form, text-free; empty for the
    /// rest.
    pub(crate) erased: Vec<u8>,
    /// What the part changes of its destination's record, for its grouped
    /// landing length ([`recomposed_len`]), each as (bytes, bytes at or
    /// above 0x80): a request part's ask, then its call's spawn fields as
    /// the rest holds them, as the skeleton holds them, and erased; a
    /// start's rest, its record.
    pub(crate) extents: Vec<(u64, u64)>,
}

/// The parts of one replay row or step start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayParts {
    /// A row's skeleton, the stub its image row holds; `None` for a start.
    pub(crate) skeleton: Option<Vec<u8>>,
    /// The rest first, then each request part in call order.
    pub(crate) parts: Vec<ReplayPart>,
}

/// How one request part stands when its destination recomposes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RequestPart<'a> {
    /// Its instance is live: the ask it carried.
    Live(&'a [u8]),
    /// Its instance retired: the erased facts kept beside it.
    Retired(&'a [u8]),
}

/// FIX 9180 (coord-b slice d): the parts a checkpoint carries of the replay
/// row `value`: its reply, each spawn ask it carries apart, and the
/// skeleton its image row holds. `None` for a row with no such ask, and for
/// one that does not decode, does not encode again to its exact bytes, or
/// whose parts do not encode: each travels whole, as before.
pub(crate) fn replay_row_parts(value: &[u8]) -> Option<ReplayParts> {
    row_parts(value).unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "a replay row whose parts do not encode travels whole"
        );
        None
    })
}

/// [`replay_row_parts`], its encode failures returned.
fn row_parts(value: &[u8]) -> Result<Option<ReplayParts>> {
    let Some(mut record) = canonical_record(value) else {
        return Ok(None);
    };
    let mut requests = take_asks(&mut record)?;
    let reply = encode_code_run_replay_record(&record)?;
    let ResponseScan::Decoded(ResponseCarriage { stub, .. }) = replay_carriage(&reply) else {
        return Ok(None);
    };
    let skeleton = decode_code_run_replay_record(&stub)?;
    for part in &mut requests {
        if let Some((index, _)) = part.request
            && let Some(call) = skeleton.bridge_calls.get(index as usize)
        {
            part.extents[2] = spawn_fields_extent(call)?;
        }
    }
    Ok(Some(ReplayParts {
        skeleton: Some(stub),
        parts: rest_then(reply, Vec::new(), requests),
    }))
}

/// FIX 9180 (coord-b slice d): the parts a checkpoint carries of the step
/// start body `bytes`: its rest, the body with each carried ask of its
/// prefix taken out, and each such ask. `None` for a start whose prefix
/// holds none, and for one that does not decode, does not encode again to
/// its exact bytes, or whose parts do not encode.
pub(crate) fn step_start_parts(bytes: &[u8]) -> Option<ReplayParts> {
    start_parts(bytes).unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "a step start whose parts do not encode travels whole"
        );
        None
    })
}

/// [`step_start_parts`], its encode failures returned.
fn start_parts(bytes: &[u8]) -> Result<Option<ReplayParts>> {
    let Ok(mut body) = rmp_serde::from_slice::<StepStartBody>(bytes) else {
        return Ok(None);
    };
    let Some(mut record) = canonical_record(&body.record) else {
        return Ok(None);
    };
    if encode_start(&body).ok().as_deref() != Some(bytes) {
        return Ok(None);
    }
    let requests = take_asks(&mut record)?;
    body.record = encode_code_run_replay_record(&record)?;
    let extents = vec![bytes_extent(&body.record)];
    Ok(Some(ReplayParts {
        skeleton: None,
        parts: rest_then(encode_start(&body)?, extents, requests),
    }))
}

/// The record `bytes` encode, when one of its calls holds an ask a
/// checkpoint carries apart and it encodes again to exactly `bytes` (CALLS
/// "replay parts need canonical bytes"): only such a record recomposes to
/// its own bytes when every part is live; any other travels whole, as
/// before.
fn canonical_record(bytes: &[u8]) -> Option<CodeRunReplayRecord> {
    let record = decode_code_run_replay_record(bytes).ok()?;
    if !record
        .bridge_calls
        .iter()
        .any(|call| spawn_ask_part(call).is_some())
    {
        return None;
    }
    if encode_code_run_replay_record(&record).ok()?.as_slice() != bytes {
        tracing::warn!(
            "a replay record that does not encode again to its bytes travels whole; its spawn \
             asks stay in its image"
        );
        return None;
    }
    Some(record)
}

/// Takes each ask a checkpoint carries apart out of `record`, nil in its
/// place, as its part, with the facts of its call in its erased form
/// ([`erase_spawn_call`] on a copy, before anything is stripped). A spawn
/// with no resolved target keeps its ask, and is reported.
fn take_asks(record: &mut CodeRunReplayRecord) -> Result<Vec<ReplayPart>> {
    let mut requests = Vec::new();
    let mut unproved = 0_usize;
    for (index, call) in record.bridge_calls.iter_mut().enumerate() {
        let Some(ask) = spawn_ask_part(call).cloned() else {
            if call.effect == SelfEffect::AgentsSpawn && call.spawn_targets.seats().is_empty() {
                unproved += 1;
            }
            continue;
        };
        let mut erased = call.clone();
        erase_spawn_call(&mut erased)?;
        let seats = call.spawn_targets.seats().to_vec();
        swap_spawn_ask(call, Value::Nil);
        let bytes = encode_code_run_replay_value(&ask, "spawn ask MessagePack encode failed")?;
        let rest = spawn_fields_extent(call)?;
        requests.push(ReplayPart {
            request: Some((
                u32::try_from(index)
                    .map_err(|_| Error::ArithmeticOverflow("replay bridge call index"))?,
                call.seq,
            )),
            extents: vec![
                bytes_extent(&bytes),
                rest,
                rest,
                spawn_fields_extent(&erased)?,
            ],
            erased: erased_facts(&erased)?,
            bytes,
            seats,
        });
    }
    if unproved > 0 {
        tracing::warn!(
            unproved,
            "spawn calls with no resolved target keep their asks where their replay row keeps them"
        );
    }
    Ok(requests)
}

/// The parts of one destination: its rest, `bytes`, then `requests`.
fn rest_then(
    bytes: Vec<u8>,
    extents: Vec<(u64, u64)>,
    requests: Vec<ReplayPart>,
) -> Vec<ReplayPart> {
    let mut parts = Vec::with_capacity(requests.len() + 1);
    parts.push(ReplayPart {
        request: None,
        bytes,
        seats: Vec::new(),
        erased: Vec::new(),
        extents,
    });
    parts.extend(requests);
    parts
}

/// The text-free facts of a call in its erased form: its request with the
/// erased marker, its `TargetErased` answer with any row receipt, and its
/// targets with the id it answered before.
fn erased_facts(erased: &CodeRunBridgeCall) -> Result<Vec<u8>> {
    encode_code_run_replay_value(
        &Value::Array(vec![
            erased.request.clone(),
            erased.outcome.clone(),
            spawn_targets_value(&erased.spawn_targets),
        ]),
        "erased spawn facts MessagePack encode failed",
    )
}

/// What a call's spawn fields (its request, answer and targets) take of its
/// record's encoding; every other field is the same in each form a part
/// recomposes it in.
fn spawn_fields_extent(call: &CodeRunBridgeCall) -> Result<(u64, u64)> {
    let mut extent = (0, 0);
    for value in [
        &call.request,
        &call.outcome,
        &spawn_targets_value(&call.spawn_targets),
    ] {
        let bytes = encode_code_run_replay_value(value, "spawn field MessagePack encode failed")?;
        let (len, high) = bytes_extent(&bytes);
        extent = (extent.0 + len, extent.1 + high);
    }
    Ok(extent)
}

/// `bytes`' length, and how many of them are 0x80 or above.
fn bytes_extent(bytes: &[u8]) -> (u64, u64) {
    let high = bytes.iter().filter(|byte| **byte >= 0x80).count();
    (bytes.len() as u64, high as u64)
}

/// A step start body as its capsule stores it.
fn encode_start(body: &StepStartBody) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(body)
        .map_err(|error| Error::InvalidConfig(format!("capsule start: {error}")))
}

/// The step start body `bytes`.
fn decode_start(bytes: &[u8]) -> Result<StepStartBody> {
    rmp_serde::from_slice(bytes)
        .map_err(|error| Error::InvalidConfig(format!("capsule start: {error}")))
}

/// The one value `bytes` hold.
fn value_of(bytes: &[u8]) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_code_run_replay("a carried spawn part is not MessagePack"))?;
    if !cursor.is_empty() {
        return Err(invalid_code_run_replay(
            "trailing bytes after a carried spawn part",
        ));
    }
    Ok(value)
}

/// The spawn call of `record` at `index`, with `seq`.
fn spawn_at(
    record: &mut CodeRunReplayRecord,
    (index, seq): (u32, u64),
) -> Result<&mut CodeRunBridgeCall> {
    record
        .bridge_calls
        .get_mut(index as usize)
        .filter(|call| call.seq == seq && call.effect == SelfEffect::AgentsSpawn)
        .ok_or_else(|| invalid_code_run_replay("a spawn part names no spawn of its record"))
}

/// FIX 9180 (Engine C3): the one recomposition of a replay record from its
/// parts, `record` its reply or rest when live, or its skeleton when the
/// reply retired (`reply_retired`). Each live ask goes back in its call's
/// place first; then each retired one's call takes the erased facts kept
/// beside it (its answer and targets too when the reply retired, which
/// keeps the id it answered before and any row receipt) and
/// [`erase_spawn_call`] runs on it last, so its `TargetErased` wins over
/// the reply's old answer and over a retired reply's stub. Every other call
/// and field stays as `record` holds it.
fn recompose_replay_record(
    record: &mut CodeRunReplayRecord,
    reply_retired: bool,
    requests: &[((u32, u64), RequestPart<'_>)],
) -> Result<()> {
    for (call, part) in requests {
        let RequestPart::Live(ask) = part else {
            continue;
        };
        let ask = value_of(ask)?;
        if !ask.is_str()
            || !matches!(
                swap_spawn_ask(spawn_at(record, *call)?, ask),
                Some(Value::Nil)
            )
        {
            return Err(invalid_code_run_replay(
                "a carried spawn ask does not fit its call",
            ));
        }
    }
    for (call, part) in requests {
        let RequestPart::Retired(facts) = part else {
            continue;
        };
        let call = spawn_at(record, *call)?;
        let Value::Array(facts) = value_of(facts)? else {
            return Err(invalid_code_run_replay("erased spawn facts are not a list"));
        };
        let [request, outcome, targets] = facts.as_slice() else {
            return Err(invalid_code_run_replay("erased spawn facts are not three"));
        };
        call.request = request.clone();
        if reply_retired {
            call.outcome = outcome.clone();
            call.spawn_targets = decode_spawn_targets(targets)?;
        }
        erase_spawn_call(call)?;
    }
    Ok(())
}

/// FIX 9180: the replay row recomposed from its parts: its live `reply`, or
/// its `skeleton` when the reply retired, with each request part as it
/// stands.
///
/// # Errors
///
/// A part that does not decode or fit, and a row that does not encode.
pub(crate) fn recompose_replay_row(
    skeleton: &[u8],
    reply: Option<&[u8]>,
    requests: &[((u32, u64), RequestPart<'_>)],
) -> Result<Vec<u8>> {
    let mut record = decode_code_run_replay_record(reply.unwrap_or(skeleton))?;
    recompose_replay_record(&mut record, reply.is_none(), requests)?;
    encode_code_run_replay_record(&record)
}

/// FIX 9180: the step start body recomposed from its live `rest`, with each
/// request part as it stands: unchanged, the start's own bytes.
///
/// # Errors
///
/// A part that does not decode or fit, and a body that does not encode.
pub(crate) fn recompose_step_start(
    rest: &[u8],
    requests: &[((u32, u64), RequestPart<'_>)],
) -> Result<Vec<u8>> {
    let mut body = decode_start(rest)?;
    let mut record = decode_code_run_replay_record(&body.record)?;
    recompose_replay_record(&mut record, false, requests)?;
    body.record = encode_code_run_replay_record(&record)?;
    encode_start(&body)
}

/// The bytes a recomposed destination is, counted from what its parts
/// carried and how each stands, with nothing opened (FIX 6025, 6232):
/// `base` is its reply's or rest's length when live, its skeleton's when
/// the reply retired (`reply_retired`); `record`, a start's rest's record,
/// which its body spells one integer per byte. Each live ask takes its
/// nil's place, and each retired call's spawn fields take their erased
/// form. `requests` names each request part's liveness and extents.
pub(crate) fn recomposed_len(
    base: u64,
    record: Option<(u64, u64)>,
    reply_retired: bool,
    requests: &[(bool, &[(u64, u64)])],
) -> u64 {
    let (mut len, mut high) = (0_i128, 0_i128);
    for (live, extents) in requests {
        let &[ask, rest, stub, erased] = *extents else {
            continue;
        };
        let (from, to) = match (*live, reply_retired) {
            (true, _) => (NIL_EXTENT, ask),
            (false, false) => (rest, erased),
            (false, true) => (stub, erased),
        };
        len += i128::from(to.0) - i128::from(from.0);
        high += i128::from(to.1) - i128::from(from.1);
    }
    let landed = match record {
        None => i128::from(base) + len,
        Some((before, before_high)) => {
            let (before, before_high) = (i128::from(before), i128::from(before_high));
            i128::from(base) - spelled(before, before_high)
                + spelled(before + len, before_high + high)
        }
    };
    u64::try_from(landed.max(0)).unwrap_or(u64::MAX)
}

/// What `len` bytes, `high` of them 0x80 or above, take spelled one integer
/// per byte, as a step start body spells its record: the array's header,
/// then one byte for each, two for each high one.
fn spelled(len: i128, high: i128) -> i128 {
    let header = if len < 16 {
        1
    } else if len < 65_536 {
        3
    } else {
        5
    };
    header + len + high
}

/// FIX 9180: the live replay row `value` with what an activation's source
/// retired of its parts, through the one recomposition: the reply's erased
/// disposition first when it retired (the stub its whole row's retirement
/// leaves), then each retired ask's call in its erased form, the facts
/// taken from the call as the live row holds it. `None` for a row that
/// does not decode; a retired part that names no spawn of the row any
/// longer is passed over.
///
/// # Errors
///
/// A row that does not encode.
pub(crate) fn retire_replay_row_parts(
    value: &[u8],
    reply_retired: bool,
    retired: &[(u32, u64)],
) -> Result<Option<Vec<u8>>> {
    let Ok(record) = decode_code_run_replay_record(value) else {
        return Ok(None);
    };
    let facts = retired_facts(&record, retired)?;
    let mut base = if reply_retired {
        let ResponseScan::Decoded(ResponseCarriage { stub, .. }) = replay_carriage(value) else {
            return Ok(None);
        };
        decode_code_run_replay_record(&stub)?
    } else {
        record
    };
    let requests: Vec<_> = facts
        .iter()
        .map(|(call, facts)| (*call, RequestPart::Retired(facts)))
        .collect();
    recompose_replay_record(&mut base, reply_retired, &requests)?;
    encode_code_run_replay_record(&base).map(Some)
}

/// FIX 9180: the live step start body `bytes` with each retired ask's call
/// in its erased form. `None` for a body that does not decode or names
/// none of `retired` any longer.
///
/// # Errors
///
/// A body that does not encode.
pub(crate) fn retire_step_start_parts(
    bytes: &[u8],
    retired: &[(u32, u64)],
) -> Result<Option<Vec<u8>>> {
    let Ok(mut body) = decode_start(bytes) else {
        return Ok(None);
    };
    let Ok(mut record) = decode_code_run_replay_record(&body.record) else {
        return Ok(None);
    };
    let facts = retired_facts(&record, retired)?;
    if facts.is_empty() {
        return Ok(None);
    }
    let requests: Vec<_> = facts
        .iter()
        .map(|(call, facts)| (*call, RequestPart::Retired(facts)))
        .collect();
    recompose_replay_record(&mut record, false, &requests)?;
    body.record = encode_code_run_replay_record(&record)?;
    encode_start(&body).map(Some)
}

/// Each of `retired` that names a spawn of `record`, with the erased facts
/// of its call as `record` holds it.
fn retired_facts(
    record: &CodeRunReplayRecord,
    retired: &[(u32, u64)],
) -> Result<Vec<((u32, u64), Vec<u8>)>> {
    let mut facts = Vec::with_capacity(retired.len());
    for &(index, seq) in retired {
        let Some(call) = record
            .bridge_calls
            .get(index as usize)
            .filter(|call| call.seq == seq && call.effect == SelfEffect::AgentsSpawn)
        else {
            continue;
        };
        let mut erased = call.clone();
        erase_spawn_call(&mut erased)?;
        facts.push(((index, seq), erased_facts(&erased)?));
    }
    Ok(facts)
}
