//! Door for `tests/erased_request_custody_identity.rs` (FIX
//! ERASED-IDENTITY-ONE-STAND-IN): one code-run call stored in an agent's
//! replay record through the side-row wall, in the vault or on a room's
//! route, erased with that agent's replies by the agent's delete, and read
//! against a call made again, as the replay cursor reads an erased row.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use rmpv::Value;

use crate::code_run::{
    BaseKnownRead, CodeRunBridgeCall, CodeRunReplayRecord, CompareKnown, ExecutorStorage, SelfCall,
    SelfDispatchOutcome, SelfFailedResult, SelfMemoryPutClaimCall, replay_rows,
};
use crate::error::{Error, Result};
use crate::off_record::OffRecordSession;
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};

/// The claim the call writes: `note`, as a new agent's note.
fn note_call(agent: EntityId, note: Value) -> SelfCall {
    SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        agent,
        ClaimCandidate::new("note.text", ClaimSubject::Entity(agent), note, 1.0),
        TimeRange { start: 1, end: 1 },
        1,
    ))
}

/// The call writing `note` as `agent`'s note, as its row records it.
fn note_row(agent: EntityId, note: Value) -> Result<CodeRunBridgeCall> {
    let call = note_call(agent, note);
    CodeRunBridgeCall::record(
        0,
        &call,
        &SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: "note not written".to_owned(),
            code: None,
            disk_floor: None,
        }),
        1,
        2,
    )
}

/// A new agent in `vault`, and the replay record of a new run whose one call
/// writes `note` as the agent's note: the agent and the run, then the record.
fn new_note_run(vault: &Vault, note: Value) -> Result<([EntityId; 2], CodeRunReplayRecord)> {
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let run = EntityId::now();
    let mut record = CodeRunReplayRecord::with_determinism(run, None);
    record.bridge_calls.push(note_row(agent, note)?);
    Ok(([agent, run], record))
}

/// Stores the record of a new run writing `note`, with its agent as its
/// replies' owner, through the vault's side-row wall.
fn store_note(vault: &Vault, note: Value) -> Result<[EntityId; 2]> {
    let ([agent, run], record) = new_note_run(vault, note)?;
    ExecutorStorage::Canonical(vault)
        .put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([agent, run])
}

/// Stores, for a new agent, the replay record of a new run whose one call
/// writes `words` as the agent's note, with the agent as its replies' owner,
/// through the side-row wall: the agent and the run, in that order.
///
/// # Errors
///
/// The agent cannot be put, or the record cannot be stored.
pub fn store_note_call(vault: &Vault, words: &str) -> Result<[EntityId; 2]> {
    store_note(vault, Value::from(words))
}

/// [`store_note_call`] for a note held as the bytes of `body`, which the
/// wall reads as a body of its own.
///
/// # Errors
///
/// The agent cannot be put, or the record cannot be stored.
pub fn store_note_body(vault: &Vault, body: &[u8]) -> Result<[EntityId; 2]> {
    store_note(vault, Value::Binary(body.to_vec()))
}

/// [`store_note_call`] on `session`'s write route: the record is staged in
/// the room's overlay through the wall. With `delete_first`, the agent is
/// deleted once the run is bound to the room and before the record is put,
/// so the room's put fence erases the record in its writer; otherwise the
/// record is staged live.
///
/// # Errors
///
/// The agent cannot be put or deleted, the run cannot be bound to the room,
/// or the record cannot be stored.
pub fn store_note_call_in_room(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    words: &str,
    delete_first: bool,
) -> Result<[EntityId; 2]> {
    let ([agent, run], record) = new_note_run(vault, Value::from(words))?;
    let storage = ExecutorStorage::for_session(session, agent)?;
    if delete_first {
        vault.delete_entity(&agent)?;
    }
    storage.put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([agent, run])
}

/// The one call `record` holds.
fn first_call(record: Option<CodeRunReplayRecord>) -> Result<CodeRunBridgeCall> {
    record
        .and_then(|record| record.bridge_calls.into_iter().next())
        .ok_or(Error::CorruptedIndex("the note run has no stored call"))
}

/// The one call `run`'s stored record holds.
fn stored_call(vault: &Vault, run: EntityId) -> Result<CodeRunBridgeCall> {
    first_call(vault.get_code_run_replay_record(&run)?)
}

/// The one call `run`'s record holds, read in `session`'s room.
fn room_stored_call(session: &OffRecordSession<'_>, run: EntityId) -> Result<CodeRunBridgeCall> {
    first_call(session.routed_side_read(|rtxn, read| replay_rows::get(&read, rtxn, &run))?)
}

/// Whether `stored` is the call `agent` makes again writing `note`, read as
/// the replay cursor reads it: with the values `vault`'s base custody holds
/// now when `custody` is in reach, else with none.
fn call_is(
    vault: &Vault,
    stored: &CodeRunBridgeCall,
    agent: EntityId,
    note: Value,
    custody: bool,
) -> Result<bool> {
    let offered = note_row(agent, note)?.request;
    let read: BaseKnownRead<'_> = &|| vault.known_values_now();
    let known = CompareKnown::new(custody.then_some(read));
    stored.request_identity_is(&offered, &known)
}

/// Whether the call `run`'s stored record holds is in its erased form.
///
/// # Errors
///
/// The record cannot be read.
pub fn stored_call_erased(vault: &Vault, run: EntityId) -> Result<bool> {
    Ok(stored_call(vault, run)?.request_erased())
}

/// Whether the call `run`'s record holds in `session`'s room is in its
/// erased form.
///
/// # Errors
///
/// The record cannot be read in the room.
pub fn room_stored_call_erased(session: &OffRecordSession<'_>, run: EntityId) -> Result<bool> {
    Ok(room_stored_call(session, run)?.request_erased())
}

/// Whether the call `run`'s stored record holds is the call `agent` makes
/// again writing `words`, read as the replay cursor reads it: with the
/// values base custody holds now when `custody` is in reach, else with
/// none.
///
/// # Errors
///
/// The record cannot be read, or the compare fails.
pub fn stored_call_is(
    vault: &Vault,
    [agent, run]: [EntityId; 2],
    words: &str,
    custody: bool,
) -> Result<bool> {
    call_is(
        vault,
        &stored_call(vault, run)?,
        agent,
        Value::from(words),
        custody,
    )
}

/// [`stored_call_is`] for a call made again writing a note held as the
/// bytes of `body`.
///
/// # Errors
///
/// The record cannot be read, or the compare fails.
pub fn stored_body_call_is(
    vault: &Vault,
    [agent, run]: [EntityId; 2],
    body: &[u8],
    custody: bool,
) -> Result<bool> {
    call_is(
        vault,
        &stored_call(vault, run)?,
        agent,
        Value::Binary(body.to_vec()),
        custody,
    )
}

/// [`stored_call_is`] for the record `session`'s room holds.
///
/// # Errors
///
/// The record cannot be read in the room, or the compare fails.
pub fn room_stored_call_is(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    [agent, run]: [EntityId; 2],
    words: &str,
    custody: bool,
) -> Result<bool> {
    call_is(
        vault,
        &room_stored_call(session, run)?,
        agent,
        Value::from(words),
        custody,
    )
}

/// The handle custody gives `record`, or `None` when it gives none.
///
/// # Errors
///
/// The vault cannot be read.
pub fn custody_handle(vault: &Vault, record: EntityId) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, &txn, &record)?
            .map(|(handle, _)| handle),
    )
}
