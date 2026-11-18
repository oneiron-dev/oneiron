//! Door for `tests/erased_request_custody_identity.rs` (FIX
//! ERASED-IDENTITY-ONE-STAND-IN): one code-run call stored in an agent's
//! replay record through the side-row wall, erased with that agent's replies
//! by the agent's delete, and read against a call made again, as the replay
//! cursor reads an erased row.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use rmpv::Value;

use crate::code_run::{
    BaseKnownRead, CodeRunBridgeCall, CodeRunReplayRecord, CompareKnown, ExecutorStorage, SelfCall,
    SelfDispatchOutcome, SelfFailedResult, SelfMemoryPutClaimCall,
};
use crate::error::{Error, Result};
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};

/// The claim the call writes: `words`, as a new agent's note.
fn note_call(agent: EntityId, words: &str) -> SelfCall {
    SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        agent,
        ClaimCandidate::new(
            "note.text",
            ClaimSubject::Entity(agent),
            Value::from(words),
            1.0,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    ))
}

/// The call writing `words` as `agent`'s note, as its row records it.
fn note_row(agent: EntityId, words: &str) -> Result<CodeRunBridgeCall> {
    let call = note_call(agent, words);
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

/// Stores, for a new agent, the replay record of a new run whose one call
/// writes `words` as the agent's note, with the agent as its replies' owner,
/// through the side-row wall: the agent and the run, in that order.
///
/// # Errors
///
/// The agent cannot be put, or the record cannot be stored.
pub fn store_note_call(vault: &Vault, words: &str) -> Result<[EntityId; 2]> {
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
    record.bridge_calls.push(note_row(agent, words)?);
    ExecutorStorage::Canonical(vault)
        .put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([agent, run])
}

/// The one call `run`'s stored record holds.
fn stored_call(vault: &Vault, run: EntityId) -> Result<CodeRunBridgeCall> {
    vault
        .get_code_run_replay_record(&run)?
        .and_then(|record| record.bridge_calls.into_iter().next())
        .ok_or(Error::CorruptedIndex("the note run has no stored call"))
}

/// Whether the call `run`'s stored record holds is in its erased form.
///
/// # Errors
///
/// The record cannot be read.
pub fn stored_call_erased(vault: &Vault, run: EntityId) -> Result<bool> {
    Ok(stored_call(vault, run)?.request_erased())
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
    let offered = note_row(agent, words)?.request;
    let read: BaseKnownRead<'_> = &|| vault.known_values_now();
    let known = CompareKnown::new(custody.then_some(read));
    stored_call(vault, run)?.request_identity_is(&offered, &known)
}
