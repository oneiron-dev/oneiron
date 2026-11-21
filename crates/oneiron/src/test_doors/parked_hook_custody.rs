//! Door for `tests/parked_hook_custody_value.rs` (FIX
//! PARKED-HOOK-LIVE-EXACT-COMPARE): one code-run call a verb pre-hook's ask
//! parked, stored in an agent's replay record through the side-row wall,
//! and the note that row leaves read against the same call made again, as a
//! durable run's next try reads it to resume the ask, with the args the ask
//! saved.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use rmpv::Value;

use crate::code_run::{
    BaseKnownRead, CodeRunBridgeCall, CodeRunReplayRecord, ExecutorStorage, SelfCall,
    SelfMemoryPutClaimCall, hook_parked_outcome_for_test, parked_note_resumed_for_test,
};
use crate::error::{Error, Result};
use crate::runtime_hooks::InvocationId;
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};

/// The call writing `words` as `agent`'s note.
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

/// Stores, for a new agent, the replay record of a new run whose one call,
/// writing `words` as the agent's note, a pre-hook's ask parked, with the
/// agent as its replies' owner, through the side-row wall: the agent and
/// the run, in that order.
///
/// # Errors
///
/// The agent cannot be put, or the record cannot be stored.
pub fn store_parked_note_call(vault: &Vault, words: &str) -> Result<[EntityId; 2]> {
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let run = EntityId::now();
    let call = note_call(agent, words);
    let parked = hook_parked_outcome_for_test(call.effect(), InvocationId::mint(), EntityId::now());
    let mut record = CodeRunReplayRecord::with_determinism(run, None);
    record
        .bridge_calls
        .push(CodeRunBridgeCall::record(0, &call, &parked, 1, 2)?);
    ExecutorStorage::Canonical(vault)
        .put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([agent, run])
}

/// Whether the call `agent` makes again writing `words` resumes the ask the
/// call `run`'s stored record parked on, read with the values `vault`'s base
/// custody holds now, as the run's next try reads it, when the ask saved the
/// args of the call writing `saved_words`.
///
/// # Errors
///
/// The record cannot be read, its call parked on no ask, or the compare
/// cannot read the request, a call's args or base custody's values.
pub fn parked_note_resumed(
    vault: &Vault,
    run: EntityId,
    agent: EntityId,
    saved_words: &str,
    words: &str,
) -> Result<bool> {
    let row = vault
        .get_code_run_replay_record(&run)?
        .and_then(|record| record.bridge_calls.into_iter().next())
        .ok_or(Error::CorruptedIndex("the parked run has no stored call"))?;
    let read: BaseKnownRead<'_> = &|| vault.known_values_now();
    let saved = note_call(agent, saved_words);
    parked_note_resumed_for_test(&row, &note_call(agent, words), read, &saved)?
        .ok_or(Error::CorruptedIndex("the stored call parked on no ask"))
}
