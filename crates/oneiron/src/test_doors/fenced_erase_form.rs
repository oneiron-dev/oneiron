//! Door for `tests/fenced_erase_form_past_wall.rs` (FIX
//! FENCE-ERASED-FORM-THROUGH-WALL): the record of a run whose agent is
//! gone, put in the vault or on a room's route, where the put fence erases
//! it in its writer before it lands, and its stored call read back.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use rmpv::Value;

use crate::code_run::{
    CodeRunBridgeCall, CodeRunReplayRecord, ExecutorStorage, SelfCall, SelfDispatchOutcome,
    SelfFailedResult, SelfMemoryPutClaimCall, SelfMemorySearchCall, SelfMemorySearchResult,
    replay_rows,
};
use crate::error::{Error, Result};
use crate::off_record::OffRecordSession;
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};

/// The one call a fenced run makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencedCall {
    /// A memory search: its answer is a reply, which the erase takes.
    Search,
    /// A note write that failed with `note not written`: the erase keeps
    /// that outcome.
    FailedNote,
}

const QUERY: &str = "fence fixture query";

/// `call`, made by `agent`, as its row records it.
fn call_row(agent: EntityId, call: FencedCall) -> Result<CodeRunBridgeCall> {
    let (call, outcome) = match call {
        FencedCall::Search => (
            SelfCall::MemorySearch(SelfMemorySearchCall::new(QUERY, 1)),
            SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
                query: QUERY.to_owned(),
                results: Vec::new(),
                hooks: Vec::new(),
            }),
        ),
        FencedCall::FailedNote => {
            let call = SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                agent,
                ClaimCandidate::new(
                    "note.text",
                    ClaimSubject::Entity(agent),
                    Value::from("a note the run kept"),
                    1.0,
                ),
                TimeRange { start: 1, end: 1 },
                1,
            ));
            let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: "note not written".to_owned(),
                code: None,
                disk_floor: None,
            });
            (call, outcome)
        }
    };
    CodeRunBridgeCall::record(0, &call, &outcome, 1, 2)
}

/// Puts, for a new agent deleted first, the replay record of a new run
/// making `call`, in the vault or, with `session`, on that session's write
/// route (the run is bound to the room before the delete): the put fence
/// erases it in its writer before it lands. The agent and the run, in that
/// order.
///
/// # Errors
///
/// The agent cannot be put or deleted, the run cannot be bound to the
/// room, or the record cannot be stored.
pub fn put_call_after_delete(
    vault: &Vault,
    session: Option<&OffRecordSession<'_>>,
    call: FencedCall,
) -> Result<[EntityId; 2]> {
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let storage = match session {
        Some(session) => ExecutorStorage::for_session(session, agent)?,
        None => ExecutorStorage::Canonical(vault),
    };
    vault.delete_entity(&agent)?;
    let run = EntityId::now();
    let mut record = CodeRunReplayRecord::with_determinism(run, None);
    record.bridge_calls.push(call_row(agent, call)?);
    storage.put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([agent, run])
}

/// What the one call `run`'s stored record holds reads, in the vault or,
/// with `session`, in its room: whether its request is erased, and the
/// error of its outcome when that is a failure.
///
/// # Errors
///
/// The record cannot be read, or holds no call.
pub fn stored_call_reads(
    vault: &Vault,
    session: Option<&OffRecordSession<'_>>,
    run: EntityId,
) -> Result<(bool, Option<String>)> {
    let record = match session {
        Some(session) => {
            session.routed_side_read(|rtxn, read| replay_rows::get(&read, rtxn, &run))?
        }
        None => vault.get_code_run_replay_record(&run)?,
    };
    let call = record
        .and_then(|record| record.bridge_calls.into_iter().next())
        .ok_or(Error::CorruptedIndex("the fenced run has no stored call"))?;
    let error = match call.recorded_outcome() {
        Ok(SelfDispatchOutcome::Failed(failed)) => Some(failed.error),
        _ => None,
    };
    Ok((call.request_erased(), error))
}
