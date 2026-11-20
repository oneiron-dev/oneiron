//! Door for `tests/fenced_erase_form_past_wall.rs` (FIX
//! FENCE-ERASED-FORM-THROUGH-WALL): the record of a run whose agent is
//! gone, put in the vault or on a room's route, where the put fence erases
//! it in its writer before it lands, or of a run whose agent is live, and
//! its stored call or output read back.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use rmpv::Value;

use crate::agent_dispatch::{AgentDispatchTarget, AgentSpawnContext};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunRawOutput, CodeRunReplayRecord, ExecutorStorage, FoldAnswer,
    FoldWordRef, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfFailedResult, SelfMemoryPutClaimCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfSpawnAsk, replay_rows,
};
use crate::compaction::SelfFoldCall;
use crate::error::{Error, Result};
use crate::off_record::OffRecordSession;
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};

/// The code a failure naming the erase's cause holds as its own
/// ([`FencedCall::FailedNoteNamingErasure`]).
pub const HELD_CODE: &str = "fence fixture held code";

/// The custody record name an erased request's identity holds as written
/// ([`FencedCall::SearchErasedNaming`]).
pub const HELD_NAME: &str = "fence fixture held name";

/// The one call a fenced run makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencedCall {
    /// A memory search: its answer is a reply, which the erase takes.
    Search,
    /// A note write that failed with `note not written`: the erase keeps
    /// that outcome.
    FailedNote,
    /// A note write that failed naming the erase's cause, `response_erased`,
    /// beside a code of its own, [`HELD_CODE`]: a failure no erase writes,
    /// which the erase keeps.
    FailedNoteNamingErasure,
    /// A memory search whose request already holds the erased form, its
    /// identity naming custody record [`HELD_NAME`] as written.
    SearchErasedNaming,
    /// A fold listing whose answer copies the words of a fold whose source
    /// record is gone: the put fence takes that answer as a withdrawal's.
    WithdrawnFoldAnswer,
    /// A spawn of an agent definition whose host answered the typed
    /// `target_erased`: its row takes the erased ask marker in its ask's
    /// place at once, as the spawn fence writes both once an erase took a
    /// spawn's target (FIX 9180).
    SpawnTargetErased,
}

const QUERY: &str = "fence fixture query";

/// The path of the one output a live run writes ([`put_output_live`]).
const OUTPUT_PATH: &str = "/mnt/outputs/fence-fixture.txt";

/// A note write by `agent`.
fn note_call(agent: EntityId) -> SelfCall {
    SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        agent,
        ClaimCandidate::new(
            "note.text",
            ClaimSubject::Entity(agent),
            Value::from("a note the run kept"),
            1.0,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    ))
}

/// A memory search, and its answer: a reply.
fn search() -> (SelfCall, SelfDispatchOutcome) {
    (
        SelfCall::MemorySearch(SelfMemorySearchCall::new(QUERY, 1)),
        SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query: QUERY.to_owned(),
            results: Vec::new(),
            hooks: Vec::new(),
        }),
    )
}

/// A spawn of a new agent definition asking for a need, and the typed
/// `target_erased` its host answered.
fn spawn_target_erased() -> Result<(SelfCall, SelfDispatchOutcome)> {
    let ask: SelfSpawnAsk =
        serde_json::from_value(serde_json::json!({ "need": "fence fixture need" }))
            .map_err(|_| Error::InvalidConfig("the fixture's spawn ask".into()))?;
    Ok((
        SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
            target: Some(AgentDispatchTarget::Custom(EntityId::now())),
            context: AgentSpawnContext::default(),
            intent_key: "fence fixture spawn".to_owned(),
            ask: Some(ask),
        })),
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::TargetErased),
    ))
}

/// The marker an erase leaves in a spawn's ask once it took the spawn's
/// target, spelled as the erase spells it.
fn target_erased_ask() -> Value {
    Value::Map(vec![
        (Value::from("state"), Value::from("erased")),
        (Value::from("cause"), Value::from("target_erased")),
    ])
}

/// A request in the erased form whose identity names custody record
/// `name`, spelled as an erase spells one.
fn erased_form_naming(name: &str) -> Value {
    Value::Map(vec![
        (Value::from("state"), Value::from("erased")),
        (Value::from("cause"), Value::from("response_erased")),
        (
            Value::from("identity"),
            Value::Array(vec![
                Value::Binary(vec![1; 32]),
                Value::Binary(vec![2; 32]),
                Value::from(name),
            ]),
        ),
    ])
}

/// `call`, made by `agent`, as its row records it.
fn call_row(agent: EntityId, call: FencedCall) -> Result<CodeRunBridgeCall> {
    let failed = |call: &SelfCall, error: &str, code: Option<&str>| {
        SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: error.to_owned(),
            code: code.map(str::to_owned),
            disk_floor: None,
        })
    };
    let (made, outcome) = match call {
        FencedCall::Search | FencedCall::SearchErasedNaming => search(),
        FencedCall::FailedNote => {
            let made = note_call(agent);
            let outcome = failed(&made, "note not written", None);
            (made, outcome)
        }
        FencedCall::FailedNoteNamingErasure => {
            let made = note_call(agent);
            let outcome = failed(&made, "response_erased", Some(HELD_CODE));
            (made, outcome)
        }
        FencedCall::WithdrawnFoldAnswer => (
            SelfCall::Fold(SelfFoldCall::List),
            SelfDispatchOutcome::Fold(FoldAnswer::new(
                "{}".to_owned(),
                vec![FoldWordRef {
                    source_run: EntityId::now(),
                    fold: 0,
                    sources: vec![EntityId::now()],
                }],
            )),
        ),
        FencedCall::SpawnTargetErased => spawn_target_erased()?,
    };
    let mut row = CodeRunBridgeCall::record(0, &made, &outcome, 1, 2)?;
    if call == FencedCall::SearchErasedNaming {
        row.request = erased_form_naming(HELD_NAME);
    }
    Ok(row)
}

/// A new agent, put in the vault.
fn new_agent(vault: &Vault) -> Result<EntityId> {
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    Ok(agent)
}

/// The record of run `run` of `agent`, making `call`.
fn run_record(agent: EntityId, run: EntityId, call: FencedCall) -> Result<CodeRunReplayRecord> {
    let mut record = CodeRunReplayRecord::with_determinism(run, None);
    record.bridge_calls.push(call_row(agent, call)?);
    Ok(record)
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
    let agent = new_agent(vault)?;
    let storage = match session {
        Some(session) => ExecutorStorage::for_session(session, agent)?,
        None => ExecutorStorage::Canonical(vault),
    };
    vault.delete_entity(&agent)?;
    let run = EntityId::now();
    let record = run_record(agent, run, call)?;
    storage.put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([agent, run])
}

/// Puts, in the vault, for a new agent that stays live, the replay record
/// of a new run making `call`. The run.
///
/// # Errors
///
/// The agent cannot be put, or the record cannot be stored.
pub fn put_call_live(vault: &Vault, call: FencedCall) -> Result<EntityId> {
    let agent = new_agent(vault)?;
    let run = EntityId::now();
    let record = run_record(agent, run, call)?;
    ExecutorStorage::Canonical(vault)
        .put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok(run)
}

/// Puts, in the vault, for a new agent that stays live, the replay record
/// of a new run whose one output is `body`, stored whole under the run
/// first, so no fence erases its preview. The run.
///
/// # Errors
///
/// The agent or the body cannot be put, or the record cannot be stored.
pub fn put_output_live(vault: &Vault, body: &[u8]) -> Result<EntityId> {
    let agent = new_agent(vault)?;
    let run = EntityId::now();
    let output = CodeRunRawOutput::from_bytes(OUTPUT_PATH, body)?;
    vault.put_code_run_raw_output(Some(run), &output, body)?;
    let mut record = CodeRunReplayRecord::with_determinism(run, None);
    record.outputs.push(output);
    ExecutorStorage::Canonical(vault)
        .put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok(run)
}

/// Puts, in the vault, for a new agent while it is live, the replay record
/// of a new run making `call`, so the row holds it as written; then has
/// custody take `held` in a record of its own, deletes the agent, and puts
/// the same record again, which the put fence erases in its writer before
/// it lands. The run and the custody record, in that order.
///
/// # Errors
///
/// The agent cannot be put or deleted, custody cannot take `held`, or the
/// record cannot be stored.
pub fn put_call_again_after_delete(
    vault: &Vault,
    call: FencedCall,
    held: &[u8],
) -> Result<[EntityId; 2]> {
    let agent = new_agent(vault)?;
    let storage = ExecutorStorage::Canonical(vault);
    let run = EntityId::now();
    let record = run_record(agent, run, call)?;
    storage.put_owned_code_run_replay_record(&record, None, run, agent)?;
    let custody = vault.register_test_secret("held value", held, Vec::new(), 1)?;
    vault.delete_entity(&agent)?;
    storage.put_owned_code_run_replay_record(&record, None, run, agent)?;
    Ok([run, custody])
}

/// The one call `run`'s stored record holds, in the vault or, with
/// `session`, in its room.
fn stored_call(
    vault: &Vault,
    session: Option<&OffRecordSession<'_>>,
    run: EntityId,
) -> Result<CodeRunBridgeCall> {
    let record = match session {
        Some(session) => {
            session.routed_side_read(|rtxn, read| replay_rows::get(&read, rtxn, &run))?
        }
        None => vault.get_code_run_replay_record(&run)?,
    };
    record
        .and_then(|record| record.bridge_calls.into_iter().next())
        .ok_or(Error::CorruptedIndex("the fenced run has no stored call"))
}

/// The failure the one call `run`'s stored record holds has for its
/// outcome, in the vault or, with `session`, in its room; `None` for any
/// other outcome.
fn stored_failure(
    vault: &Vault,
    session: Option<&OffRecordSession<'_>>,
    run: EntityId,
) -> Result<Option<SelfFailedResult>> {
    Ok(match stored_call(vault, session, run)?.recorded_outcome() {
        Ok(SelfDispatchOutcome::Failed(failed)) => Some(failed),
        _ => None,
    })
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
    let erased = stored_call(vault, session, run)?.request_erased();
    let error = stored_failure(vault, session, run)?.map(|failed| failed.error);
    Ok((erased, error))
}

/// The error and the code of the failure the one call `run`'s stored
/// record in the vault holds for its outcome; `None` for any other outcome.
///
/// # Errors
///
/// The record cannot be read, or holds no call.
pub fn stored_failure_reads(
    vault: &Vault,
    run: EntityId,
) -> Result<Option<(String, Option<String>)>> {
    Ok(stored_failure(vault, None, run)?.map(|failed| (failed.error, failed.code)))
}

/// The custody record names the identity of the erased request of the one
/// call `run`'s stored record in the vault holds, as the row holds them:
/// `None` when that request is not erased or its identity names none.
///
/// # Errors
///
/// The record cannot be read, or holds no call.
pub fn stored_request_custody_names(vault: &Vault, run: EntityId) -> Result<Option<Vec<String>>> {
    let call = stored_call(vault, None, run)?;
    if !call.request_erased() {
        return Ok(None);
    }
    let Value::Map(fields) = &call.request else {
        return Ok(None);
    };
    let identity = fields
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("identity")).then_some(value));
    Ok(match identity {
        Some(Value::Array(parts)) => parts.get(2..).map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        }),
        _ => None,
    })
}

/// What the one spawn call `run`'s stored record in the vault holds reads:
/// whether its ask is the marker an erase leaves once it took the spawn's
/// target (in a request that keeps its fields, or kept by an erased one),
/// and whether its answer is the typed `target_erased`.
///
/// # Errors
///
/// The record cannot be read, or holds no call.
pub fn stored_spawn_reads(vault: &Vault, run: EntityId) -> Result<(bool, bool)> {
    let call = stored_call(vault, None, run)?;
    let ask_erased = match &call.request {
        Value::Map(fields) => fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("ask") && *value == target_erased_ask()),
        _ => false,
    };
    let answer_erased = matches!(
        call.recorded_outcome(),
        Ok(SelfDispatchOutcome::AgentSpawn(
            SelfAgentSpawnResult::TargetErased
        ))
    );
    Ok((ask_erased, answer_erased))
}

/// The preview text of the one output `run`'s stored record in the vault
/// holds; `None` when it holds none.
///
/// # Errors
///
/// The record cannot be read.
pub fn stored_preview(vault: &Vault, run: EntityId) -> Result<Option<String>> {
    Ok(vault
        .get_code_run_replay_record(&run)?
        .and_then(|record| record.outputs.into_iter().next())
        .map(|output| output.preview.text))
}
