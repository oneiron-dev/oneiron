//! Durable replay identity: config/terminal markers, hashes, and checkpoint state.

use super::store::{
    CONFIG_OUTPUT_PATH, is_terminal_output_path, load_utf8_output, record_text_output,
    resumed_output_path, resumed_output_wait, terminal_output_path, terminal_output_seq,
};
use super::types::EngineExecutorError;
use super::types::{
    CallerRunInput, EngineExecutorConfig, EngineExecutorResult, EngineExecutorStatus,
};
use crate::code_run::{
    CodeConsentResume, CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage, ParkedWait,
    SelfDurableWait, SelfEffect, WaitKey, code_consent_resume_evidence,
    verify_code_consent_consumed, verify_parked_code_consent,
};
use crate::entity_id::EntityId;
use crate::{Error, Result, Vault};
use crate::{FatalLlmError, LlmError};
use serde::{Deserialize, Serialize};

mod caller_source;
mod caller_task;
mod replay_hash;
mod step_digests;
use self::caller_source::caller_source_in_txn;
pub(super) use self::caller_source::{
    caller_source_code_digest, has_caller_source, missing_caller_source_body, record_caller_source,
    refuse_caller_source_as_task, verify_caller_source,
};
pub(crate) use self::caller_task::caller_task_in_txn;
pub(super) use self::caller_task::record_caller_task;
#[cfg(test)]
pub(super) use self::replay_hash::executor_config_hash_for_binding;
use self::replay_hash::executor_config_hash_hex;
pub(super) use self::replay_hash::prepared_step_state_hash;
#[cfg(test)]
pub(super) use self::replay_hash::step_state_hash;
#[cfg(oneiron_test_support)]
pub(crate) use self::replay_hash::{executor_config_hash_for_test, step_state_hash_for_test};
pub(super) use self::step_digests::{StepEnd, StepResultDigests};

pub(super) struct LoadedReplayRecord {
    pub(super) record: CodeRunReplayRecord,
    pub(super) generation: Option<CodeRunReplayGeneration>,
    pub(super) terminal_status: Option<EngineExecutorStatus>,
    /// Whether the resolved prompt drifted from the one the record was made
    /// under; a terminal record passes with it, a resume does not.
    pub(super) prompt: PromptBinding,
}

/// The replay record's own binding evidence.
///
/// `config_hash` is RUN IDENTITY — storage binding, privacy-route target, run
/// id, task, model, determinism and limits. It is strict on every resume.
///
/// `prompt_fingerprint` is the resolved teaching bytes the run's provider work
/// was produced under. It is deliberately a SEPARATE field rather than another
/// input to the hash, because the two answer different questions: identity says
/// "this is the same run", the fingerprint says "the next provider request
/// would be asked under different instructions". Folding them together made
/// prompt drift refuse a terminal record that has no next request to make —
/// stranding a checkpointed implicit bubble that only needed materializing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExecutorConfigMarker {
    schema_version: u64,
    config_hash: String,
    prompt_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExecutorTerminalMarker {
    schema_version: u64,
    #[serde(flatten)]
    status: StoredTerminalStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StoredTerminalStatus {
    Complete,
    Waiting { wait: StoredDurableWait },
    WindowOutgrown,
}

impl StoredTerminalStatus {
    fn from_executor_status(status: &EngineExecutorStatus) -> EngineExecutorResult<Self> {
        match status {
            EngineExecutorStatus::Complete => Ok(Self::Complete),
            EngineExecutorStatus::Waiting(wait) => Ok(Self::Waiting {
                wait: StoredDurableWait::from_wait(wait),
            }),
            EngineExecutorStatus::Yielded { .. }
            | EngineExecutorStatus::WindowFull { .. }
            | EngineExecutorStatus::Paused { .. } => {
                Err(Error::InvariantViolation("non-terminal executor status marker").into())
            }
        }
    }

    fn into_executor_status(self) -> EngineExecutorResult<EngineExecutorStatus> {
        match self {
            Self::Complete => Ok(EngineExecutorStatus::Complete),
            Self::Waiting { wait } => Ok(EngineExecutorStatus::Waiting(wait.into_wait()?)),
            Self::WindowOutgrown => Err(EngineExecutorError::Llm(LlmError::Fatal(
                FatalLlmError::ContextWindowExceeded {
                    message: "this run outgrew its model's context window; start a new run"
                        .to_owned(),
                },
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredDurableWait {
    wait_id: String,
    pub(super) effect: String,
    pub(super) reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prompt: Option<String>,
}

impl StoredDurableWait {
    pub(super) fn from_wait(wait: &SelfDurableWait) -> Self {
        Self {
            wait_id: wait.wait_id.to_hex(),
            effect: wait.effect.as_str().to_owned(),
            reason: durable_wait_reason_str(wait.reason).to_owned(),
            prompt: wait.prompt.clone(),
        }
    }

    pub(super) fn into_wait(self) -> EngineExecutorResult<SelfDurableWait> {
        Ok(SelfDurableWait {
            wait_id: EntityId::from_hex(&self.wait_id)?,
            effect: self_effect_from_str(&self.effect)?,
            reason: durable_wait_reason_from_str(&self.reason)?,
            prompt: self.prompt,
        })
    }
}

pub(super) const REPLAY_METADATA_SCHEMA_VERSION: u64 = 1;

pub(super) fn completed_step_count(record: &CodeRunReplayRecord) -> EngineExecutorResult<u64> {
    u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("engine executor step count").into())
}

pub(super) fn previous_state_hash(record: &CodeRunReplayRecord) -> [u8; 32] {
    record
        .step_checkpoints
        .last()
        .map_or([0; 32], |checkpoint| checkpoint.state_hash)
}

pub(super) fn record_config_marker(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    config: &EngineExecutorConfig,
    prompt_fingerprint: &str,
    continuation: Option<&[u8; 32]>,
) -> EngineExecutorResult<()> {
    let marker = ExecutorConfigMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        config_hash: executor_config_hash_hex(storage, config, continuation),
        prompt_fingerprint: prompt_fingerprint.to_owned(),
    };
    let text = serde_json::to_string(&marker)?;
    record_text_output(storage, record, CONFIG_OUTPUT_PATH.to_owned(), &text)
}

pub(super) fn executor_config_marker_bytes(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
    prompt_fingerprint: &str,
    continuation: Option<&[u8; 32]>,
) -> EngineExecutorResult<Vec<u8>> {
    Ok(serde_json::to_vec(&ExecutorConfigMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        config_hash: executor_config_hash_hex(storage, config, continuation),
        prompt_fingerprint: prompt_fingerprint.to_owned(),
    })?)
}

/// Verifies run identity and reports whether the deployed prompt drifted.
///
/// Identity mismatch is always a refusal, before anything is read or written.
/// Prompt drift is NOT decided here: whether it refuses depends on whether the
/// resumed record still has provider or replay work to do, which only the
/// caller knows. See [`EngineNativeExecutor::load_or_create_record`].
pub(super) fn validate_executor_config_marker(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    config: &EngineExecutorConfig,
    prompt_fingerprint: &str,
    continuation: Option<&[u8; 32]>,
) -> EngineExecutorResult<PromptBinding> {
    let marker = load_config_marker(storage, record)?.ok_or_else(|| {
        Error::InvalidConfig("engine executor replay missing config marker".to_owned())
    })?;
    validate_config_marker(storage, &marker, config, prompt_fingerprint, continuation)
}

/// Validates a canonical marker in the caller's snapshot and custody guard.
pub(super) fn validate_executor_config_marker_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &CodeRunReplayRecord,
    config: &EngineExecutorConfig,
    prompt_fingerprint: &str,
    continuation: Option<&[u8; 32]>,
) -> EngineExecutorResult<PromptBinding> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == CONFIG_OUTPUT_PATH)
        .ok_or_else(|| {
            Error::InvalidConfig("engine executor replay missing config marker".to_owned())
        })?;
    let _pin = vault.pin_result_body(output.raw_blake3);
    let raw = vault
        .code_run_result_body_in_txn(txn, output)?
        .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
    let text = super::store::decode_text_output(raw)?;
    let marker: ExecutorConfigMarker = serde_json::from_str(&text)
        .map_err(|_| Error::CorruptedIndex("executor replay config marker"))?;
    validate_config_marker(
        &ExecutorStorage::Canonical(vault),
        &marker,
        config,
        prompt_fingerprint,
        continuation,
    )
}

fn validate_config_marker(
    storage: &ExecutorStorage<'_>,
    marker: &ExecutorConfigMarker,
    config: &EngineExecutorConfig,
    prompt_fingerprint: &str,
    continuation: Option<&[u8; 32]>,
) -> EngineExecutorResult<PromptBinding> {
    if marker.schema_version != REPLAY_METADATA_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(
            "engine executor replay config marker schema changed".to_owned(),
        )
        .into());
    }
    if marker.config_hash != executor_config_hash_hex(storage, config, continuation) {
        return Err(Error::InvalidConfig(
            "engine executor config changed for existing run".to_owned(),
        )
        .into());
    }
    Ok(if marker.prompt_fingerprint == prompt_fingerprint {
        PromptBinding::Unchanged
    } else {
        PromptBinding::Drifted
    })
}

/// Whether the resolved prompt bytes still match the ones this run's committed
/// provider work was produced under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PromptBinding {
    Unchanged,
    Drifted,
}

fn load_config_marker(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
) -> EngineExecutorResult<Option<ExecutorConfigMarker>> {
    if !record
        .outputs
        .iter()
        .any(|output| output.path == CONFIG_OUTPUT_PATH)
    {
        return Ok(None);
    }
    let text = load_utf8_output(storage, record, CONFIG_OUTPUT_PATH)?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("executor replay config marker").into())
}

/// The identity a canonical run was entered under, as its replay record's
/// config marker holds it (FIX 2310): read once, so a host that keeps no
/// note of a binding it chose at the run's first entry tells which of the
/// configs it could have chosen that entry took, and never decides again.
pub struct EnteredRun<'v> {
    vault: &'v Vault,
    /// `None` for a record with no marker of this schema.
    config_hash: Option<String>,
}

impl EnteredRun<'_> {
    /// Whether the run was entered under `config`: its marker binds this
    /// config's identity on canonical storage, under no continuation.
    #[must_use]
    pub fn under(&self, config: &EngineExecutorConfig) -> bool {
        self.config_hash.as_deref().is_some_and(|hash| {
            hash == executor_config_hash_hex(&ExecutorStorage::Canonical(self.vault), config, None)
        })
    }
}

/// What canonical run `run_id` was entered under; `None` when it holds no
/// replay record yet, so its first entry is still to come.
///
/// # Errors
///
/// Storage errors, and a config marker that does not decode.
pub fn entered_run(
    vault: &Vault,
    run_id: EntityId,
) -> EngineExecutorResult<Option<EnteredRun<'_>>> {
    let Some(record) = vault.get_code_run_replay_record(&run_id)? else {
        return Ok(None);
    };
    let config_hash = load_config_marker(&ExecutorStorage::Canonical(vault), &record)?
        .filter(|marker| marker.schema_version == REPLAY_METADATA_SCHEMA_VERSION)
        .map(|marker| marker.config_hash);
    Ok(Some(EnteredRun { vault, config_hash }))
}

/// A run's caller input as its record keeps it (FIX EXECUTE-CALLER-CODE): the caller's exact
/// code for a caller-source run, else the caller task for a task run. `None` when the run holds
/// no replay record yet, or is a task run that keeps no caller task. A source run whose body
/// cannot be read is refused, never read as a task run.
///
/// # Errors
///
/// Storage errors reading the record or its bodies, and [`Error::InvalidConfig`] when the
/// record holds a caller-source body that cannot be read.
pub fn caller_run_input(vault: &Vault, run_id: EntityId) -> Result<Option<CallerRunInput>> {
    let _custody = vault.store.gate_custody_read_guard()?;
    let txn = vault.store.env.read_txn()?;
    let Some(record) = vault.get_code_run_replay_record_in_txn(&txn, &run_id)? else {
        return Ok(None);
    };
    caller_run_input_in_txn(vault, &txn, &record)
}

/// [`caller_run_input`] for a record the caller already holds, in the caller's transaction.
pub(crate) fn caller_run_input_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &CodeRunReplayRecord,
) -> Result<Option<CallerRunInput>> {
    // FIX EXECUTE-CALLER-CODE: the manifest decides the mode. A source run's code is required:
    // an unreadable body is a refusal, never a fallback to a task.
    if has_caller_source(record) {
        let Some(code) = caller_source_in_txn(vault, txn, record)? else {
            return Err(missing_caller_source_body());
        };
        return Ok(Some(CallerRunInput::Source(code)));
    }
    Ok(caller_task_in_txn(vault, txn, record)?.map(CallerRunInput::Task))
}

pub(super) fn record_terminal_output(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    status: &EngineExecutorStatus,
) -> EngineExecutorResult<()> {
    let marker = ExecutorTerminalMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        status: StoredTerminalStatus::from_executor_status(status)?,
    };
    let text = serde_json::to_string(&marker)?;
    record_text_output(storage, record, terminal_output_path(seq), &text)
}

pub(super) fn record_window_outgrown_output(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
) -> EngineExecutorResult<()> {
    let marker = ExecutorTerminalMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        status: StoredTerminalStatus::WindowOutgrown,
    };
    let text = serde_json::to_string(&marker)?;
    record_text_output(storage, record, terminal_output_path(seq), &text)
}

/// Whether this canonical run's latest durable marker is terminal (Complete or WindowOutgrown),
/// observed with its record and body in the caller's transaction. A parked or resumed Waiting
/// marker never closes the run's scratchpad.
pub(crate) fn code_run_terminal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
) -> crate::Result<bool> {
    let Some(record) = vault.get_code_run_replay_record_in_txn(txn, &run)? else {
        return Ok(false);
    };
    if record.run_id != run {
        return Err(Error::CorruptedIndex("executor replay run identity"));
    }
    let Some(output) = record
        .outputs
        .iter()
        .filter(|output| is_terminal_output_path(&output.path))
        .max_by(|left, right| left.path.cmp(&right.path))
    else {
        return Ok(false);
    };
    let bytes = vault
        .code_run_result_body_in_txn(txn, output)?
        .ok_or(Error::CorruptedIndex(
            "executor replay terminal marker body",
        ))?;
    let marker: ExecutorTerminalMarker = serde_json::from_slice(&bytes)
        .map_err(|_| Error::CorruptedIndex("executor replay terminal marker"))?;
    if marker.schema_version != REPLAY_METADATA_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex(
            "executor replay terminal marker schema",
        ));
    }
    Ok(matches!(
        marker.status,
        StoredTerminalStatus::Complete | StoredTerminalStatus::WindowOutgrown
    ))
}

/// The run's latest terminal status. A Waiting marker the run resumed from
/// is behind it: the reply its step's call came back with is in the record,
/// and the run goes on from the next step. For a code consent wait the
/// resumed reply alone is not enough: it must stand on the wait's committed
/// consumption (DOOR-079 1b), or the record is corrupt, never a wait to ask
/// again.
pub(super) fn load_terminal_status(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
) -> EngineExecutorResult<Option<EngineExecutorStatus>> {
    let Some(output) = record
        .outputs
        .iter()
        .filter(|output| is_terminal_output_path(&output.path))
        .max_by(|left, right| left.path.cmp(&right.path))
    else {
        return Ok(None);
    };
    let status = load_terminal_marker(storage, record, &output.path)?.into_executor_status()?;
    if let EngineExecutorStatus::Waiting(wait) = &status
        && let Some(seq) = terminal_output_seq(&output.path)
        && has_output(record, &resumed_output_path(seq, wait.wait_id))
    {
        verify_code_consent_resume(storage, record, seq, wait)?;
        return Ok(None);
    }
    Ok(Some(status))
}

fn load_terminal_marker(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
) -> EngineExecutorResult<StoredTerminalStatus> {
    let text = load_utf8_output(storage, record, path)?;
    let marker: ExecutorTerminalMarker = serde_json::from_str(&text)
        .map_err(|_| Error::CorruptedIndex("executor replay terminal marker"))?;
    if marker.schema_version != REPLAY_METADATA_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex("executor replay terminal marker schema").into());
    }
    Ok(marker.status)
}

fn has_output(record: &CodeRunReplayRecord, path: &str) -> bool {
    record.outputs.iter().any(|output| output.path == path)
}

/// The wait step `seq` parked on, from its Waiting marker; `None` when the
/// step left none.
pub(super) fn parked_wait_at(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    seq: u64,
) -> EngineExecutorResult<Option<SelfDurableWait>> {
    let path = terminal_output_path(seq);
    if !has_output(record, &path) {
        return Ok(None);
    }
    match load_terminal_marker(storage, record, &path)? {
        StoredTerminalStatus::Waiting { wait } => wait.into_wait().map(Some),
        StoredTerminalStatus::Complete | StoredTerminalStatus::WindowOutgrown => Ok(None),
    }
}

/// How many times the run already resumed from `wait_id`: the resumed
/// replies in its record that name the wait.
pub(super) fn wait_generation(record: &CodeRunReplayRecord, wait_id: EntityId) -> u64 {
    let wait = wait_id.to_hex();
    record
        .outputs
        .iter()
        .filter(|output| resumed_output_wait(&output.path).is_some_and(|(_, named)| named == wait))
        .count() as u64
}

/// The key a run parked on `wait` is delivered under.
pub(super) fn wait_key(record: &CodeRunReplayRecord, wait: &SelfDurableWait) -> WaitKey {
    WaitKey {
        run: record.run_id,
        wait_id: wait.wait_id,
        generation: wait_generation(record, wait.wait_id),
    }
}

/// The wait the run `record` holds is parked on now, read through the
/// storage its rows are in, and the key its reply is delivered under:
/// `None` once it resumed from its latest wait, or never parked (FIX 4284).
/// It reads the record's latest terminal marker as an entry of the run
/// does, and enters nothing.
pub(crate) fn parked_wait_now(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
) -> EngineExecutorResult<Option<(WaitKey, SelfDurableWait)>> {
    match load_terminal_status(storage, record) {
        Ok(Some(EngineExecutorStatus::Waiting(wait))) => Ok(Some((wait_key(record, &wait), wait))),
        Ok(_) => Ok(None),
        Err(EngineExecutorError::Llm(LlmError::Fatal(FatalLlmError::ContextWindowExceeded {
            ..
        }))) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The wait a step's commit parks its run on, for the step writer's seal:
/// its key, and the step's first bridge position.
pub(super) fn parked_wait(
    record: &CodeRunReplayRecord,
    status: Option<&EngineExecutorStatus>,
    step_start: usize,
) -> Option<ParkedWait> {
    let Some(EngineExecutorStatus::Waiting(wait)) = status else {
        return None;
    };
    Some(ParkedWait {
        key: wait_key(record, wait),
        step_start: step_start as u64,
    })
}

/// Checks the code consent wait `key` names, if a control row binds it,
/// before the run parks on it (DOOR-079 1b): this run's, sealed by the step
/// that parked, at this generation. The wait is found by its row, never by
/// its reason or prompt; a room's run binds none.
pub(super) fn verify_code_consent_park(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    key: &WaitKey,
) -> EngineExecutorResult<()> {
    if let ExecutorStorage::Canonical(vault) = storage {
        verify_parked_code_consent(vault, record, key)?;
    }
    Ok(())
}

/// The consent evidence the resumed result of step `seq` carries when its
/// wait `key` is a bound code consent wait (DOOR-079 1b): the binding, the
/// word, the answer and the settlement, once the seal and the settlement's
/// own delivered reply verify. `None` for any other wait.
pub(super) fn code_consent_evidence(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    key: &WaitKey,
    seq: u64,
    delivered: &str,
) -> EngineExecutorResult<Option<serde_json::Value>> {
    let ExecutorStorage::Canonical(vault) = storage else {
        return Ok(None);
    };
    let path = resumed_output_path(seq, key.wait_id);
    let resume = CodeConsentResume {
        record,
        key: *key,
        step_seq: seq,
        resumed_path: &path,
    };
    Ok(code_consent_resume_evidence(vault, &resume, delivered)?)
}

/// Verifies that the reply step `seq` resumed with stands on its code
/// consent wait's committed consumption, when a control row binds `wait`
/// (DOOR-079 1b): the matching settlement, sealed step, generation and
/// result. The marker's resume is the wait's latest, so the run resumed at
/// the generation before the record's count of it.
pub(super) fn verify_code_consent_resume(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    seq: u64,
    wait: &SelfDurableWait,
) -> EngineExecutorResult<()> {
    let ExecutorStorage::Canonical(vault) = storage else {
        return Ok(());
    };
    let path = resumed_output_path(seq, wait.wait_id);
    let key = WaitKey {
        run: record.run_id,
        wait_id: wait.wait_id,
        generation: wait_generation(record, wait.wait_id).saturating_sub(1),
    };
    let resume = CodeConsentResume {
        record,
        key,
        step_seq: seq,
        resumed_path: &path,
    };
    Ok(verify_code_consent_consumed(vault, &resume)?)
}

pub(super) fn self_effect_from_str(value: &str) -> EngineExecutorResult<SelfEffect> {
    match value {
        "self.memory.search" => Ok(SelfEffect::MemorySearch),
        "self.memory.write_fixture" => Ok(SelfEffect::MemoryWriteFixture),
        "self.memory.put_claim" => Ok(SelfEffect::MemoryPutClaim),
        "self.memory.supersede_claim" => Ok(SelfEffect::MemorySupersedeClaim),
        "self.memory.put_edge" => Ok(SelfEffect::MemoryPutEdge),
        "ask" => Ok(SelfEffect::Ask),
        "self.fixture.destructive" => Ok(SelfEffect::DestructiveFixture),
        "self.fixture.outbound" => Ok(SelfEffect::OutboundFixture),
        "agents.spawn" => Ok(SelfEffect::AgentsSpawn),
        "vault.agents.put" => Ok(SelfEffect::AgentsPut),
        "tasks.ask" => Ok(SelfEffect::TasksAsk),
        "tasks.wait" => Ok(SelfEffect::TasksWait),
        "self.tasks.delegate" => Ok(SelfEffect::TaskDelegate),
        "self.speak" => Ok(SelfEffect::Speak),
        "self.think" => Ok(SelfEffect::Think),
        "self.think.aloud" => Ok(SelfEffect::ThinkAloud),
        "self.express" => Ok(SelfEffect::Express),
        "self.report_blocked" => Ok(SelfEffect::ReportBlocked),
        "self.inference_defaults.read" => Ok(SelfEffect::InferenceDefaultsRead),
        "self.inference_defaults.replace" => Ok(SelfEffect::InferenceDefaultsReplace),
        // A summary not yet made parks its call on its job's task.
        "summarize" => Ok(SelfEffect::Summarize),
        // A held `connector.call` parks on the call's ref (FIX 4380).
        "self.verbs.call" => Ok(SelfEffect::AgentVerb),
        // A wait on a work order parks on the order's wait (pass 34 Q1).
        "vault.jobs.orders.wait" => Ok(SelfEffect::JobsOrdersWait),
        _ => Err(Error::CorruptedIndex("executor replay durable wait effect").into()),
    }
}

#[doc(hidden)]
pub(super) use oneiron_records::engine_executor::record::{
    durable_wait_reason_from_str, durable_wait_reason_str,
};
