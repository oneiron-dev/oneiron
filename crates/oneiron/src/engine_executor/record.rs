//! Durable replay identity: config/terminal markers, hashes, and checkpoint state.

use super::store::{
    CONFIG_OUTPUT_PATH, is_terminal_output_path, load_utf8_output, record_text_output,
    resumed_output_path, resumed_output_wait, terminal_output_path, terminal_output_seq,
};
use super::types::{EngineExecutorConfig, EngineExecutorResult, EngineExecutorStatus};
use crate::code_run::{
    CodeConsentResume, CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord,
    ExecutorStorage, ParkedWait, SelfDurableWait, SelfDurableWaitReason, SelfEffect, WaitKey,
    code_consent_resume_evidence, encode_code_run_replay_value, verify_code_consent_consumed,
    verify_parked_code_consent,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::session_overlay::RouteTarget;
use crate::{Error, ModelLocality, Vault};
use serde::{Deserialize, Serialize};

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
}

impl StoredTerminalStatus {
    fn from_executor_status(status: &EngineExecutorStatus) -> EngineExecutorResult<Self> {
        match status {
            EngineExecutorStatus::Complete => Ok(Self::Complete),
            EngineExecutorStatus::Waiting(wait) => Ok(Self::Waiting {
                wait: StoredDurableWait::from_wait(wait),
            }),
            EngineExecutorStatus::Yielded { .. } | EngineExecutorStatus::WindowFull { .. } => {
                Err(Error::InvariantViolation("non-terminal executor status marker").into())
            }
        }
    }

    fn into_executor_status(self) -> EngineExecutorResult<EngineExecutorStatus> {
        match self {
            Self::Complete => Ok(EngineExecutorStatus::Complete),
            Self::Waiting { wait } => Ok(EngineExecutorStatus::Waiting(wait.into_wait()?)),
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

const CHECKPOINT_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:v1";

/// Marks a step that ran as the JavaScript Oxc printed for its TypeScript
/// program (FIX 8276); a JavaScript step hashes no such part.
const PREPARED_SOURCE_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:prepared-source:v1";

const CONFIG_HASH_DOMAIN: &[u8] = b"oneiron:engine-executor-config:v1";

/// Storage-binding tags folded into the config marker (ONE-1729).
const CONFIG_BINDING_CANONICAL_TAG: &[u8] = b"storage:canonical";

const CONFIG_BINDING_SESSION_TAG: &[u8] = b"storage:off-record-session";

const CONFIG_ROUTE_OVERLAY_TAG: &[u8] = b"route:overlay";

const CONFIG_ROUTE_BASE_TAG: &[u8] = b"route:base";

/// Tags the digest of the approved continuation a child run was forked
/// under (FIX 3694); a run with none hashes nothing more.
const CONFIG_CONTINUATION_TAG: &[u8] = b"continuation";

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

fn executor_config_hash_hex(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> String {
    bytes_to_hex_lower(&executor_config_hash(storage, config, continuation))
}

/// Binds replay identity to storage, privacy-route target, and the executor
/// config. The resolved prompt bytes are bound BESIDE this hash, in the config
/// marker's own `prompt_fingerprint` field, so drift can gate provider work
/// without gating a terminal record's materialization.
///
/// Wherever the bound storage can see an existing replay record — the session
/// view is overlay ∪ base, the canonical view is base — a run under a
/// different binding refuses before it writes an output or replay row. Target
/// binding also refuses a same-id resume across an off-record/on-record flip:
/// the old record can point at overlay-only raw outputs and must never be
/// copied to base. The overlay's RAM-local mode generation is not identity; it
/// can reset after a process restart.
///
/// A record that lived only in an overlay evaporates at close, so a later run
/// under any binding starts fresh. That is BY DESIGN: evaporation is the
/// absence of history, not a resumable identity.
///
/// A child run forked from a failed one (FIX 3694) also binds its
/// continuation's digest, after every other input: the same run under
/// another approved note, or under none, is another identity.
fn executor_config_hash(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_bytes(&mut hasher, CONFIG_HASH_DOMAIN);
    match storage.session_ref() {
        None => hash_bytes(&mut hasher, CONFIG_BINDING_CANONICAL_TAG),
        Some(session_ref) => {
            hash_bytes(&mut hasher, CONFIG_BINDING_SESSION_TAG);
            hash_str(&mut hasher, session_ref);
        }
    }
    if let Some(target) = storage.session_route_target() {
        hash_bytes(
            &mut hasher,
            match target {
                RouteTarget::Overlay => CONFIG_ROUTE_OVERLAY_TAG,
                RouteTarget::Base => CONFIG_ROUTE_BASE_TAG,
                RouteTarget::Discard => b"discard",
            },
        );
    }
    hash_str(&mut hasher, &config.run_id.to_hex());
    hash_str(&mut hasher, &config.task);
    hash_str(&mut hasher, config.model.as_str());
    hash_str(&mut hasher, model_locality_str(config.model_locality));
    if let Some(effort) = config.seat_effort {
        hash_str(&mut hasher, &format!("seat_effort:{effort:?}"));
    }
    hash_str(&mut hasher, config.global_tier.as_str());
    hash_u64(&mut hasher, config.determinism.frozen_unix_ms);
    hash_bytes(&mut hasher, &config.determinism.rng_seed);
    if let Some(digest) = continuation {
        hash_bytes(&mut hasher, CONFIG_CONTINUATION_TAG);
        hash_bytes(&mut hasher, digest);
    }
    *hasher.finalize().as_bytes()
}

fn model_locality_str(locality: ModelLocality) -> &'static str {
    match locality {
        ModelLocality::OnDevice => "on_device",
        ModelLocality::OwnServer => "own_server",
        ModelLocality::ThirdParty => "third_party",
    }
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
        StoredTerminalStatus::Complete => Ok(None),
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
        "self.express" => Ok(SelfEffect::Express),
        "self.report_blocked" => Ok(SelfEffect::ReportBlocked),
        "self.inference_defaults.read" => Ok(SelfEffect::InferenceDefaultsRead),
        "self.inference_defaults.replace" => Ok(SelfEffect::InferenceDefaultsReplace),
        // A summary not yet made parks its call on its job's task.
        "summarize" => Ok(SelfEffect::Summarize),
        // A held `connector.call` parks on the call's ref (FIX 4380).
        "self.verbs.call" => Ok(SelfEffect::AgentVerb),
        _ => Err(Error::CorruptedIndex("executor replay durable wait effect").into()),
    }
}

pub(super) fn durable_wait_reason_str(reason: SelfDurableWaitReason) -> &'static str {
    match reason {
        SelfDurableWaitReason::HumanInput => "human_input",
        SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        SelfDurableWaitReason::OutboundEffect => "outbound_effect",
        SelfDurableWaitReason::PeerResult => "peer_result",
    }
}

pub(super) fn durable_wait_reason_from_str(
    value: &str,
) -> EngineExecutorResult<SelfDurableWaitReason> {
    match value {
        "human_input" => Ok(SelfDurableWaitReason::HumanInput),
        "destructive_effect" => Ok(SelfDurableWaitReason::DestructiveEffect),
        "outbound_effect" => Ok(SelfDurableWaitReason::OutboundEffect),
        "peer_result" => Ok(SelfDurableWaitReason::PeerResult),
        _ => Err(Error::CorruptedIndex("executor replay durable wait reason").into()),
    }
}

/// What a step's checkpoint hashes of its result: each body's BLAKE3
/// digest, which its stored manifest already carries, never the body.
pub(super) struct StepResultDigests {
    pub(super) observation: [u8; 32],
    pub(super) done: bool,
    /// Each file the step wrote, by the guest path it named.
    pub(super) outputs: Vec<(String, [u8; 32])>,
    /// Each result name the step bound, with the handle it names, in the
    /// order the step bound them.
    pub(super) bindings: Vec<(String, String)>,
}

impl StepResultDigests {
    /// The digests of a result held whole in memory.
    pub(super) fn of(observation: &str, done: bool) -> Self {
        Self {
            observation: *blake3::hash(observation.as_bytes()).as_bytes(),
            done,
            outputs: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

/// [`prepared_step_state_hash`] for a JavaScript step, which hashes no
/// preparation; every caller outside the tests passes its preparation.
#[cfg(test)]
pub(super) fn step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    result: &StepResultDigests,
    implicit_speak: Option<&str>,
    bridge_calls: &[CodeRunBridgeCall],
) -> EngineExecutorResult<[u8; 32]> {
    prepared_step_state_hash(
        previous,
        seq,
        request_hash,
        script,
        None,
        result,
        implicit_speak,
        bridge_calls,
    )
}

/// The checkpoint hash of one step, for a step whose program may have run as
/// the JavaScript Oxc printed for it (FIX 8276). `prepared` is that
/// preparation's identity (the executed JavaScript, its map and the Oxc
/// pin), hashed beside the original program; a JavaScript step has none,
/// and its hash is the one it always had.
#[expect(
    clippy::too_many_arguments,
    reason = "the checkpoint hashes every part of the step's state"
)]
pub(super) fn prepared_step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    prepared: Option<&[u8; 32]>,
    result: &StepResultDigests,
    implicit_speak: Option<&str>,
    bridge_calls: &[CodeRunBridgeCall],
) -> EngineExecutorResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hash_bytes(&mut hasher, CHECKPOINT_DOMAIN);
    hash_bytes(&mut hasher, &previous);
    hash_u64(&mut hasher, seq);
    hash_bytes(&mut hasher, request_hash);
    hash_bytes(&mut hasher, blake3::hash(script.as_bytes()).as_bytes());
    if let Some(identity) = prepared {
        hash_bytes(&mut hasher, PREPARED_SOURCE_DOMAIN);
        hash_bytes(&mut hasher, identity);
    }
    hash_bytes(&mut hasher, &result.observation);
    hash_bytes(&mut hasher, &[u8::from(result.done)]);
    hash_bytes(&mut hasher, &[u8::from(implicit_speak.is_some())]);
    if let Some(text) = implicit_speak {
        hash_bytes(&mut hasher, blake3::hash(text.as_bytes()).as_bytes());
    }
    hash_u64(&mut hasher, result.outputs.len() as u64);
    for (path, digest) in &result.outputs {
        hash_str(&mut hasher, path);
        hash_bytes(&mut hasher, digest);
    }
    hash_u64(&mut hasher, result.bindings.len() as u64);
    for (name, handle) in &result.bindings {
        hash_str(&mut hasher, name);
        hash_str(&mut hasher, handle);
    }
    hash_u64(&mut hasher, bridge_calls.len() as u64);
    for call in bridge_calls {
        hash_u64(&mut hasher, call.seq);
        hash_str(&mut hasher, call.effect.as_str());
        let request =
            encode_code_run_replay_value(&call.request, "executor bridge call request hash")?;
        let outcome =
            encode_code_run_replay_value(&call.outcome, "executor bridge call outcome hash")?;
        hash_bytes(&mut hasher, &request);
        hash_bytes(&mut hasher, &outcome);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_be_bytes());
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn hash_str(hasher: &mut blake3::Hasher, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}
