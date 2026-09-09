//! Durable replay identity: config/terminal markers, hashes, and checkpoint state.

use super::store::{
    CONFIG_OUTPUT_PATH, is_terminal_output_path, load_utf8_output, record_text_output,
    terminal_output_path,
};
use super::types::{
    EngineExecutorConfig, EngineExecutorResult, EngineExecutorStatus, JsCodeModeStepOutcome,
};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, encode_code_run_replay_value,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::session_overlay::RouteTarget;
use crate::{Error, ModelLocality};
use serde::{Deserialize, Serialize};

pub(super) struct LoadedReplayRecord {
    pub(super) record: CodeRunReplayRecord,
    pub(super) generation: Option<CodeRunReplayGeneration>,
    pub(super) terminal_status: Option<EngineExecutorStatus>,
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
            EngineExecutorStatus::Yielded { .. } | EngineExecutorStatus::HardStepLimitReached => {
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

const CONFIG_HASH_DOMAIN: &[u8] = b"oneiron:engine-executor-config:v1";

/// Storage-binding tags folded into the config marker (ONE-1729).
const CONFIG_BINDING_CANONICAL_TAG: &[u8] = b"storage:canonical";

const CONFIG_BINDING_SESSION_TAG: &[u8] = b"storage:off-record-session";

const CONFIG_ROUTE_OVERLAY_TAG: &[u8] = b"route:overlay";

const CONFIG_ROUTE_BASE_TAG: &[u8] = b"route:base";

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
) -> EngineExecutorResult<()> {
    let marker = ExecutorConfigMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        config_hash: executor_config_hash_hex(storage, config),
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
    if marker.config_hash != executor_config_hash_hex(storage, config) {
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

fn executor_config_hash_hex(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
) -> String {
    bytes_to_hex_lower(&executor_config_hash(storage, config))
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
fn executor_config_hash(storage: &ExecutorStorage<'_>, config: &EngineExecutorConfig) -> [u8; 32] {
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
            },
        );
    }
    hash_str(&mut hasher, &config.run_id.to_hex());
    hash_str(&mut hasher, &config.task);
    hash_str(&mut hasher, config.model.as_str());
    hash_str(&mut hasher, model_locality_str(config.model_locality));
    hash_str(&mut hasher, config.global_tier.as_str());
    hash_u64(&mut hasher, config.determinism.frozen_unix_ms);
    hash_bytes(&mut hasher, &config.determinism.rng_seed);
    hash_u64(&mut hasher, u64::from(config.limits.hard_steps));
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
    let text = load_utf8_output(storage, record, &output.path)?;
    let marker: ExecutorTerminalMarker = serde_json::from_str(&text)
        .map_err(|_| Error::CorruptedIndex("executor replay terminal marker"))?;
    if marker.schema_version != REPLAY_METADATA_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex("executor replay terminal marker schema").into());
    }
    marker.status.into_executor_status().map(Some)
}

pub(super) fn self_effect_from_str(value: &str) -> EngineExecutorResult<SelfEffect> {
    match value {
        "self.memory.search" => Ok(SelfEffect::MemorySearch),
        "self.memory.write_fixture" => Ok(SelfEffect::MemoryWriteFixture),
        "self.memory.put_claim" => Ok(SelfEffect::MemoryPutClaim),
        "self.memory.supersede_claim" => Ok(SelfEffect::MemorySupersedeClaim),
        "self.memory.put_edge" => Ok(SelfEffect::MemoryPutEdge),
        "self.ask_human" => Ok(SelfEffect::AskHuman),
        "self.fixture.destructive" => Ok(SelfEffect::DestructiveFixture),
        "self.fixture.outbound" => Ok(SelfEffect::OutboundFixture),
        "self.tasks.delegate" => Ok(SelfEffect::TaskDelegate),
        "self.speak" => Ok(SelfEffect::Speak),
        "self.think" => Ok(SelfEffect::Think),
        "self.express" => Ok(SelfEffect::Express),
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

pub(super) fn step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    outcome: &JsCodeModeStepOutcome,
    implicit_speak: Option<&str>,
    bridge_calls: &[CodeRunBridgeCall],
) -> EngineExecutorResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hash_bytes(&mut hasher, CHECKPOINT_DOMAIN);
    hash_bytes(&mut hasher, &previous);
    hash_u64(&mut hasher, seq);
    hash_bytes(&mut hasher, request_hash);
    hash_bytes(&mut hasher, blake3::hash(script.as_bytes()).as_bytes());
    hash_bytes(
        &mut hasher,
        blake3::hash(outcome.observation.as_bytes()).as_bytes(),
    );
    hash_bytes(&mut hasher, &[u8::from(outcome.done)]);
    hash_bytes(&mut hasher, &[u8::from(implicit_speak.is_some())]);
    if let Some(text) = implicit_speak {
        hash_bytes(&mut hasher, blake3::hash(text.as_bytes()).as_bytes());
    }
    hash_u64(&mut hasher, outcome.outputs.len() as u64);
    for output in &outcome.outputs {
        hash_str(&mut hasher, &output.path);
        hash_bytes(&mut hasher, blake3::hash(&output.bytes).as_bytes());
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
