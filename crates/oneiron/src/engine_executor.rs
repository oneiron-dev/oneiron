//! Engine-native JS code-mode executor.
//!
//! This module intentionally sits above [`crate::LlmBackend`],
//! [`crate::code_sandbox`], and [`crate::code_run`]. The LLM backend generates
//! plain JavaScript, the CODE-1 sandbox runtime executes that JavaScript inside
//! the pinned component boundary, and every `self.*` import is routed through a
//! host dispatcher that records the typed bridge call in the durable replay log.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayGeneration,
    CodeRunReplayRecord, CodeRunStepCheckpoint,
};
use crate::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, Error,
    FinishReason, GatedActorWrite, LlmBackend, LlmError, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelId, ModelLocality, ModelTierRef, ResponseFormat, SandboxBoundaryContract,
    SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestTier, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfDispatcher, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    TierPrecedence, Vault,
};
use crate::{Result, code_sandbox::PLAIN_JS_HOST_VERB_DTS};
use crate::{
    code_sandbox::SANDBOX_WIT_WORLD_NAME,
    types::{EntityId, bytes_to_hex_lower},
};

pub const ENGINE_EXECUTOR_SOFT_STEP_LIMIT: u32 = 6;
pub const ENGINE_EXECUTOR_HARD_STEP_LIMIT: u32 = 50;
pub const ENGINE_EXECUTOR_PURPOSE_NAME: &str = "engine_native_executor";
pub const ENGINE_EXECUTOR_FALLBACK_NAME: &str = "engine_native_js_executor_v1";

const CHECKPOINT_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:v1";
const CONFIG_HASH_DOMAIN: &[u8] = b"oneiron:engine-executor-config:v1";
const SCRIPT_OUTPUT_DIR: &str = "executor/repl";
const TEXT_OUTPUT_PREFIX: &[u8] = b"oneiron-engine-executor-text-output-v1\n";
const CONFIG_OUTPUT_PATH: &str = "executor/repl/run.config.json";
const TERMINAL_OUTPUT_SUFFIX: &str = ".terminal.json";
const REPLAY_METADATA_SCHEMA_VERSION: u64 = 1;
const EXECUTOR_REQUIRED_HOST_IMPORTS: &[&str] = &[
    "self.memory.search",
    "self.memory.put_claim",
    "self.memory.supersede_claim",
    "self.memory.put_edge",
    "self.ask_human",
    "self.askHuman",
];

pub type EngineExecutorResult<T> = std::result::Result<T, EngineExecutorError>;

#[derive(Debug, thiserror::Error)]
pub enum EngineExecutorError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Llm(#[from] LlmError),
    #[error("executor request canonicalization failed: {0}")]
    CanonicalRequest(#[from] serde_json::Error),
}

/// Soft-yield and hard-stop limits for the durable REPL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineExecutorLimits {
    pub soft_steps: u32,
    pub hard_steps: u32,
}

impl Default for EngineExecutorLimits {
    fn default() -> Self {
        Self {
            soft_steps: ENGINE_EXECUTOR_SOFT_STEP_LIMIT,
            hard_steps: ENGINE_EXECUTOR_HARD_STEP_LIMIT,
        }
    }
}

impl EngineExecutorLimits {
    fn validate(self) -> EngineExecutorResult<()> {
        if self.soft_steps == 0 {
            return Err(Error::InvalidConfig(
                "engine executor soft step limit must be positive".to_owned(),
            )
            .into());
        }
        if self.hard_steps == 0 {
            return Err(Error::InvalidConfig(
                "engine executor hard step limit must be positive".to_owned(),
            )
            .into());
        }
        if self.soft_steps > self.hard_steps {
            return Err(Error::InvalidConfig(
                "engine executor soft step limit exceeds hard step limit".to_owned(),
            )
            .into());
        }
        if self.hard_steps > ENGINE_EXECUTOR_HARD_STEP_LIMIT {
            return Err(Error::InvalidConfig(
                "engine executor hard step limit exceeds EXEC-1 bound".to_owned(),
            )
            .into());
        }
        Ok(())
    }
}

/// One durable executor run.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineExecutorConfig {
    pub run_id: EntityId,
    pub task: String,
    pub model: ModelId,
    pub model_locality: ModelLocality,
    pub global_tier: ModelTierRef,
    pub determinism: CodeRunDeterminism,
    pub limits: EngineExecutorLimits,
}

impl EngineExecutorConfig {
    pub fn validate(&self) -> EngineExecutorResult<()> {
        if self.task.trim().is_empty() {
            return Err(
                Error::InvalidConfig("engine executor task must be non-empty".to_owned()).into(),
            );
        }
        self.limits.validate()
    }
}

/// Host import bridge exposed to a JS runtime component.
pub trait JsCodeModeHost {
    /// Dispatches one typed `self.*` call through the host-owned traps.
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchOutcome>;
}

/// Runtime seam for the CODE-1 plain-JS guest component.
pub trait JsCodeModeRuntime {
    /// Executes one generated JS REPL step inside the sandbox boundary.
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome>;
}

#[derive(Debug, Clone, Copy)]
pub struct JsCodeModeStep<'a> {
    pub run_id: EntityId,
    pub seq: u64,
    pub script: &'a str,
    pub boundary: SandboxBoundaryContract,
    pub determinism: CodeRunDeterminism,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsCodeModeOutput {
    pub path: String,
    pub bytes: Vec<u8>,
}

impl JsCodeModeOutput {
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: bytes.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsCodeModeStepOutcome {
    pub done: bool,
    pub observation: String,
    pub outputs: Vec<JsCodeModeOutput>,
}

impl JsCodeModeStepOutcome {
    #[must_use]
    pub fn pending(observation: impl Into<String>) -> Self {
        Self {
            done: false,
            observation: observation.into(),
            outputs: Vec::new(),
        }
    }

    #[must_use]
    pub fn complete(observation: impl Into<String>) -> Self {
        Self {
            done: true,
            observation: observation.into(),
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineExecutorStatus {
    Complete,
    Waiting(SelfDurableWait),
    Yielded { next_step_seq: u64 },
    HardStepLimitReached,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineExecutorOutcome {
    pub status: EngineExecutorStatus,
    pub steps_run: u32,
    pub replay_record: CodeRunReplayRecord,
}

struct LoadedReplayRecord {
    record: CodeRunReplayRecord,
    generation: Option<CodeRunReplayGeneration>,
    terminal_status: Option<EngineExecutorStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExecutorConfigMarker {
    schema_version: u64,
    config_hash: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredDurableWait {
    wait_id: String,
    effect: String,
    reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prompt: Option<String>,
}

/// Engine-native executor driver.
pub struct EngineNativeExecutor<'a> {
    vault: &'a Vault,
    backend: &'a dyn LlmBackend,
    lease: &'a BudgetLease,
    runtime: &'a mut dyn JsCodeModeRuntime,
    gated_write: &'a GatedActorWrite<'a>,
}

impl<'a> EngineNativeExecutor<'a> {
    #[must_use]
    pub fn new(
        vault: &'a Vault,
        backend: &'a dyn LlmBackend,
        lease: &'a BudgetLease,
        runtime: &'a mut dyn JsCodeModeRuntime,
        gated_write: &'a GatedActorWrite<'a>,
    ) -> Self {
        Self {
            vault,
            backend,
            lease,
            runtime,
            gated_write,
        }
    }

    pub async fn run(
        &mut self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        config.validate()?;
        let boundary = executor_boundary_contract()?;
        let loaded = self.load_or_create_record(config)?;
        if let Some(status) = loaded.terminal_status {
            return Ok(EngineExecutorOutcome {
                status,
                steps_run: 0,
                replay_record: loaded.record,
            });
        }
        let mut record = loaded.record;
        let mut expected_generation = loaded.generation;
        let mut steps_run = 0_u32;

        loop {
            let completed_steps = completed_step_count(&record)?;
            if completed_steps >= u64::from(config.limits.hard_steps) {
                return Ok(EngineExecutorOutcome {
                    status: EngineExecutorStatus::HardStepLimitReached,
                    steps_run,
                    replay_record: record,
                });
            }
            if steps_run >= config.limits.soft_steps {
                return Ok(EngineExecutorOutcome {
                    status: EngineExecutorStatus::Yielded {
                        next_step_seq: completed_steps,
                    },
                    steps_run,
                    replay_record: record,
                });
            }

            let request = self.build_llm_request(config, &record)?;
            let request_hash = request.canonical_hash()?;
            let response = self.backend.generate(request, self.lease).await?;
            let script = extract_plain_js(&response)?;
            record_text_output(
                self.vault,
                &mut record,
                script_output_path(completed_steps),
                &script,
            )?;

            let bridge_start = record.bridge_calls.len();
            let mut host =
                RecordingJsHost::new(self.gated_write, bridge_start as u64, config.determinism);
            let step = JsCodeModeStep {
                run_id: config.run_id,
                seq: completed_steps,
                script: &script,
                boundary,
                determinism: config.determinism,
            };
            let step_outcome = match self.runtime.run_step(step, &mut host) {
                Ok(outcome) => outcome,
                Err(err) => {
                    let durable_wait = host.durable_wait;
                    let bridge_calls = host.bridge_calls;
                    if !bridge_calls.is_empty()
                        && let Some(status) = self.persist_failed_step_after_bridge_calls(
                            &mut record,
                            expected_generation,
                            completed_steps,
                            &request_hash,
                            &script,
                            bridge_start,
                            bridge_calls,
                            durable_wait,
                            format!("Runtime error after host bridge calls: {err}"),
                            config,
                        )?
                    {
                        return Ok(EngineExecutorOutcome {
                            status,
                            steps_run: steps_run + 1,
                            replay_record: record,
                        });
                    }
                    return Err(err.into());
                }
            };
            let runtime_output_paths =
                match validate_runtime_outputs(&record, completed_steps, &step_outcome) {
                    Ok(paths) => paths,
                    Err(err) => {
                        let durable_wait = host.durable_wait;
                        let bridge_calls = host.bridge_calls;
                        if !bridge_calls.is_empty()
                            && let Some(status) = self.persist_failed_step_after_bridge_calls(
                                &mut record,
                                expected_generation,
                                completed_steps,
                                &request_hash,
                                &script,
                                bridge_start,
                                bridge_calls,
                                durable_wait,
                                format!(
                                    "Runtime output recording failed after host bridge calls: {err}"
                                ),
                                config,
                            )?
                        {
                            return Ok(EngineExecutorOutcome {
                                status,
                                steps_run: steps_run + 1,
                                replay_record: record,
                            });
                        }
                        return Err(err);
                    }
                };
            record.bridge_calls.extend(host.bridge_calls);
            record_text_output(
                self.vault,
                &mut record,
                observation_output_path(completed_steps),
                &step_outcome.observation,
            )?;
            for (path, output) in runtime_output_paths
                .into_iter()
                .zip(step_outcome.outputs.iter())
            {
                record_output(self.vault, &mut record, path, &output.bytes)?;
            }
            let terminal_status = host
                .durable_wait
                .clone()
                .map(EngineExecutorStatus::Waiting)
                .or({
                    if step_outcome.done {
                        Some(EngineExecutorStatus::Complete)
                    } else {
                        None
                    }
                });
            if let Some(status) = &terminal_status {
                record_terminal_output(self.vault, &mut record, completed_steps, status)?;
            }

            let checkpoint = CodeRunStepCheckpoint::new(
                completed_steps,
                checkpoint_label(completed_steps),
                step_state_hash(
                    previous_state_hash(&record),
                    completed_steps,
                    &request_hash,
                    &script,
                    &step_outcome,
                    &record.bridge_calls[bridge_start..],
                ),
                config
                    .determinism
                    .frozen_unix_ms
                    .saturating_add(completed_steps),
            )?;
            record.step_checkpoints.push(checkpoint);
            let next_generation = self
                .vault
                .put_code_run_replay_record_if_generation(&record, expected_generation)?;
            steps_run += 1;

            if let Some(status) = terminal_status {
                return Ok(EngineExecutorOutcome {
                    status,
                    steps_run,
                    replay_record: record,
                });
            }
            expected_generation = Some(next_generation);
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "failed REPL step persistence is atomic"
    )]
    fn persist_failed_step_after_bridge_calls(
        &self,
        record: &mut CodeRunReplayRecord,
        expected_generation: Option<CodeRunReplayGeneration>,
        completed_steps: u64,
        request_hash: &[u8; 32],
        script: &str,
        bridge_start: usize,
        bridge_calls: Vec<CodeRunBridgeCall>,
        durable_wait: Option<SelfDurableWait>,
        observation: String,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<Option<EngineExecutorStatus>> {
        record.bridge_calls.extend(bridge_calls);
        let failed_outcome = JsCodeModeStepOutcome::pending(observation);
        record_text_output(
            self.vault,
            record,
            observation_output_path(completed_steps),
            &failed_outcome.observation,
        )?;
        let terminal_status = durable_wait.map(EngineExecutorStatus::Waiting);
        if let Some(status) = &terminal_status {
            record_terminal_output(self.vault, record, completed_steps, status)?;
        }
        let checkpoint = CodeRunStepCheckpoint::new(
            completed_steps,
            checkpoint_label(completed_steps),
            step_state_hash(
                previous_state_hash(record),
                completed_steps,
                request_hash,
                script,
                &failed_outcome,
                &record.bridge_calls[bridge_start..],
            ),
            config
                .determinism
                .frozen_unix_ms
                .saturating_add(completed_steps),
        )?;
        record.step_checkpoints.push(checkpoint);
        self.vault
            .put_code_run_replay_record_if_generation(record, expected_generation)?;
        Ok(terminal_status)
    }

    fn load_or_create_record(
        &self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<LoadedReplayRecord> {
        if let Some(record) = self.vault.get_code_run_replay_record(&config.run_id)? {
            if record.determinism != config.determinism {
                return Err(Error::InvalidConfig(
                    "engine executor determinism changed for existing run".to_owned(),
                )
                .into());
            }
            validate_executor_config_marker(self.vault, &record, config)?;
            let generation = Some(record.generation()?);
            let terminal_status = load_terminal_status(self.vault, &record)?;
            return Ok(LoadedReplayRecord {
                record,
                generation,
                terminal_status,
            });
        }
        let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        record_config_marker(self.vault, &mut record, config)?;
        Ok(LoadedReplayRecord {
            record,
            generation: None,
            terminal_status: None,
        })
    }

    fn build_llm_request(
        &self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
    ) -> EngineExecutorResult<LlmRequest> {
        let completed_steps = completed_step_count(record)?;
        let mut messages = Vec::new();
        messages.push(LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: executor_system_prompt(),
            }],
        });
        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: format!(
                    "Run id: {}\nHard step limit: {}\nTask:\n{}",
                    config.run_id.to_hex(),
                    config.limits.hard_steps,
                    config.task
                ),
            }],
        });

        for seq in 0..completed_steps {
            messages.push(LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: load_utf8_output(self.vault, record, &script_output_path(seq))?,
                }],
            });
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: format!(
                        "Observation after durable step {seq}:\n{}",
                        load_utf8_output(self.vault, record, &observation_output_path(seq))?
                    ),
                }],
            });
        }

        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: format!(
                    "Emit plain JavaScript for durable step {completed_steps}. Return only executable JS."
                ),
            }],
        });

        Ok(LlmRequest {
            model: config.model.clone(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Other {
                    name: ENGINE_EXECUTOR_PURPOSE_NAME.to_owned(),
                },
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: ENGINE_EXECUTOR_FALLBACK_NAME.to_owned(),
                        config: Some(json!({
                            "run_id": config.run_id.to_hex(),
                            "step_seq": completed_steps,
                        })),
                    },
                },
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: config.global_tier.clone(),
                },
                response_format: ResponseFormat::Text,
                locality: config.model_locality,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}

struct RecordingJsHost<'a> {
    gated_write: &'a GatedActorWrite<'a>,
    next_seq: u64,
    determinism: CodeRunDeterminism,
    bridge_calls: Vec<CodeRunBridgeCall>,
    durable_wait: Option<SelfDurableWait>,
}

impl<'a> RecordingJsHost<'a> {
    fn new(
        gated_write: &'a GatedActorWrite<'a>,
        next_seq: u64,
        determinism: CodeRunDeterminism,
    ) -> Self {
        Self {
            gated_write,
            next_seq,
            determinism,
            bridge_calls: Vec::new(),
            durable_wait: None,
        }
    }
}

impl JsCodeModeHost for RecordingJsHost<'_> {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let started_at_ms = self.determinism.frozen_unix_ms.saturating_add(seq);
        if let Some(wait) = &self.durable_wait {
            let outcome = SelfDispatchOutcome::DurableWait(wait.clone());
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(outcome);
        }
        let outcome = match self.gated_write.dispatch(call.clone()) {
            Ok(outcome) => outcome,
            Err(err) => {
                if let Error::GateWriteRejected {
                    outcome,
                    reason_codes,
                } = &err
                {
                    let denied = SelfDispatchOutcome::Denied(SelfDeniedResult {
                        effect: call.effect(),
                        outcome: (*outcome).to_owned(),
                        reason_codes: reason_codes
                            .iter()
                            .map(|reason| (*reason).to_owned())
                            .collect(),
                    });
                    let row = CodeRunBridgeCall::record(
                        seq,
                        &call,
                        &denied,
                        started_at_ms,
                        started_at_ms,
                    )?;
                    self.bridge_calls.push(row);
                }
                return Err(err);
            }
        };
        let finished_at_ms = started_at_ms;
        let row = CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, finished_at_ms)?;
        if self.durable_wait.is_none()
            && let SelfDispatchOutcome::DurableWait(wait) = &outcome
        {
            self.durable_wait = Some(wait.clone());
        }
        self.bridge_calls.push(row);
        Ok(outcome)
    }
}

fn executor_boundary_contract() -> EngineExecutorResult<SandboxBoundaryContract> {
    let boundary = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    if boundary.guest_language() != SandboxGuestLanguage::PlainJavaScript {
        return Err(Error::InvariantViolation("executor sandbox is not plain JavaScript").into());
    }
    if boundary.component_boundary() != SandboxComponentBoundary::WasmtimeWit {
        return Err(Error::InvariantViolation("executor sandbox is not the WIT boundary").into());
    }
    if boundary.wit_world() != SANDBOX_WIT_WORLD_NAME {
        return Err(Error::InvariantViolation("executor sandbox WIT world drift").into());
    }
    for required in EXECUTOR_REQUIRED_HOST_IMPORTS {
        if !boundary
            .linked_imports()
            .iter()
            .any(|import| import.name() == *required)
        {
            return Err(Error::InvariantViolation(
                "executor sandbox missing advertised host import",
            )
            .into());
        }
    }
    Ok(boundary)
}

fn executor_system_prompt() -> String {
    format!(
        "You are Oneiron's engine-native executor.\n\
         Emit plain JavaScript only. Do not emit TypeScript, ReadScript, markdown, or prose.\n\
         The guest runs inside the CODE-1 Wasmtime WIT component boundary.\n\
         Clock and random values are host-controlled imports for replay determinism.\n\
         Use the prompt-side host verb types below as documentation only; runtime effects arrive \
         as typed host imports:\n\n{PLAIN_JS_HOST_VERB_DTS}"
    )
}

fn completed_step_count(record: &CodeRunReplayRecord) -> EngineExecutorResult<u64> {
    u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("engine executor step count").into())
}

fn previous_state_hash(record: &CodeRunReplayRecord) -> [u8; 32] {
    record
        .step_checkpoints
        .last()
        .map_or([0; 32], |checkpoint| checkpoint.state_hash)
}

fn record_config_marker(
    vault: &Vault,
    record: &mut CodeRunReplayRecord,
    config: &EngineExecutorConfig,
) -> EngineExecutorResult<()> {
    let marker = ExecutorConfigMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        config_hash: executor_config_hash_hex(config),
    };
    let text = serde_json::to_string(&marker)?;
    record_text_output(vault, record, CONFIG_OUTPUT_PATH.to_owned(), &text)
}

fn validate_executor_config_marker(
    vault: &Vault,
    record: &CodeRunReplayRecord,
    config: &EngineExecutorConfig,
) -> EngineExecutorResult<()> {
    let marker = load_config_marker(vault, record)?.ok_or_else(|| {
        Error::InvalidConfig("engine executor replay missing config marker".to_owned())
    })?;
    if marker.schema_version != REPLAY_METADATA_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(
            "engine executor replay config marker schema changed".to_owned(),
        )
        .into());
    }
    if marker.config_hash != executor_config_hash_hex(config) {
        return Err(Error::InvalidConfig(
            "engine executor config changed for existing run".to_owned(),
        )
        .into());
    }
    Ok(())
}

fn load_config_marker(
    vault: &Vault,
    record: &CodeRunReplayRecord,
) -> EngineExecutorResult<Option<ExecutorConfigMarker>> {
    if !record
        .outputs
        .iter()
        .any(|output| output.path == CONFIG_OUTPUT_PATH)
    {
        return Ok(None);
    }
    let text = load_utf8_output(vault, record, CONFIG_OUTPUT_PATH)?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("executor replay config marker").into())
}

fn executor_config_hash_hex(config: &EngineExecutorConfig) -> String {
    bytes_to_hex_lower(&executor_config_hash(config))
}

fn executor_config_hash(config: &EngineExecutorConfig) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_bytes(&mut hasher, CONFIG_HASH_DOMAIN);
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

fn record_terminal_output(
    vault: &Vault,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    status: &EngineExecutorStatus,
) -> EngineExecutorResult<()> {
    let marker = ExecutorTerminalMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        status: StoredTerminalStatus::from_executor_status(status)?,
    };
    let text = serde_json::to_string(&marker)?;
    record_text_output(vault, record, terminal_output_path(seq), &text)
}

fn load_terminal_status(
    vault: &Vault,
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
    let text = load_utf8_output(vault, record, &output.path)?;
    let marker: ExecutorTerminalMarker = serde_json::from_str(&text)
        .map_err(|_| Error::CorruptedIndex("executor replay terminal marker"))?;
    if marker.schema_version != REPLAY_METADATA_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex("executor replay terminal marker schema").into());
    }
    marker.status.into_executor_status().map(Some)
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

impl StoredDurableWait {
    fn from_wait(wait: &SelfDurableWait) -> Self {
        Self {
            wait_id: wait.wait_id.to_hex(),
            effect: wait.effect.as_str().to_owned(),
            reason: durable_wait_reason_str(wait.reason).to_owned(),
            prompt: wait.prompt.clone(),
        }
    }

    fn into_wait(self) -> EngineExecutorResult<SelfDurableWait> {
        Ok(SelfDurableWait {
            wait_id: EntityId::from_hex(&self.wait_id)?,
            effect: self_effect_from_str(&self.effect)?,
            reason: durable_wait_reason_from_str(&self.reason)?,
            prompt: self.prompt,
        })
    }
}

fn self_effect_from_str(value: &str) -> EngineExecutorResult<SelfEffect> {
    match value {
        "self.memory.search" => Ok(SelfEffect::MemorySearch),
        "self.memory.write_fixture" => Ok(SelfEffect::MemoryWriteFixture),
        "self.memory.put_claim" => Ok(SelfEffect::MemoryPutClaim),
        "self.memory.supersede_claim" => Ok(SelfEffect::MemorySupersedeClaim),
        "self.memory.put_edge" => Ok(SelfEffect::MemoryPutEdge),
        "self.ask_human" => Ok(SelfEffect::AskHuman),
        "self.fixture.destructive" => Ok(SelfEffect::DestructiveFixture),
        "self.fixture.outbound" => Ok(SelfEffect::OutboundFixture),
        _ => Err(Error::CorruptedIndex("executor replay durable wait effect").into()),
    }
}

fn durable_wait_reason_str(reason: SelfDurableWaitReason) -> &'static str {
    match reason {
        SelfDurableWaitReason::HumanInput => "human_input",
        SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        SelfDurableWaitReason::OutboundEffect => "outbound_effect",
    }
}

fn durable_wait_reason_from_str(value: &str) -> EngineExecutorResult<SelfDurableWaitReason> {
    match value {
        "human_input" => Ok(SelfDurableWaitReason::HumanInput),
        "destructive_effect" => Ok(SelfDurableWaitReason::DestructiveEffect),
        "outbound_effect" => Ok(SelfDurableWaitReason::OutboundEffect),
        _ => Err(Error::CorruptedIndex("executor replay durable wait reason").into()),
    }
}

fn step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    outcome: &JsCodeModeStepOutcome,
    bridge_calls: &[CodeRunBridgeCall],
) -> [u8; 32] {
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
    hash_u64(&mut hasher, outcome.outputs.len() as u64);
    for output in &outcome.outputs {
        hash_str(&mut hasher, &output.path);
        hash_bytes(&mut hasher, blake3::hash(&output.bytes).as_bytes());
    }
    hash_u64(&mut hasher, bridge_calls.len() as u64);
    for call in bridge_calls {
        hash_u64(&mut hasher, call.seq);
        hash_str(&mut hasher, call.effect.as_str());
        hash_str(&mut hasher, &format!("{:?}", call.request));
        hash_str(&mut hasher, &format!("{:?}", call.outcome));
    }
    *hasher.finalize().as_bytes()
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

fn extract_plain_js(response: &LlmResponse) -> EngineExecutorResult<String> {
    if response.finish_reason != FinishReason::Stop {
        return Err(Error::InvalidClaimBody("executor LLM response did not finish cleanly").into());
    }
    let text = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            ContentPart::Reasoning { .. }
            | ContentPart::ToolCall { .. }
            | ContentPart::ToolResult { .. }
            | ContentPart::Image { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidClaimBody("executor LLM response missing plain JS").into());
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("```") {
        if !lower.starts_with("```") {
            return Err(
                Error::InvalidClaimBody("executor LLM response mixed prose and JS fence").into(),
            );
        }
        return extract_single_js_fence(trimmed);
    }

    if !looks_like_plain_js(trimmed) {
        return Err(
            Error::InvalidClaimBody("executor LLM response is not executable plain JS").into(),
        );
    }

    Ok(trimmed.to_owned())
}

fn extract_single_js_fence(trimmed: &str) -> EngineExecutorResult<String> {
    let mut lines = trimmed.lines();
    let Some(first) = lines.next() else {
        return Err(Error::InvalidClaimBody("executor LLM response missing plain JS").into());
    };
    let lang = first.trim_start_matches("```").trim().to_ascii_lowercase();
    if lang == "ts" || lang == "typescript" || lang == "readscript" {
        return Err(
            Error::InvalidClaimBody("executor LLM response used a non-JS code fence").into(),
        );
    }
    if lang != "js" && lang != "javascript" {
        return Err(
            Error::InvalidClaimBody("executor LLM response used an unknown code fence").into(),
        );
    }
    let body_lines = lines.collect::<Vec<_>>();
    let Some((closing_index, _)) = body_lines
        .iter()
        .enumerate()
        .rfind(|(_, line)| line.trim() == "```")
    else {
        return Err(
            Error::InvalidClaimBody("executor LLM response has unterminated JS fence").into(),
        );
    };
    if body_lines[closing_index + 1..]
        .iter()
        .any(|line| !line.trim().is_empty())
    {
        return Err(
            Error::InvalidClaimBody("executor LLM response had prose after JS fence").into(),
        );
    }
    let code = body_lines[..closing_index].join("\n");
    if code.contains("```") {
        return Err(
            Error::InvalidClaimBody("executor LLM response used multiple code fences").into(),
        );
    }
    let code = code.trim();
    if code.is_empty() {
        return Err(Error::InvalidClaimBody("executor LLM response missing plain JS").into());
    }
    if !looks_like_plain_js(code) {
        return Err(Error::InvalidClaimBody(
            "executor JS fence did not contain executable plain JS",
        )
        .into());
    }
    Ok(code.to_owned())
}

fn looks_like_plain_js(text: &str) -> bool {
    let trimmed = text.trim_start();
    let first_line = trimmed.lines().next().unwrap_or_default().trim_start();
    [
        "await ",
        "const ",
        "let ",
        "var ",
        "if ",
        "for ",
        "while ",
        "switch ",
        "try ",
        "return ",
        "throw ",
        "function ",
        "async ",
        "class ",
        "import ",
        "export ",
        "self.",
    ]
    .iter()
    .any(|prefix| first_line.starts_with(prefix))
}

fn record_output(
    vault: &Vault,
    record: &mut CodeRunReplayRecord,
    path: String,
    raw: &[u8],
) -> EngineExecutorResult<()> {
    if record.outputs.iter().any(|output| output.path == path) {
        return Err(Error::InvalidClaimBody("duplicate executor output path").into());
    }
    let output = CodeRunRawOutput::from_bytes(path, raw)?;
    vault.put_code_run_raw_output(&output, raw)?;
    record.outputs.push(output);
    Ok(())
}

fn validate_runtime_outputs(
    record: &CodeRunReplayRecord,
    seq: u64,
    outcome: &JsCodeModeStepOutcome,
) -> EngineExecutorResult<Vec<String>> {
    let mut output_paths = BTreeSet::new();
    let mut paths = Vec::with_capacity(outcome.outputs.len());
    for (index, output) in outcome.outputs.iter().enumerate() {
        let path = runtime_output_path(seq, index, &output.path);
        if record.outputs.iter().any(|existing| existing.path == path)
            || !output_paths.insert(path.clone())
        {
            return Err(Error::InvalidClaimBody("duplicate executor output path").into());
        }
        let _ = CodeRunRawOutput::from_bytes(path.clone(), &output.bytes)?;
        paths.push(path);
    }
    Ok(paths)
}

fn record_text_output(
    vault: &Vault,
    record: &mut CodeRunReplayRecord,
    path: String,
    text: &str,
) -> EngineExecutorResult<()> {
    let raw = text_output_bytes(&path, text);
    record_output(vault, record, path, &raw)
}

fn text_output_bytes(path: &str, text: &str) -> Vec<u8> {
    let mut raw = Vec::with_capacity(TEXT_OUTPUT_PREFIX.len() + path.len() + 1 + text.len());
    raw.extend_from_slice(TEXT_OUTPUT_PREFIX);
    raw.extend_from_slice(path.as_bytes());
    raw.push(b'\n');
    raw.extend_from_slice(text.as_bytes());
    raw
}

fn decode_text_output(path: &str, raw: Vec<u8>) -> EngineExecutorResult<String> {
    let Some(rest) = raw.strip_prefix(TEXT_OUTPUT_PREFIX) else {
        return Err(Error::CorruptedIndex("executor replay text output envelope").into());
    };
    let path_header = format!("{path}\n");
    let Some(text) = rest.strip_prefix(path_header.as_bytes()) else {
        return Err(Error::CorruptedIndex("executor replay text output path").into());
    };
    String::from_utf8(text.to_vec())
        .map_err(|_| Error::InvalidClaimBody("executor replay output is not utf8").into())
}

fn load_utf8_output(
    vault: &Vault,
    record: &CodeRunReplayRecord,
    path: &str,
) -> EngineExecutorResult<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    let raw = vault
        .get_code_run_raw_output(output)?
        .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
    decode_text_output(path, raw)
}

fn script_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.generated.js")
}

fn observation_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.observation.txt")
}

fn terminal_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}{TERMINAL_OUTPUT_SUFFIX}")
}

fn is_terminal_output_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(SCRIPT_OUTPUT_DIR) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('/') else {
        return false;
    };
    let Some(seq) = rest.strip_suffix(TERMINAL_OUTPUT_SUFFIX) else {
        return false;
    };
    !seq.is_empty() && seq.bytes().all(|byte| byte.is_ascii_digit())
}

fn runtime_output_path(seq: u64, index: usize, path: &str) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}/output/{index:03}-{path}")
}

fn checkpoint_label(seq: u64) -> String {
    format!("executor.repl.step.{seq:06}")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::Future,
        pin::pin,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };

    use rmpv::Value;

    use crate::{
        BudgetLease, ClaimCandidate, ClaimSubject, ContentPart, EdgeActorClass, EdgeKind,
        FatalLlmError, FinishReason, HnswConfig, LlmGenerateFuture, LlmResponse, LlmStreamResult,
        LlmUsage, ModelId, SelfAskHumanCall, SelfDurableWaitReason, SelfEffect,
        SelfMemoryPutEdgeCall, SelfMemoryWriteFixtureCall, TimeRange, VaultConfig, WriteActor,
        types::ENTITY_TYPE_PERSON,
    };

    use super::*;

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), test_config()).expect("open vault");
        (dir, vault)
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("entity id")
    }

    fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn seed_person(vault: &Vault, seed: u8) -> EntityId {
        let id = entity(seed);
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .expect("seed person");
        id
    }

    fn gated_actor_write<'a>(vault: &'a Vault, run_ref: &str) -> GatedActorWrite<'a> {
        let actor = seed_person(vault, 0xA0);
        GatedActorWrite::new(
            vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            run_ref,
        )
        .expect("gated actor write")
    }

    fn gate_decision_count(vault: &Vault) -> usize {
        vault
            .store
            .gate_decisions(100)
            .expect("gate decisions")
            .len()
    }

    fn bridge_outcome_kind(call: &CodeRunBridgeCall) -> &str {
        let Value::Map(entries) = &call.outcome else {
            panic!("bridge outcome must be a map");
        };
        entries
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some("kind"))
                    .then(|| value.as_str().expect("outcome kind must be a string"))
            })
            .expect("bridge outcome kind")
    }

    fn model() -> ModelId {
        ModelId::new("test/executor@v1").expect("model id")
    }

    fn determinism() -> CodeRunDeterminism {
        CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32])
    }

    fn executor_config(run_id: EntityId, limits: EngineExecutorLimits) -> EngineExecutorConfig {
        EngineExecutorConfig {
            run_id,
            task: "remember the project status".to_owned(),
            model: model(),
            model_locality: ModelLocality::OwnServer,
            global_tier: ModelTierRef("executor-tier".to_owned()),
            determinism: determinism(),
            limits,
        }
    }

    fn llm_response(text: impl Into<String>) -> LlmResponse {
        llm_response_with_finish(text, FinishReason::Stop)
    }

    fn llm_response_with_finish(
        text: impl Into<String>,
        finish_reason: FinishReason,
    ) -> LlmResponse {
        LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text { text: text.into() }],
            },
            usage: LlmUsage::zero(),
            finish_reason,
        }
    }

    struct FixtureBackend {
        responses: Mutex<VecDeque<LlmResponse>>,
        requests: Mutex<Vec<LlmRequest>>,
    }

    impl FixtureBackend {
        fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(llm_response).collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl LlmBackend for FixtureBackend {
        fn generate<'a>(
            &'a self,
            request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmGenerateFuture<'a> {
            self.requests.lock().expect("requests lock").push(request);
            let text = self
                .responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .expect("fixture response");
            Box::pin(async move { Ok(text) })
        }

        fn stream<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmStreamResult<'a> {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }

    struct FixtureRuntime {
        observations: VecDeque<JsCodeModeStepOutcome>,
        calls: VecDeque<Vec<SelfCall>>,
        seen: Vec<SeenStep>,
    }

    #[derive(Debug, Clone)]
    struct SeenStep {
        seq: u64,
        script: String,
        boundary: SandboxBoundaryContract,
    }

    impl FixtureRuntime {
        fn new(observations: impl IntoIterator<Item = JsCodeModeStepOutcome>) -> Self {
            Self {
                observations: observations.into_iter().collect(),
                calls: VecDeque::new(),
                seen: Vec::new(),
            }
        }

        fn with_calls(mut self, calls: impl IntoIterator<Item = Vec<SelfCall>>) -> Self {
            self.calls = calls.into_iter().collect();
            self
        }
    }

    impl JsCodeModeRuntime for FixtureRuntime {
        fn run_step(
            &mut self,
            step: JsCodeModeStep<'_>,
            host: &mut dyn JsCodeModeHost,
        ) -> Result<JsCodeModeStepOutcome> {
            self.seen.push(SeenStep {
                seq: step.seq,
                script: step.script.to_owned(),
                boundary: step.boundary,
            });
            if let Some(calls) = self.calls.pop_front() {
                for call in calls {
                    let _ = host.dispatch_self(call)?;
                }
            }
            self.observations
                .pop_front()
                .ok_or(Error::InvariantViolation("missing fixture observation"))
        }
    }

    struct ErrorAfterCallsRuntime {
        calls: Vec<SelfCall>,
    }

    impl ErrorAfterCallsRuntime {
        fn new(calls: Vec<SelfCall>) -> Self {
            Self { calls }
        }
    }

    impl JsCodeModeRuntime for ErrorAfterCallsRuntime {
        fn run_step(
            &mut self,
            _step: JsCodeModeStep<'_>,
            host: &mut dyn JsCodeModeHost,
        ) -> Result<JsCodeModeStepOutcome> {
            for call in self.calls.drain(..) {
                let _ = host.dispatch_self(call)?;
            }
            Err(Error::InvariantViolation(
                "fixture runtime failed after bridge calls",
            ))
        }
    }

    #[test]
    fn executor_uses_llm_backend_and_plain_js_boundary() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["const answer = 42;"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let gated_write = gated_actor_write(&vault, "run-boundary");
        let config = executor_config(entity(0x81), EngineExecutorLimits::default());

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let outcome = block_on_ready(executor.run(&config)).expect("executor run");

        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(outcome.steps_run, 1);
        assert_eq!(runtime.seen.len(), 1);
        assert_eq!(runtime.seen[0].seq, 0);
        assert_eq!(runtime.seen[0].script, "const answer = 42;");
        assert_eq!(
            runtime.seen[0].boundary.guest_language(),
            SandboxGuestLanguage::PlainJavaScript
        );
        assert_eq!(
            runtime.seen[0].boundary.component_boundary(),
            SandboxComponentBoundary::WasmtimeWit
        );
        assert!(runtime.seen[0].boundary.links_write_imports());
        let linked_imports = runtime.seen[0]
            .boundary
            .linked_imports()
            .iter()
            .map(|import| import.name())
            .collect::<Vec<_>>();
        for required in EXECUTOR_REQUIRED_HOST_IMPORTS {
            assert!(
                linked_imports.contains(required),
                "executor boundary must link advertised host import {required}"
            );
        }

        let requests = backend.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].envelope.purpose,
            CallPurpose::Other {
                name: ENGINE_EXECUTOR_PURPOSE_NAME.to_owned(),
            }
        );
        assert!(matches!(
            requests[0].envelope.class,
            CallClass::Durable { .. }
        ));
        let system = text_message(&requests[0].messages[0]);
        assert!(system.contains(PLAIN_JS_HOST_VERB_DTS));
        assert!(system.contains("plain JavaScript"));
        for advertised in [
            "function search",
            "function putClaim",
            "function supersedeClaim",
            "function putEdge",
            "function askHuman",
            "function ask_human",
        ] {
            assert!(
                system.contains(advertised),
                "executor prompt must advertise linked host verb {advertised}"
            );
        }
        assert_eq!(outcome.replay_record.step_checkpoints.len(), 1);
        assert_ne!(
            outcome.replay_record.step_checkpoints[0].state_hash,
            [0; 32]
        );
        assert!(
            vault
                .get_code_run_replay_record(&config.run_id)
                .expect("load replay")
                .is_some()
        );
    }

    #[test]
    fn executor_records_self_calls_through_dispatcher_and_waits_durably() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["await self.ask_human('continue?');"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("waiting")])
            .with_calls([vec![SelfCall::AskHuman(SelfAskHumanCall::new("continue?"))]]);
        let gated_write = gated_actor_write(&vault, "run-wait");
        let config = executor_config(entity(0x82), EngineExecutorLimits::default());

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let outcome = block_on_ready(executor.run(&config)).expect("executor run");

        let EngineExecutorStatus::Waiting(wait) = outcome.status else {
            panic!("expected durable wait");
        };
        assert_eq!(wait.effect, SelfEffect::AskHuman);
        assert_eq!(wait.reason, SelfDurableWaitReason::HumanInput);
        assert_eq!(wait.prompt.as_deref(), Some("continue?"));
        assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
        assert_eq!(outcome.replay_record.bridge_calls[0].seq, 0);
        assert_eq!(
            outcome.replay_record.bridge_calls[0].effect,
            SelfEffect::AskHuman
        );
        let stored = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored replay");
        assert_eq!(stored.bridge_calls.len(), 1);
    }

    #[test]
    fn executor_blocks_later_self_calls_after_durable_wait() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["self.askHuman({ prompt: 'continue?' });"]);
        let lease = BudgetLease::for_test("executor-lease");
        let src = seed_person(&vault, 0xC1);
        let tgt = seed_person(&vault, 0xC2);
        let calls = vec![
            SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.9,
            )),
        ];
        let mut runtime =
            FixtureRuntime::new([JsCodeModeStepOutcome::pending("waiting")]).with_calls([calls]);
        let gated_write = gated_actor_write(&vault, "run-wait-barrier");
        let config = executor_config(entity(0x87), EngineExecutorLimits::default());
        let before = gate_decision_count(&vault);

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let outcome = block_on_ready(executor.run(&config)).expect("executor run");

        assert!(matches!(outcome.status, EngineExecutorStatus::Waiting(_)));
        assert_eq!(outcome.replay_record.bridge_calls.len(), 2);
        assert_eq!(
            outcome.replay_record.bridge_calls[0].effect,
            SelfEffect::AskHuman
        );
        assert_eq!(
            outcome.replay_record.bridge_calls[1].effect,
            SelfEffect::MemoryPutEdge
        );
        assert_eq!(
            gate_decision_count(&vault),
            before,
            "post-wait write must not reach GatedActorWrite"
        );
        assert!(
            vault
                .targets(&src, EdgeKind::Mentions, None)
                .expect("edge targets")
                .is_empty()
        );
    }

    #[test]
    fn executor_self_writes_route_through_gated_actor_write_trap() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["await self.memory.put_edge(src, 'mentions', tgt);"]);
        let lease = BudgetLease::for_test("executor-lease");
        let src = seed_person(&vault, 0xB1);
        let tgt = seed_person(&vault, 0xB2);
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("unreachable")])
            .with_calls([vec![SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            ))]]);
        let gated_write = gated_actor_write(&vault, "run-gated-write");
        let config = executor_config(
            entity(0x85),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 1,
            },
        );
        let before = gate_decision_count(&vault);

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let err = block_on_ready(executor.run(&config)).expect_err("pending gate rejects write");

        assert!(matches!(
            err,
            EngineExecutorError::Engine(Error::GateWriteRejected { .. })
        ));
        assert_eq!(gate_decision_count(&vault), before + 1);
        assert!(
            vault
                .targets(&src, EdgeKind::Mentions, None)
                .expect("edge targets")
                .is_empty()
        );
        let stored = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored denied-step replay");
        assert_eq!(stored.bridge_calls.len(), 1);
        assert_eq!(stored.bridge_calls[0].effect, SelfEffect::MemoryPutEdge);
        assert_eq!(bridge_outcome_kind(&stored.bridge_calls[0]), "denied");
        assert_eq!(stored.step_checkpoints.len(), 1);

        let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
        let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
        let mut retry = EngineNativeExecutor::new(
            &vault,
            &retry_backend,
            &lease,
            &mut retry_runtime,
            &gated_write,
        );
        let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
        assert_eq!(
            retry_outcome.status,
            EngineExecutorStatus::HardStepLimitReached
        );
        assert!(retry_runtime.seen.is_empty());
        assert!(
            retry_backend
                .requests
                .lock()
                .expect("requests lock")
                .is_empty()
        );
    }

    #[test]
    fn executor_persists_bridge_calls_when_runtime_errors_after_dispatch() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["await self.memory.write_fixture(claim);"]);
        let lease = BudgetLease::for_test("executor-lease");
        let subject = seed_person(&vault, 0xD1);
        let claim = entity(0xD2);
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("matcha"),
            0.8,
        );
        let mut runtime = ErrorAfterCallsRuntime::new(vec![SelfCall::MemoryWriteFixture(
            SelfMemoryWriteFixtureCall::new(claim, candidate, range(7), 8),
        )]);
        let gated_write = gated_actor_write(&vault, "run-error-after-dispatch");
        let config = executor_config(
            entity(0x8B),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 1,
            },
        );

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let err = block_on_ready(executor.run(&config)).expect_err("runtime error returned");

        assert!(matches!(
            err,
            EngineExecutorError::Engine(Error::InvariantViolation(
                "fixture runtime failed after bridge calls"
            ))
        ));
        assert!(
            vault
                .get_claim(&claim)
                .expect("load committed claim")
                .is_some(),
            "host write committed before the runtime error"
        );
        let stored = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored failed-step replay");
        assert_eq!(stored.bridge_calls.len(), 1);
        assert_eq!(
            stored.bridge_calls[0].effect,
            SelfEffect::MemoryWriteFixture
        );
        assert_eq!(stored.step_checkpoints.len(), 1);
        assert!(
            load_utf8_output(&vault, &stored, &observation_output_path(0))
                .expect("stored error observation")
                .contains("fixture runtime failed after bridge calls")
        );

        let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
        let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
        let mut retry = EngineNativeExecutor::new(
            &vault,
            &retry_backend,
            &lease,
            &mut retry_runtime,
            &gated_write,
        );
        let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
        assert_eq!(
            retry_outcome.status,
            EngineExecutorStatus::HardStepLimitReached
        );
        assert!(retry_runtime.seen.is_empty());
        assert!(
            retry_backend
                .requests
                .lock()
                .expect("requests lock")
                .is_empty()
        );
    }

    #[test]
    fn executor_persists_bridge_calls_when_output_recording_fails_after_dispatch() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["await self.memory.write_fixture(claim);"]);
        let lease = BudgetLease::for_test("executor-lease");
        let subject = seed_person(&vault, 0xD3);
        let claim = entity(0xD4);
        let candidate = ClaimCandidate::new(
            "profile.favorite_snack",
            ClaimSubject::Entity(subject),
            Value::from("senbei"),
            0.8,
        );
        let long_path = format!("{}.txt", "x".repeat(1100));
        let mut step_outcome = JsCodeModeStepOutcome::complete("done");
        step_outcome
            .outputs
            .push(JsCodeModeOutput::new(long_path, b"unreachable".to_vec()));
        let mut runtime =
            FixtureRuntime::new([step_outcome]).with_calls([vec![SelfCall::MemoryWriteFixture(
                SelfMemoryWriteFixtureCall::new(claim, candidate, range(9), 10),
            )]]);
        let gated_write = gated_actor_write(&vault, "run-output-error-after-dispatch");
        let config = executor_config(
            entity(0x8C),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 1,
            },
        );

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let err =
            block_on_ready(executor.run(&config)).expect_err("output validation error returned");

        assert!(matches!(
            err,
            EngineExecutorError::Engine(Error::InvalidCodeArtifactBody("raw output path"))
        ));
        assert!(
            vault
                .get_claim(&claim)
                .expect("load committed claim")
                .is_some(),
            "host write committed before output recording failed"
        );
        let stored = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored failed-step replay");
        assert_eq!(stored.bridge_calls.len(), 1);
        assert_eq!(
            stored.bridge_calls[0].effect,
            SelfEffect::MemoryWriteFixture
        );
        assert_eq!(stored.step_checkpoints.len(), 1);
        assert!(
            load_utf8_output(&vault, &stored, &observation_output_path(0))
                .expect("stored error observation")
                .contains("Runtime output recording failed after host bridge calls")
        );

        let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
        let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
        let mut retry = EngineNativeExecutor::new(
            &vault,
            &retry_backend,
            &lease,
            &mut retry_runtime,
            &gated_write,
        );
        let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
        assert_eq!(
            retry_outcome.status,
            EngineExecutorStatus::HardStepLimitReached
        );
        assert!(retry_runtime.seen.is_empty());
        assert!(
            retry_backend
                .requests
                .lock()
                .expect("requests lock")
                .is_empty()
        );
    }

    #[test]
    fn executor_preserves_durable_wait_when_runtime_errors_after_wait() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["await self.ask_human('continue?');"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime = ErrorAfterCallsRuntime::new(vec![SelfCall::AskHuman(
            SelfAskHumanCall::new("continue?"),
        )]);
        let gated_write = gated_actor_write(&vault, "run-wait-then-error");
        let config = executor_config(
            entity(0x8D),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 1,
            },
        );

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let outcome = block_on_ready(executor.run(&config)).expect("durable wait persists");

        let EngineExecutorStatus::Waiting(wait) = outcome.status else {
            panic!("expected durable wait");
        };
        assert_eq!(wait.effect, SelfEffect::AskHuman);
        assert_eq!(wait.reason, SelfDurableWaitReason::HumanInput);
        assert_eq!(outcome.steps_run, 1);
        let stored = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored wait replay");
        assert_eq!(stored.bridge_calls.len(), 1);
        assert_eq!(stored.step_checkpoints.len(), 1);

        let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
        let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
        let mut retry = EngineNativeExecutor::new(
            &vault,
            &retry_backend,
            &lease,
            &mut retry_runtime,
            &gated_write,
        );
        let retry_outcome = block_on_ready(retry.run(&config)).expect("retry returns wait");
        assert!(matches!(
            retry_outcome.status,
            EngineExecutorStatus::Waiting(_)
        ));
        assert_eq!(retry_outcome.steps_run, 0);
        assert!(retry_runtime.seen.is_empty());
        assert!(
            retry_backend
                .requests
                .lock()
                .expect("requests lock")
                .is_empty()
        );
    }

    #[test]
    fn executor_resumes_from_persisted_repl_record() {
        let (_dir, vault) = open_test_vault();
        let lease = BudgetLease::for_test("executor-lease");
        let config = executor_config(
            entity(0x83),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 3,
            },
        );
        let gated_write = gated_actor_write(&vault, "run-resume");

        let first_backend = FixtureBackend::new(["const first = true;"]);
        let mut first_runtime =
            FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
        let mut first = EngineNativeExecutor::new(
            &vault,
            &first_backend,
            &lease,
            &mut first_runtime,
            &gated_write,
        );
        let first_outcome = block_on_ready(first.run(&config)).expect("first run");
        assert_eq!(
            first_outcome.status,
            EngineExecutorStatus::Yielded { next_step_seq: 1 }
        );

        let second_backend = FixtureBackend::new(["const second = true;"]);
        let mut second_runtime =
            FixtureRuntime::new([JsCodeModeStepOutcome::complete("first observation")]);
        let mut second = EngineNativeExecutor::new(
            &vault,
            &second_backend,
            &lease,
            &mut second_runtime,
            &gated_write,
        );
        let second_outcome = block_on_ready(second.run(&config)).expect("second run");

        assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(second_outcome.replay_record.step_checkpoints.len(), 2);
        assert_eq!(second_runtime.seen[0].seq, 1);
        let requests = second_backend.requests.lock().expect("requests lock");
        let resumed_request = &requests[0];
        let transcript = resumed_request
            .messages
            .iter()
            .map(text_message)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(transcript.contains("const first = true;"));
        assert!(transcript.contains("first observation"));
    }

    #[test]
    fn executor_allows_resume_with_different_soft_step_budget() {
        let (_dir, vault) = open_test_vault();
        let lease = BudgetLease::for_test("executor-lease");
        let config = executor_config(
            entity(0x8E),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 3,
            },
        );
        let gated_write = gated_actor_write(&vault, "run-soft-step-resume");

        let first_backend = FixtureBackend::new(["const first = true;"]);
        let mut first_runtime =
            FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
        let mut first = EngineNativeExecutor::new(
            &vault,
            &first_backend,
            &lease,
            &mut first_runtime,
            &gated_write,
        );
        let first_outcome = block_on_ready(first.run(&config)).expect("first run");
        assert_eq!(
            first_outcome.status,
            EngineExecutorStatus::Yielded { next_step_seq: 1 }
        );

        let mut resumed_config = config.clone();
        resumed_config.limits.soft_steps = 2;
        let second_backend = FixtureBackend::new(["const second = true;"]);
        let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let mut second = EngineNativeExecutor::new(
            &vault,
            &second_backend,
            &lease,
            &mut second_runtime,
            &gated_write,
        );
        let second_outcome = block_on_ready(second.run(&resumed_config)).expect("resume run");

        assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(second_outcome.replay_record.step_checkpoints.len(), 2);
        assert_eq!(second_runtime.seen[0].seq, 1);
    }

    #[test]
    fn executor_rejects_resume_with_mismatched_config_identity() {
        let (_dir, vault) = open_test_vault();
        let lease = BudgetLease::for_test("executor-lease");
        let config = executor_config(
            entity(0x88),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 3,
            },
        );
        let gated_write = gated_actor_write(&vault, "run-config-drift");

        let first_backend = FixtureBackend::new(["const first = true;"]);
        let mut first_runtime =
            FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
        let mut first = EngineNativeExecutor::new(
            &vault,
            &first_backend,
            &lease,
            &mut first_runtime,
            &gated_write,
        );
        block_on_ready(first.run(&config)).expect("first run");

        let mut drifted = config.clone();
        drifted.task = "do a different task".to_owned();
        let second_backend = FixtureBackend::new(["const second = true;"]);
        let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let mut second = EngineNativeExecutor::new(
            &vault,
            &second_backend,
            &lease,
            &mut second_runtime,
            &gated_write,
        );
        let err = block_on_ready(second.run(&drifted)).expect_err("config drift rejected");

        assert!(matches!(
            err,
            EngineExecutorError::Engine(Error::InvalidConfig(message))
                if message == "engine executor config changed for existing run"
        ));
        assert!(second_runtime.seen.is_empty());
        assert!(
            second_backend
                .requests
                .lock()
                .expect("requests lock")
                .is_empty()
        );
    }

    #[test]
    fn executor_returns_persisted_terminal_status_without_replaying() {
        let (_dir, vault) = open_test_vault();
        let lease = BudgetLease::for_test("executor-lease");
        let config = executor_config(entity(0x89), EngineExecutorLimits::default());
        let gated_write = gated_actor_write(&vault, "run-terminal-replay");

        let first_backend = FixtureBackend::new(["const done = true;"]);
        let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let mut first = EngineNativeExecutor::new(
            &vault,
            &first_backend,
            &lease,
            &mut first_runtime,
            &gated_write,
        );
        let first_outcome = block_on_ready(first.run(&config)).expect("first run");
        assert_eq!(first_outcome.status, EngineExecutorStatus::Complete);

        let replay_backend = FixtureBackend::new(std::iter::empty::<&str>());
        let mut replay_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
        let mut replay = EngineNativeExecutor::new(
            &vault,
            &replay_backend,
            &lease,
            &mut replay_runtime,
            &gated_write,
        );
        let replay_outcome = block_on_ready(replay.run(&config)).expect("terminal replay");

        assert_eq!(replay_outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(replay_outcome.steps_run, 0);
        assert!(replay_runtime.seen.is_empty());
        assert!(
            replay_backend
                .requests
                .lock()
                .expect("requests lock")
                .is_empty()
        );
    }

    #[test]
    fn executor_ignores_runtime_outputs_that_look_like_terminal_markers() {
        let (_dir, vault) = open_test_vault();
        let lease = BudgetLease::for_test("executor-lease");
        let config = executor_config(
            entity(0x8B),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 3,
            },
        );
        let gated_write = gated_actor_write(&vault, "run-terminal-output-shadow");

        let first_backend = FixtureBackend::new(["const first = true;"]);
        let mut first_outcome = JsCodeModeStepOutcome::pending("first");
        first_outcome.outputs = vec![JsCodeModeOutput::new(
            "report.terminal.json",
            b"not a terminal marker".to_vec(),
        )];
        let mut first_runtime = FixtureRuntime::new([first_outcome]);
        let mut first = EngineNativeExecutor::new(
            &vault,
            &first_backend,
            &lease,
            &mut first_runtime,
            &gated_write,
        );
        let first_outcome = block_on_ready(first.run(&config)).expect("first run");
        assert_eq!(
            first_outcome.status,
            EngineExecutorStatus::Yielded { next_step_seq: 1 }
        );

        let second_backend = FixtureBackend::new(["const second = true;"]);
        let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let mut second = EngineNativeExecutor::new(
            &vault,
            &second_backend,
            &lease,
            &mut second_runtime,
            &gated_write,
        );
        let second_outcome = block_on_ready(second.run(&config)).expect("resume run");

        assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(second_runtime.seen.len(), 1);
        assert_eq!(second_runtime.seen[0].seq, 1);
    }

    #[test]
    fn replay_record_guard_rejects_stale_append_generation() {
        let (_dir, vault) = open_test_vault();
        let lease = BudgetLease::for_test("executor-lease");
        let config = executor_config(
            entity(0x8A),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 3,
            },
        );
        let gated_write = gated_actor_write(&vault, "run-stale-append");
        let backend = FixtureBackend::new(["const first = true;"]);
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("first")]);
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        block_on_ready(executor.run(&config)).expect("first run");

        let base = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored replay");
        let stale_generation = base.generation().expect("base generation");
        let mut winner = base.clone();
        record_text_output(
            &vault,
            &mut winner,
            "executor/repl/test-winner.txt".to_owned(),
            "winner",
        )
        .expect("winner output");
        vault
            .put_code_run_replay_record_if_generation(&winner, Some(stale_generation))
            .expect("winner append");

        let mut stale = base;
        record_text_output(
            &vault,
            &mut stale,
            "executor/repl/test-stale.txt".to_owned(),
            "stale",
        )
        .expect("stale output");
        let err = vault
            .put_code_run_replay_record_if_generation(&stale, Some(stale_generation))
            .expect_err("stale append rejected");

        assert!(matches!(err, Error::ConcurrentWrite(_)));
        let stored = vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .expect("stored replay");
        assert!(
            stored
                .outputs
                .iter()
                .any(|output| output.path == "executor/repl/test-winner.txt")
        );
        assert!(
            !stored
                .outputs
                .iter()
                .any(|output| output.path == "executor/repl/test-stale.txt")
        );
    }

    #[test]
    fn executor_retains_identical_runtime_output_bytes_under_distinct_paths() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["const done = true;"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut outcome = JsCodeModeStepOutcome::complete("done");
        outcome.outputs = vec![
            JsCodeModeOutput::new("first.txt", b"same bytes".to_vec()),
            JsCodeModeOutput::new("second.txt", b"same bytes".to_vec()),
        ];
        let mut runtime = FixtureRuntime::new([outcome]);
        let gated_write = gated_actor_write(&vault, "run-duplicate-output");
        let config = executor_config(entity(0x86), EngineExecutorLimits::default());

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let outcome = block_on_ready(executor.run(&config)).expect("executor run");

        let runtime_outputs = outcome
            .replay_record
            .outputs
            .iter()
            .filter(|output| output.path.contains("/output/"))
            .collect::<Vec<_>>();
        assert_eq!(runtime_outputs.len(), 2);
        assert_ne!(runtime_outputs[0].path, runtime_outputs[1].path);
        assert_eq!(runtime_outputs[0].handle, runtime_outputs[1].handle);
        for output in runtime_outputs {
            let raw = vault
                .get_code_run_raw_output(output)
                .expect("load raw output")
                .expect("raw output bytes");
            assert_eq!(raw, b"same bytes");
        }
    }

    #[test]
    fn extract_plain_js_accepts_only_raw_js_or_whole_response_js_fence() {
        assert_eq!(
            extract_plain_js(&llm_response("```javascript\nconst ok = true;\n```"))
                .expect("js fence"),
            "const ok = true;"
        );
        assert_eq!(
            extract_plain_js(&llm_response("await self.ask_human('continue?');")).expect("raw js"),
            "await self.ask_human('continue?');"
        );

        assert!(
            extract_plain_js(&llm_response(
                "Here is the code:\n```js\nconst answer = 42;\n```"
            ))
            .is_err()
        );
        assert!(extract_plain_js(&llm_response("I will search memory first.")).is_err());
        assert!(extract_plain_js(&llm_response("I will search memory first;")).is_err());
        assert!(
            extract_plain_js(&llm_response(
                "```js\nconst first = true;\n```\n```js\nconst second = true;\n```"
            ))
            .is_err()
        );
        assert!(
            extract_plain_js(&llm_response("```js\nconst ok = true;\n```\nThat is all.")).is_err()
        );
        assert!(
            extract_plain_js(&llm_response_with_finish(
                "const partial = true;",
                FinishReason::Length
            ))
            .is_err()
        );
    }

    #[test]
    fn step_state_hash_frames_variable_length_boundaries() {
        let request_hash = [0x11; 32];
        let left = JsCodeModeStepOutcome {
            done: false,
            observation: "observed".to_owned(),
            outputs: vec![
                JsCodeModeOutput::new("a", b"bc".to_vec()),
                JsCodeModeOutput::new("def", Vec::new()),
            ],
        };
        let right = JsCodeModeStepOutcome {
            done: false,
            observation: "observed".to_owned(),
            outputs: vec![
                JsCodeModeOutput::new("ab", b"c".to_vec()),
                JsCodeModeOutput::new("de", b"f".to_vec()),
            ],
        };

        assert_ne!(
            step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &left, &[]),
            step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &right, &[])
        );
    }

    #[test]
    fn executor_rejects_typescript_code_fence() {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["```ts\nconst answer: number = 42;\n```"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let gated_write = gated_actor_write(&vault, "run-typescript-reject");
        let config = executor_config(entity(0x84), EngineExecutorLimits::default());

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let err = block_on_ready(executor.run(&config)).expect_err("typescript fence rejected");

        assert!(matches!(
            err,
            EngineExecutorError::Engine(Error::InvalidClaimBody(
                "executor LLM response used a non-JS code fence"
            ))
        ));
        assert!(runtime.seen.is_empty());
    }

    fn text_message(message: &LlmMessage) -> String {
        message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
