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
    CodeRunReplayRecord, CodeRunStepCheckpoint, ExecutorStorage, encode_code_run_replay_value,
};
use crate::dreamer_wake::{BudgetLegibilityEnvelope, WakePassDeadline, current_legibility};
use crate::facade::WitnessReceipt;
use crate::llm::BudgetGuard;
use crate::off_record::{ExecutorUtterance, OffRecordSession};
use crate::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, Error,
    FinishReason, GatedActorWrite, LlmBackend, LlmError, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelId, ModelLocality, ModelTierRef, ResponseFormat, SandboxBoundaryContract,
    SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestTier, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfDispatcher, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfFailedResult, TierPrecedence, Vault,
};
use crate::{Result, code_sandbox::PLAIN_JS_HOST_VERB_DTS};
use crate::{
    code_sandbox::SANDBOX_WIT_WORLD_NAME,
    entity_id::{EntityId, bytes_to_hex_lower},
};

pub const ENGINE_EXECUTOR_SOFT_STEP_LIMIT: u32 = 6;
pub const ENGINE_EXECUTOR_HARD_STEP_LIMIT: u32 = 50;
pub const ENGINE_EXECUTOR_PURPOSE_NAME: &str = "engine_native_executor";
pub const ENGINE_EXECUTOR_FALLBACK_NAME: &str = "engine_native_js_executor_v1";

const CHECKPOINT_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:v1";
const CONFIG_HASH_DOMAIN: &[u8] = b"oneiron:engine-executor-config:v1";
/// Storage-binding tags folded into the config marker (ONE-1729).
const CONFIG_BINDING_CANONICAL_TAG: &[u8] = b"storage:canonical";
const CONFIG_BINDING_SESSION_TAG: &[u8] = b"storage:off-record-session";
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

/// Reserved guest response key carrying the budget legibility envelope
/// (ONE-1305; guest-visible contract — the key name is pinned).
pub const GUEST_BUDGET_RESPONSE_KEY: &str = "budget";

/// Guest-visible response for one dispatched `self.*` bridge call: the
/// typed outcome plus the wake-pass budget legibility envelope (Some inside
/// wake passes). EVERY response returned by the dispatch chokepoint carries
/// the envelope — success, durable wait, AND the typed `Denied`/`Failed`
/// error outcomes (the run still fails after the step with the original
/// error; the guest-visible response for the failing call is this struct).
/// The runtime serializing for the guest MUST attach the envelope under
/// [`GUEST_BUDGET_RESPONSE_KEY`] — [`Self::guest_json`] is the one blessed
/// composition.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfDispatchResponse {
    pub outcome: SelfDispatchOutcome,
    pub budget: Option<BudgetLegibilityEnvelope>,
}

impl SelfDispatchResponse {
    /// Serializes a guest-facing response body with THIS response's budget
    /// envelope attached under [`GUEST_BUDGET_RESPONSE_KEY`]. Runtimes use
    /// this instead of composing the envelope by hand, so the AC "every
    /// host-call response carries budget" holds at one point.
    #[must_use]
    pub fn guest_json(&self, body: serde_json::Value) -> serde_json::Value {
        guest_response_with_budget(body, self.budget.as_ref())
    }
}

/// Inserts the budget envelope into a guest response JSON object under the
/// reserved `"budget"` key:
/// `{"remaining_units":u64,"limit_units":u64,"remaining_ms":u64,"wrap_up":bool,"finalize_by_ms":u64|null}`.
/// A non-object body is wrapped as `{"result": body}` first.
#[must_use]
pub fn guest_response_with_budget(
    body: serde_json::Value,
    budget: Option<&BudgetLegibilityEnvelope>,
) -> serde_json::Value {
    let mut object = match body {
        serde_json::Value::Object(object) => object,
        other => {
            let mut object = serde_json::Map::new();
            object.insert("result".to_owned(), other);
            object
        }
    };
    if let Some(envelope) = budget {
        let encoded = serde_json::to_value(envelope)
            .unwrap_or_else(|error| unreachable!("budget envelope is plain data: {error}"));
        object.insert(GUEST_BUDGET_RESPONSE_KEY.to_owned(), encoded);
    }
    serde_json::Value::Object(object)
}

/// Wake-pass legibility context for the executor: the ONE wake-budget
/// counter plus the pass deadline (ONE-1305).
#[derive(Clone, Copy)]
pub struct ExecutorLegibility<'a> {
    pub guard: &'a BudgetGuard,
    pub deadline: &'a WakePassDeadline,
}

impl ExecutorLegibility<'_> {
    fn envelope(&self) -> BudgetLegibilityEnvelope {
        current_legibility(&self.guard.read(), self.deadline)
    }
}

/// Host import bridge exposed to a JS runtime component.
pub trait JsCodeModeHost {
    /// Dispatches one typed `self.*` call through the host-owned traps.
    /// Every response carries the budget legibility envelope inside a wake
    /// pass (design D5: attached to EVERY host-call response) — including
    /// the typed `Denied`/`Failed` error outcomes, which return as `Ok`
    /// responses here while the executor fails the step afterwards. `Err`
    /// is reserved for infrastructure failures with no guest-visible
    /// response at all.
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse>;
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
    storage: ExecutorStorage<'a>,
    backend: &'a dyn LlmBackend,
    lease: &'a BudgetLease,
    runtime: &'a mut dyn JsCodeModeRuntime,
    gated_write: &'a GatedActorWrite<'a>,
    legibility: Option<ExecutorLegibility<'a>>,
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
            storage: ExecutorStorage::Canonical(vault),
            backend,
            lease,
            runtime,
            gated_write,
            legibility: None,
        }
    }

    /// Binds a run to an already-acquired live off-record session
    /// (ONE-1729/P4b).
    ///
    /// Every artifact this run produces — replay record, config and terminal
    /// markers, generated scripts, observations, runtime outputs, raw output
    /// bytes, and its turns — follows the session's mode-aware route: the
    /// overlay while the room is off record, ordinary base storage after the
    /// same live session flips on record. There is no executor-specific base
    /// bypass and no durable session row.
    ///
    /// The run's [`crate::off_record::SessionWriteRoute`] is captured HERE,
    /// at run entry (R-20260807-02 rider 2), which is why this constructor is
    /// fallible where the canonical one is not.
    pub fn for_off_record_session(
        session: &'a OffRecordSession<'a>,
        backend: &'a dyn LlmBackend,
        lease: &'a BudgetLease,
        runtime: &'a mut dyn JsCodeModeRuntime,
        gated_write: &'a GatedActorWrite<'a>,
    ) -> EngineExecutorResult<Self> {
        Ok(Self {
            storage: ExecutorStorage::for_session(session)?,
            backend,
            lease,
            runtime,
            gated_write,
            legibility: None,
        })
    }

    /// Configures the wake-pass legibility context: every subsequent
    /// bridge-call response carries the budget envelope (ONE-1305).
    #[must_use]
    pub fn with_legibility(mut self, legibility: ExecutorLegibility<'a>) -> Self {
        self.legibility = Some(legibility);
        self
    }

    /// Records ONE executor turn.
    ///
    /// This is a CALL SITE, not a transcript surface: the turn event is
    /// formed by ONE-1728's facade witness door, the one place conversation
    /// identity, container resolution, role tags, and session routing are
    /// decided. Nothing here mints a message schema, a `BatchOp` program, or
    /// a guest-facing transcript input, and `turn_ref` is not a parameter the
    /// executor has — turn identity comes from the session.
    ///
    /// A CANONICAL run materializes no transcript (`Ok(None)`); on-record
    /// executor transcripts are not this ticket's work, which is what keeps
    /// the of060 fitness pin at zero diff.
    ///
    /// # Errors
    ///
    /// Propagates the session's typed refusals, including the stale-route
    /// family when the room flipped mode after this run's entry.
    pub fn witness_turn(
        &self,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Ok(None);
        };
        Ok(Some(binding.witness_executor_turn(
            kind,
            text,
            occurred_at,
            self.gated_write.actor(),
        )?))
    }

    /// Refuses a mismatched storage/dispatcher pair before ANY read or write.
    ///
    /// Correctness must not rest on a caller having picked the matching
    /// constructor pair, so both dimensions are checked: the session ref, and
    /// the OWNING STORE. The store check is what catches two vaults whose
    /// refs compare equal — `None == None` for a pair of canonical runs, or
    /// the same session ref entered in two different vaults.
    fn verify_storage_dispatcher_binding(&self) -> EngineExecutorResult<()> {
        if self.storage.session_ref() != self.gated_write.session_ref()
            || !std::ptr::eq(
                self.storage.store_identity(),
                self.gated_write.store_identity(),
            )
        {
            return Err(Error::InvalidConfig(
                "executor storage/dispatcher binding mismatch".to_owned(),
            )
            .into());
        }
        Ok(())
    }

    pub async fn run(
        &mut self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        self.verify_storage_dispatcher_binding()?;
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
                &self.storage,
                &mut record,
                script_output_path(completed_steps),
                &script,
            )?;

            let bridge_start = record.bridge_calls.len();
            let mut host = RecordingJsHost::new(
                self.gated_write,
                bridge_start as u64,
                config.determinism,
                self.legibility,
            );
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
            if let Some(failure) = host.hard_failure.take() {
                // The guest saw a typed Denied/Failed response (budget
                // attached) at the chokepoint; the STEP still fails with
                // the original error after persisting the bridge rows.
                let durable_wait = host.durable_wait;
                let bridge_calls = host.bridge_calls;
                if let Some(status) = self.persist_failed_step_after_bridge_calls(
                    &mut record,
                    expected_generation,
                    completed_steps,
                    &request_hash,
                    &script,
                    bridge_start,
                    bridge_calls,
                    durable_wait,
                    format!("Host bridge call failed: {failure}"),
                    config,
                )? {
                    return Ok(EngineExecutorOutcome {
                        status,
                        steps_run: steps_run + 1,
                        replay_record: record,
                    });
                }
                return Err(failure.into());
            }
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
                &self.storage,
                &mut record,
                observation_output_path(completed_steps),
                &step_outcome.observation,
            )?;
            for (path, output) in runtime_output_paths
                .into_iter()
                .zip(step_outcome.outputs.iter())
            {
                record_output(&self.storage, &mut record, path, &output.bytes)?;
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
                record_terminal_output(&self.storage, &mut record, completed_steps, status)?;
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
                )?,
                config
                    .determinism
                    .frozen_unix_ms
                    .saturating_add(completed_steps),
            )?;
            record.step_checkpoints.push(checkpoint);
            let next_generation = self
                .storage
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
            &self.storage,
            record,
            observation_output_path(completed_steps),
            &failed_outcome.observation,
        )?;
        let terminal_status = durable_wait.map(EngineExecutorStatus::Waiting);
        if let Some(status) = &terminal_status {
            record_terminal_output(&self.storage, record, completed_steps, status)?;
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
            )?,
            config
                .determinism
                .frozen_unix_ms
                .saturating_add(completed_steps),
        )?;
        record.step_checkpoints.push(checkpoint);
        self.storage
            .put_code_run_replay_record_if_generation(record, expected_generation)?;
        Ok(terminal_status)
    }

    fn load_or_create_record(
        &self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<LoadedReplayRecord> {
        if let Some(record) = self.storage.get_code_run_replay_record(&config.run_id)? {
            if record.determinism != config.determinism {
                return Err(Error::InvalidConfig(
                    "engine executor determinism changed for existing run".to_owned(),
                )
                .into());
            }
            validate_executor_config_marker(&self.storage, &record, config)?;
            let generation = Some(record.generation()?);
            let terminal_status = load_terminal_status(&self.storage, &record)?;
            return Ok(LoadedReplayRecord {
                record,
                generation,
                terminal_status,
            });
        }
        let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        record_config_marker(&self.storage, &mut record, config)?;
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
                    text: load_utf8_output(&self.storage, record, &script_output_path(seq))?,
                }],
            });
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: format!(
                        "Observation after durable step {seq}:\n{}",
                        load_utf8_output(&self.storage, record, &observation_output_path(seq))?
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
    legibility: Option<ExecutorLegibility<'a>>,
    bridge_calls: Vec<CodeRunBridgeCall>,
    durable_wait: Option<SelfDurableWait>,
    /// First hard bridge failure (gate rejection or failed audited write).
    /// The guest received a typed `Denied`/`Failed` RESPONSE for it (budget
    /// attached); the executor fails the step with this error AFTER the
    /// step returns, and later calls in the step are refused fail-closed.
    hard_failure: Option<Error>,
}

impl<'a> RecordingJsHost<'a> {
    fn new(
        gated_write: &'a GatedActorWrite<'a>,
        next_seq: u64,
        determinism: CodeRunDeterminism,
        legibility: Option<ExecutorLegibility<'a>>,
    ) -> Self {
        Self {
            gated_write,
            next_seq,
            determinism,
            legibility,
            bridge_calls: Vec::new(),
            durable_wait: None,
            hard_failure: None,
        }
    }

    fn budget(&self) -> Option<BudgetLegibilityEnvelope> {
        self.legibility.as_ref().map(ExecutorLegibility::envelope)
    }

    /// The ONE response chokepoint: every guest-visible bridge-call
    /// response — success, wait, or typed error outcome — leaves through
    /// here so the budget envelope can never be skipped.
    fn respond(&self, outcome: SelfDispatchOutcome) -> SelfDispatchResponse {
        SelfDispatchResponse {
            outcome,
            budget: self.budget(),
        }
    }
}

impl JsCodeModeHost for RecordingJsHost<'_> {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let started_at_ms = self.determinism.frozen_unix_ms.saturating_add(seq);
        if let Some(wait) = &self.durable_wait {
            let outcome = SelfDispatchOutcome::DurableWait(wait.clone());
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(outcome));
        }
        if self.hard_failure.is_some() {
            // Fail-closed after the first hard failure: no further gate
            // dispatches; the guest sees a typed Failed response (budget
            // attached) and the replay row records exactly that.
            let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: "host bridge halted after failed call".to_owned(),
            });
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(outcome));
        }
        let outcome = match self.gated_write.dispatch(call.clone()) {
            Ok(outcome) => outcome,
            Err(err) => {
                let Some(error_outcome) = dispatch_error_outcome(&call, &err) else {
                    // Infrastructure failure: no guest-visible response
                    // exists for this call at all.
                    return Err(err);
                };
                let row = CodeRunBridgeCall::record(
                    seq,
                    &call,
                    &error_outcome,
                    started_at_ms,
                    started_at_ms,
                )?;
                self.bridge_calls.push(row);
                self.hard_failure = Some(err);
                return Ok(self.respond(error_outcome));
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
        Ok(self.respond(outcome))
    }
}

fn dispatch_error_outcome(call: &SelfCall, err: &Error) -> Option<SelfDispatchOutcome> {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => Some(SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: call.effect(),
            outcome: (*outcome).to_owned(),
            reason_codes: reason_codes
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
        })),
        _ if records_failed_write_trap(call.effect()) => {
            Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: err.to_string(),
            }))
        }
        _ => None,
    }
}

fn records_failed_write_trap(effect: SelfEffect) -> bool {
    matches!(
        effect,
        SelfEffect::MemoryPutClaim | SelfEffect::MemorySupersedeClaim | SelfEffect::MemoryPutEdge
    )
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
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    config: &EngineExecutorConfig,
) -> EngineExecutorResult<()> {
    let marker = ExecutorConfigMarker {
        schema_version: REPLAY_METADATA_SCHEMA_VERSION,
        config_hash: executor_config_hash_hex(storage, config),
    };
    let text = serde_json::to_string(&marker)?;
    record_text_output(storage, record, CONFIG_OUTPUT_PATH.to_owned(), &text)
}

fn validate_executor_config_marker(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    config: &EngineExecutorConfig,
) -> EngineExecutorResult<()> {
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
    Ok(())
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

/// Binds replay identity to the STORAGE BINDING as well as the config, without
/// widening [`EngineExecutorConfig`].
///
/// Wherever the bound storage can see an existing replay record — the session
/// view is overlay ∪ base, the canonical view is base — a run under a
/// different binding refuses before it writes an output or a replay row. The
/// canonical and session tags are length-prefixed through
/// [`hash_bytes`], so a session literally named `canonical` cannot collide
/// with a canonical run.
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

fn load_terminal_status(
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
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    path: String,
    raw: &[u8],
) -> EngineExecutorResult<()> {
    if record.outputs.iter().any(|output| output.path == path) {
        return Err(Error::InvalidClaimBody("duplicate executor output path").into());
    }
    let output = CodeRunRawOutput::from_bytes(path, raw)?;
    storage.put_code_run_raw_output(&output, raw)?;
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
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    path: String,
    text: &str,
) -> EngineExecutorResult<()> {
    let raw = text_output_bytes(&path, text);
    record_output(storage, record, path, &raw)
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
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
) -> EngineExecutorResult<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    let raw = storage
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
mod tests;
