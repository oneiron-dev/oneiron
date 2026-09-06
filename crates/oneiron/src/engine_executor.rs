//! Engine-native JS code-mode executor.
//!
//! This module intentionally sits above [`crate::LlmBackend`],
//! [`crate::code_sandbox`], and [`crate::code_run`]. The LLM backend generates
//! plain JavaScript, the CODE-1 sandbox runtime executes that JavaScript inside
//! the pinned component boundary, and every `self.*` import is routed through a
//! host dispatcher that records the typed bridge call in the durable replay log.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::code_run::{
    CODE_RUN_CONSOLE_CLOSE, CODE_RUN_CONSOLE_OPEN, CODE_RUN_EXEC_CLOSE, CODE_RUN_EXEC_OPEN,
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunHistoryTurn, CodeRunRawOutput,
    CodeRunReplayGeneration, CodeRunReplayRecord, CodeRunStepCheckpoint, ExecutorStorage,
    encode_code_run_replay_value,
};
use crate::dreamer_wake::{BudgetLegibilityEnvelope, WakePassDeadline, current_legibility};
use crate::llm::BudgetGuard;
use crate::memory::WitnessReceipt;
use crate::off_record::{ExecutorUtterance, OffRecordSession};
use crate::prompt::resolve_engine_executor_wire_prompt;
use crate::session_overlay::RouteTarget;
use crate::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, Error,
    FinishReason, LlmBackend, LlmError, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
    code_run::GatedActorWrite, code_run::SelfCall, code_run::SelfDeniedResult,
    code_run::SelfDispatchOutcome, code_run::SelfDurableWait, code_run::SelfDurableWaitReason,
    code_run::SelfEffect, code_run::SelfFailedResult, code_sandbox::SandboxBoundaryContract,
    code_sandbox::SandboxComponentBoundary, code_sandbox::SandboxGuestLanguage,
    code_sandbox::SandboxGuestTier,
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
const CONFIG_ROUTE_OVERLAY_TAG: &[u8] = b"route:overlay";
const CONFIG_ROUTE_BASE_TAG: &[u8] = b"route:base";
const SCRIPT_OUTPUT_DIR: &str = "executor/repl";
const TEXT_OUTPUT_PREFIX: &[u8] = b"oneiron-engine-executor-text-output-v1\n";
const CONFIG_OUTPUT_PATH: &str = "executor/repl/run.config.json";
const TERMINAL_OUTPUT_SUFFIX: &str = ".terminal.json";
/// ONE-1686: the trailing-plaintext fallback's durable emission marker. A
/// SIBLING suffix of the terminal marker, never the same one:
/// `is_terminal_output_path` must not read it as a terminal status.
const FALLBACK_SPEECH_MARKER_SUFFIX: &str = ".fallback-speech.json";
const REPLAY_METADATA_SCHEMA_VERSION: u64 = 1;
const EXECUTOR_REQUIRED_HOST_IMPORTS: &[&str] = &[
    "self.memory.search",
    "self.memory.put_claim",
    "self.memory.supersede_claim",
    "self.memory.put_edge",
    "self.ask_human",
    "self.askHuman",
    "self.speak",
    "self.think",
    "self.express",
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
    /// Root of the deployed canonical non-Rust prompt package. Making this a
    /// required run input keeps registry/relocated builds independent of the
    /// source checkout that compiled the crate.
    pub prompt_package_root: PathBuf,
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
    /// Next order for the public compatibility witness door, whose callers do
    /// not have an [`EngineExecutorConfig`] run id. Explicit-order witnesses
    /// bypass this allocator and retain their exact order.
    next_witness_order: AtomicU32,
    /// TEST-ONLY (ONE-1929): fails the run once at the moment BETWEEN the
    /// terminal replay commit and the implicit bubble, which is the exact
    /// window the checkpointed payload exists to survive.
    #[cfg(test)]
    fail_before_implicit_speak_once: bool,
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
            next_witness_order: AtomicU32::new(0),
            #[cfg(test)]
            fail_before_implicit_speak_once: false,
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
    /// The run's `crate::off_record::SessionWriteRoute` is captured HERE,
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
            next_witness_order: AtomicU32::new(0),
            #[cfg(test)]
            fail_before_implicit_speak_once: false,
        })
    }

    /// Configures the wake-pass legibility context: every subsequent
    /// bridge-call response carries the budget envelope (ONE-1305).
    #[must_use]
    pub fn with_legibility(mut self, legibility: ExecutorLegibility<'a>) -> Self {
        self.legibility = Some(legibility);
        self
    }

    #[cfg(test)]
    fn fail_before_implicit_speak_once_for_test(&mut self) {
        self.fail_before_implicit_speak_once = true;
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
    /// BOTH storage arms materialize the bubble (ONE-1686): a canonical run
    /// witnesses into the run-scoped shell its dispatcher's run ref derives,
    /// a session-bound run into the room's captured shell. The `Option` is
    /// kept for API compatibility and is now always `Some` on success — a
    /// receipt is the proof that speech happened.
    ///
    /// This is a WRITE-CAPABLE entry point, so it verifies the same
    /// storage/dispatcher binding [`Self::run`] does, before it reads or
    /// writes anything: a mismatched pair that never calls `run` would
    /// otherwise land a turn through one binding's session under the other's
    /// actor.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidConfig` for a mismatched storage/dispatcher
    /// pair, and propagates the witness door's typed refusals — the ONE-1686
    /// approval ceiling and the stale-route family when the room flipped mode
    /// after this run's entry.
    pub fn witness_turn(
        &self,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        let order = self.allocate_witness_order()?;
        self.witness_turn_at(kind, text, occurred_at, order)
    }

    /// [`Self::witness_turn`], carrying an explicit bubble `order`.
    ///
    /// The order is the emitter's position in the run's bridge ordering, so a
    /// turn recorded outside the bridge can still be placed against the calls
    /// it follows. It is also the bubble's IDENTITY input: the storage door
    /// derives the MESSAGE id from the run identity and this order, so
    /// re-emitting the same position converges on the same row.
    ///
    /// This explicit door never advances [`Self::witness_turn`]'s compatibility
    /// allocator. Durable runtime dispatch and fallback use a private sibling
    /// that also binds [`EngineExecutorConfig::run_id`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::witness_turn`], plus `Error::InvalidConfig` when `order`
    /// exceeds the witness MESSAGE order ceiling.
    pub fn witness_turn_at(
        &self,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        self.witness_turn_for_run_at(None, kind, text, occurred_at, order)
    }

    fn allocate_witness_order(&self) -> EngineExecutorResult<u32> {
        // Relaxed ordering is sufficient: the atomic protects only uniqueness
        // of the returned integer, not publication of any other memory.
        self.next_witness_order
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |order| {
                if order > crate::gate::MAX_WITNESS_MESSAGE_ORDER {
                    None
                } else {
                    order.checked_add(1)
                }
            })
            .map_err(|_| {
                Error::InvalidConfig(
                    "engine executor compatibility witness order exhausted".to_owned(),
                )
                .into()
            })
    }

    fn witness_turn_for_run_at(
        &self,
        run_id: Option<EntityId>,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        if order > crate::gate::MAX_WITNESS_MESSAGE_ORDER {
            return Err(Error::InvalidConfig(
                "engine executor witness order exceeds the MESSAGE order ceiling".to_owned(),
            )
            .into());
        }
        self.verify_storage_dispatcher_binding()?;
        Ok(Some(self.storage.witness_executor_utterance(
            self.gated_write.run_ref(),
            run_id,
            kind,
            text,
            occurred_at,
            order,
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
        // Resolve exactly once per run attempt. Both teaching sites use these
        // bytes, and the fingerprint joins the durable replay identity below.
        let wire_prompt = resolve_engine_executor_wire_prompt(&config.prompt_package_root)
            .map_err(Error::from)?;
        let boundary = executor_boundary_contract()?;
        let loaded = self.load_or_create_record(config, &wire_prompt.stamp.resolved_fingerprint)?;
        if let Some(status) = loaded.terminal_status {
            self.recover_checkpointed_implicit_speak(&loaded.record, &status, config)?;
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

            let request = self.build_llm_request(config, &record, &wire_prompt.text)?;
            let request_hash = request.canonical_hash()?;
            let response = self.backend.generate(request, self.lease).await?;
            // ONE-1929: the ONE normalization seam. Only `code` is executed,
            // staged, hashed, or replayed; the reply's own console bytes are
            // already gone, and `trailing_speak` belongs to ONE-1686.
            let HealedExecutorReply {
                code: script,
                trailing_speak,
                repairs,
            } = heal_executor_reply(&response)?;
            record_text_output(
                &self.storage,
                &mut record,
                script_output_path(completed_steps),
                &script,
            )?;

            let bridge_start = record.bridge_calls.len();
            // ONE-1314: the DURABLE history is the load-bearing half of the
            // lineage seam. An outbound effect parks its step, so a run that
            // reached outside and then writes always spans a resume, and the
            // resuming step's only record of that hop is the replay record
            // being read here. Observed before any write of this step can
            // dispatch; the dispatcher owns the history-to-lineage mapping.
            self.gated_write
                .observe_bridge_history(&record.bridge_calls);
            let mut host = RecordingJsHost::new(
                self.gated_write,
                config.run_id,
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
                            repairs.healed(),
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
                    repairs.healed(),
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
                                repairs.healed(),
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
            let implicit_speak = matches!(terminal_status, Some(EngineExecutorStatus::Complete))
                .then(|| {
                    self.prepare_trailing_speak_fallback(
                        &record,
                        &step_outcome,
                        trailing_speak.as_deref(),
                    )
                })
                .flatten();
            if let Some(text) = implicit_speak.as_deref() {
                // The exact side-effect payload is part of the replay append,
                // not ephemeral provider state. It is content-addressed like
                // every other executor output and hashed into the checkpoint.
                record_text_output(
                    &self.storage,
                    &mut record,
                    implicit_speak_output_path(completed_steps),
                    text,
                )?;
            }
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
                    implicit_speak.as_deref(),
                    &record.bridge_calls[bridge_start..],
                )?,
                config
                    .determinism
                    .frozen_unix_ms
                    .saturating_add(completed_steps),
            )?;
            record.step_checkpoints.push(checkpoint);
            // Replay persistence and its one-per-healed-turn signal are one
            // transaction. A generation conflict, tally error, or failed
            // commit advances neither; a durable append has already counted.
            let next_generation = self
                .storage
                .put_code_run_replay_record_if_generation_with_heal(
                    &record,
                    expected_generation,
                    repairs.healed().then_some(&config.model),
                )?;
            // The implicit bubble is downstream of its checkpoint commit. A
            // compare-and-put failure emits nothing. A terminal retry replays
            // this delivery under stable witness ids, so it can recover a
            // missed emit without minting a duplicate bubble.
            if let Some(text) = implicit_speak.as_deref() {
                self.emit_trailing_speak_fallback(&record, completed_steps, text, config)?;
            }
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

    /// Selects the IMPLICIT speak payload BEFORE the terminal checkpoint
    /// (ONE-1686 policy, ONE-1929 checkpointing).
    ///
    /// # What is said
    ///
    /// A completed run's trailing plaintext becomes its last word. With
    /// bare-wire healing (ONE-1929) that plaintext is the HEALED trailing
    /// prose when the reply carried one, and the raw observation otherwise, so
    /// a model that wrapped its answer in a fence or forged a `<console>`
    /// block still speaks the words it actually meant.
    ///
    /// # What suppresses it
    ///
    /// Explicit speech is CANONICAL, and "canonical" is about the TEXT, not
    /// about whether the run happened to speak at all. A run that spoke and
    /// then finished with the SAME words has already said them, so a trailing
    /// bubble would be a duplicate; a run that spoke and then finished with
    /// DIFFERENT words has a last word nobody has heard, and dropping it loses
    /// the answer. So the suppression is per-text: the fallback is skipped only
    /// when an emitted speech row in the durable record carries exactly this
    /// trailing text. The check is over the DURABLE record, not a per-step
    /// flag, so a run that spoke in step 0 and completed in step 3 is still
    /// judged against everything it said.
    ///
    /// A speech row that did NOT emit — a barrier-parked wait, a denied or
    /// failed trap — never suppresses anything: no bubble exists for it, so
    /// its text was not said.
    ///
    /// It fires on `Complete` only: a run parked on a durable wait has not
    /// finished speaking, and a yielded or step-limited run has not finished
    /// at all. Both storage arms answer here, because ONE-1686 gave a
    /// canonical run a derived shell and turn of its own; the arm choice lives
    /// at the witness door, not in this policy.
    fn prepare_trailing_speak_fallback(
        &self,
        record: &CodeRunReplayRecord,
        step_outcome: &JsCodeModeStepOutcome,
        trailing_speak: Option<&str>,
    ) -> Option<String> {
        let text = trailing_speak.unwrap_or(&step_outcome.observation).trim();
        if text.is_empty() {
            return None;
        }
        if record
            .bridge_calls
            .iter()
            .filter_map(CodeRunBridgeCall::emitted_visible_speech_text)
            .any(|spoken| spoken.trim() == text)
        {
            return None;
        }
        Some(text.to_owned())
    }

    /// Recovers a terminal checkpoint's implicit speech intent (ONE-1929).
    ///
    /// The payload is content-addressed into the replay record BEFORE the
    /// terminal commit, so a retry that resumes a committed-but-unspoken run
    /// replays the exact words from durable storage and never needs provider
    /// bytes: a fresh session, a restarted process, or a prompt
    /// deployment/fingerprint drift recovers the same bubble. The bubble's
    /// identity is derived from the durable run identity and its order, and
    /// the durable marker below makes the delivery at-most-once, so recovery
    /// converges on the row that already exists instead of minting a second.
    fn recover_checkpointed_implicit_speak(
        &mut self,
        record: &CodeRunReplayRecord,
        status: &EngineExecutorStatus,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<()> {
        if !matches!(status, EngineExecutorStatus::Complete) {
            return Ok(());
        }
        let Some(seq) = completed_step_count(record)?.checked_sub(1) else {
            return Ok(());
        };
        let path = implicit_speak_output_path(seq);
        if !record.outputs.iter().any(|output| output.path == path) {
            return Ok(());
        }
        let text = load_utf8_output(&self.storage, record, &path)?;
        self.emit_trailing_speak_fallback(record, seq, &text, config)
    }

    /// Materializes ONE already-checkpointed implicit bubble, at most once.
    ///
    /// # Crash and retry
    ///
    /// The bubble is downstream of its checkpoint commit, so the window
    /// between them is real: a crash, or a post-commit witness failure, sends
    /// the caller back through terminal recovery. Two things close it, and
    /// both are needed. The DURABLE MARKER below is written straight after the
    /// bubble, keyed by content into the same routed raw-output store the run
    /// already uses, so a recovery that runs after a successful emit says
    /// nothing a second time. And the bubble's own IDENTITY is derived from
    /// the durable run identity and this order (`code_run::storage`), so even
    /// a crash landing between the witness and the marker re-puts THAT row
    /// rather than adding a second one: the witness door verifies the existing
    /// materialization exactly and refuses a divergent one typed. There is no
    /// window in which the transcript grows twice.
    fn emit_trailing_speak_fallback(
        &mut self,
        record: &CodeRunReplayRecord,
        step_seq: u64,
        text: &str,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<()> {
        let order = u32::try_from(record.bridge_calls.len()).unwrap_or(u32::MAX);
        let (marker, marker_bytes) = fallback_speech_marker(config.run_id, step_seq, order)?;
        if self.storage.get_code_run_raw_output(&marker)?.is_some() {
            return Ok(());
        }
        let occurred_at = config
            .determinism
            .frozen_unix_ms
            .saturating_add(u64::from(order))
            / 1000;
        #[cfg(test)]
        if self.fail_before_implicit_speak_once {
            self.fail_before_implicit_speak_once = false;
            return Err(Error::InvariantViolation(
                "injected failure before implicit speech materialization",
            )
            .into());
        }
        self.witness_turn_for_run_at(
            Some(config.run_id),
            ExecutorUtterance::Speak,
            text,
            occurred_at,
            order,
        )?;
        // Written AFTER the bubble, deliberately: a marker written first and
        // then orphaned by a crash would silence a run that never spoke, which
        // is the failure the fallback exists to prevent. Written second, the
        // worst case is a re-emission that lands on the same derived MESSAGE
        // id.
        self.storage
            .put_code_run_raw_output(&marker, &marker_bytes)?;
        Ok(())
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
        healed: bool,
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
                None,
                &record.bridge_calls[bridge_start..],
            )?,
            config
                .determinism
                .frozen_unix_ms
                .saturating_add(completed_steps),
        )?;
        record.step_checkpoints.push(checkpoint);
        self.storage
            .put_code_run_replay_record_if_generation_with_heal(
                record,
                expected_generation,
                healed.then_some(&config.model),
            )?;
        Ok(terminal_status)
    }

    /// Loads the run's replay record, or starts one.
    ///
    /// Run IDENTITY is strict on every resume. Resolved-prompt drift is judged
    /// against what the resume would DO: a record that is not terminal still
    /// owes provider requests and replay appends, and those must be produced
    /// under the teaching this run committed to, so drift refuses with the same
    /// typed config error as before, before another provider call. A TERMINAL
    /// record owes neither — its last checkpoint is committed, and the only
    /// work left is materializing an implicit bubble whose exact payload is
    /// already in the record — so drift is allowed through and the run returns
    /// its stored terminal status. Refusing there would strand a checkpointed
    /// bubble permanently the first time a prompt block was re-deployed.
    fn load_or_create_record(
        &self,
        config: &EngineExecutorConfig,
        prompt_fingerprint: &str,
    ) -> EngineExecutorResult<LoadedReplayRecord> {
        if let Some(record) = self.storage.get_code_run_replay_record(&config.run_id)? {
            if record.determinism != config.determinism {
                return Err(Error::InvalidConfig(
                    "engine executor determinism changed for existing run".to_owned(),
                )
                .into());
            }
            let prompt_binding = validate_executor_config_marker(
                &self.storage,
                &record,
                config,
                prompt_fingerprint,
            )?;
            let generation = Some(record.generation()?);
            let terminal_status = load_terminal_status(&self.storage, &record)?;
            if prompt_binding == PromptBinding::Drifted && terminal_status.is_none() {
                return Err(Error::InvalidConfig(
                    "engine executor config changed for existing run".to_owned(),
                )
                .into());
            }
            return Ok(LoadedReplayRecord {
                record,
                generation,
                terminal_status,
            });
        }
        let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        record_config_marker(&self.storage, &mut record, config, prompt_fingerprint)?;
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
        wire_prompt: &str,
    ) -> EngineExecutorResult<LlmRequest> {
        let completed_steps = completed_step_count(record)?;
        let mut messages = Vec::new();
        messages.push(LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: executor_system_prompt(wire_prompt),
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
            // ONE-1929: history is rendered CANONICALLY from the two trusted
            // sources — the healed bare program and the runtime's own
            // observation. A malformed provider reply is never taught back,
            // and neither payload can forge the engine's framing.
            let turn = CodeRunHistoryTurn {
                code: load_utf8_output(&self.storage, record, &script_output_path(seq))?,
                console: load_utf8_output(&self.storage, record, &observation_output_path(seq))?,
            };
            messages.push(LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: turn.assistant_exec(),
                }],
            });
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: turn.user_console(seq),
                }],
            });
        }

        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: executor_turn_instruction(completed_steps, wire_prompt),
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
    run_id: EntityId,
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
        run_id: EntityId,
        next_seq: u64,
        determinism: CodeRunDeterminism,
        legibility: Option<ExecutorLegibility<'a>>,
    ) -> Self {
        Self {
            gated_write,
            run_id,
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
        // ONE-1686: the speech family's order and timestamp are the BRIDGE's,
        // stamped here — on the one ordering path every `self.*` call takes —
        // before the row is recorded or the effect dispatched. Guest code
        // cannot forge either, and the replay row, the dispatched call and the
        // emitted bubble all carry the same number.
        let call = call.with_bridge_stamp(seq, started_at_ms);
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
        // ONE-1314: the current step's own history, observed at the last
        // moment before this call dispatches. The durable half was observed
        // when the step opened; together they are every bridge call this run
        // has made, so a write can never be sealed against a narrower history
        // than the one already recorded.
        self.gated_write.observe_bridge_history(&self.bridge_calls);
        let outcome = match self
            .gated_write
            .dispatch_for_executor_run(self.run_id, call.clone())
        {
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
        _ if records_failed_effect(call.effect()) => {
            Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: err.to_string(),
            }))
        }
        _ => None,
    }
}

/// Effects whose failure is REPLAY-VISIBLE rather than infrastructural.
///
/// These cross an audited durable boundary, so a refusal is part of the run's
/// history: the guest sees a typed `Failed` response, the row lands in the
/// replay log, and the fail-closed barrier refuses everything after it.
/// ONE-1686 adds the speech family — a refused bubble (a stale route after a
/// mid-run mode flip, a door rejection) is exactly that kind of failure.
fn records_failed_effect(effect: SelfEffect) -> bool {
    matches!(
        effect,
        SelfEffect::MemoryPutClaim | SelfEffect::MemorySupersedeClaim | SelfEffect::MemoryPutEdge
    ) || effect.is_speech()
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

/// The system and per-turn sites render the SAME resolved prompt-package
/// block. The prose lives outside Rust so agent-facing instructions cannot
/// drift from prompt tooling or be hand-copied between call sites.
fn executor_system_prompt(wire: &str) -> String {
    let wire = wire.trim_end();
    format!(
        "You are Oneiron's engine-native executor.\n{wire}\n\
         The guest runs inside the CODE-1 Wasmtime WIT component boundary.\n\
         Clock and random values are host-controlled imports for replay determinism.\n\
         Use the prompt-side host verb types below as documentation only; runtime effects arrive \
         as typed host imports:\n\n{PLAIN_JS_HOST_VERB_DTS}"
    )
}

/// The per-turn trailing instruction: the SAME canonical wire teaching, bound
/// to the durable step the model is being asked for.
fn executor_turn_instruction(step_seq: u64, wire: &str) -> String {
    let wire = wire.trim_end();
    format!("Emit the source for durable step {step_seq}.\n{wire}")
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
fn validate_executor_config_marker(
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
enum PromptBinding {
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
        "self.tasks.delegate" => Ok(SelfEffect::TaskDelegate),
        "self.speak" => Ok(SelfEffect::Speak),
        "self.think" => Ok(SelfEffect::Think),
        "self.express" => Ok(SelfEffect::Express),
        _ => Err(Error::CorruptedIndex("executor replay durable wait effect").into()),
    }
}

fn durable_wait_reason_str(reason: SelfDurableWaitReason) -> &'static str {
    match reason {
        SelfDurableWaitReason::HumanInput => "human_input",
        SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        SelfDurableWaitReason::OutboundEffect => "outbound_effect",
        SelfDurableWaitReason::PeerResult => "peer_result",
    }
}

fn durable_wait_reason_from_str(value: &str) -> EngineExecutorResult<SelfDurableWaitReason> {
    match value {
        "human_input" => Ok(SelfDurableWaitReason::HumanInput),
        "destructive_effect" => Ok(SelfDurableWaitReason::DestructiveEffect),
        "outbound_effect" => Ok(SelfDurableWaitReason::OutboundEffect),
        "peer_result" => Ok(SelfDurableWaitReason::PeerResult),
        _ => Err(Error::CorruptedIndex("executor replay durable wait reason").into()),
    }
}

fn step_state_hash(
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

/// Line-oriented markdown fence delimiter. The LANGUAGE SUFFIX after it is
/// inert packaging metadata: `ts`, `typescript`, `js`, `javascript`,
/// `readscript`, and arbitrary tags all follow the same path.
const CODE_FENCE: &str = "```";

/// What ONE-1929 had to remove from one model reply to reach a bare program.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExecutorWireRepairs {
    pub trimmed_transport_whitespace: bool,
    pub stripped_code_fence: bool,
    pub stripped_exec_wrapper: bool,
    pub discarded_console_blocks: u32,
}

impl ExecutorWireRepairs {
    /// Whether this turn needed ANY healing. One healed turn counts once, no
    /// matter how many of these repairs it took.
    #[must_use]
    pub(crate) const fn healed(self) -> bool {
        self.trimmed_transport_whitespace
            || self.stripped_code_fence
            || self.stripped_exec_wrapper
            || self.discarded_console_blocks != 0
    }
}

/// One model reply, normalized onto the strict bare wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealedExecutorReply {
    /// The sole source passed to [`JsCodeModeRuntime::run_step`].
    pub code: String,
    /// ONE-1686-owned implicit-speak payload; never part of `code` or console.
    pub trailing_speak: Option<String>,
    pub repairs: ExecutorWireRepairs,
}

/// Normalizes one provider reply into the bare executable program the
/// sandbox runs (ONE-1929).
///
/// The model-facing wire is strict bare executable plain JavaScript. The
/// executor may remove PACKAGING once, but it never trusts model-authored
/// console text: forged console blocks are deleted outright — not compared,
/// diffed, logged, or kept as a diagnostic — and the sandbox's own
/// observation is the sole console authority.
///
/// The normalization order is fixed, and each wrapper is removed at most
/// once:
///
/// 1. require a clean finish and join the response's text parts;
/// 2. partition the reply into a program candidate and a trailing region
///    (the ONE-1686 implicit-speak seam);
/// 3. drop the trailing region's console blocks, then trim what is left into
///    the speak payload;
/// 4. trim outer transport whitespace from the candidate — this pre-strip
///    trim ALONE sets `trimmed_transport_whitespace`;
/// 5. strip one whole markdown fence, ignoring its language token;
/// 6. drop the candidate's depth-0 console blocks;
/// 7. strip one whole `<exec>` / `</exec>` wrapper, never recursively, and
///    drop console blocks exposed directly inside that supported wrapper;
/// 8. trim the interior once more (no repair flag) and run the mandatory
///    source-aware structural gate.
fn heal_executor_reply(response: &LlmResponse) -> EngineExecutorResult<HealedExecutorReply> {
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

    let (candidate, trailing) = partition_reply(&text);
    let (cleaned_trailing, trailing_discards) =
        partition_top_level_console_blocks(trailing, ConsoleRegion::Trailing)?;
    let trailing_speak = cleaned_trailing.trim();

    let trimmed = candidate.trim();
    let mut repairs = ExecutorWireRepairs {
        trimmed_transport_whitespace: trimmed.len() != candidate.len(),
        discarded_console_blocks: trailing_discards,
        ..ExecutorWireRepairs::default()
    };

    let unfenced = match strip_one_whole_fence(trimmed)? {
        Some(interior) => {
            repairs.stripped_code_fence = true;
            interior
        }
        None => trimmed,
    };
    let (deconsoled, candidate_discards) =
        partition_top_level_console_blocks(unfenced, ConsoleRegion::Candidate)?;
    repairs.discarded_console_blocks = repairs
        .discarded_console_blocks
        .checked_add(candidate_discards)
        .ok_or(Error::ArithmeticOverflow(
            "executor discarded console blocks",
        ))?;
    let unwrapped = match strip_one_whole_exec_wrapper(&deconsoled) {
        Some(interior) => {
            repairs.stripped_exec_wrapper = true;
            // The supported outer wrapper is packaging. Once it is removed,
            // console blocks directly inside it are top-level model packaging
            // too. Scan that interior once; a nested second exec wrapper still
            // protects its own body and survives into the mandatory gate.
            let (cleaned, wrapper_discards) =
                partition_top_level_console_blocks(interior, ConsoleRegion::Candidate)?;
            repairs.discarded_console_blocks = repairs
                .discarded_console_blocks
                .checked_add(wrapper_discards)
                .ok_or(Error::ArithmeticOverflow(
                    "executor discarded console blocks",
                ))?;
            cleaned
        }
        None => deconsoled,
    };

    let code = unwrapped.trim();
    mandatory_structural_gate(code, trailing_speak)?;
    Ok(HealedExecutorReply {
        code: code.to_owned(),
        trailing_speak: (!trailing_speak.is_empty()).then(|| trailing_speak.to_owned()),
        repairs,
    })
}

/// The ONE-1686 reply partition: where the program candidate ends and the
/// trailing region begins.
///
/// A reply that OPENS with a whole markdown fence hands everything after that
/// fence's closer line to ONE-1686 as trailing prose; anything else is one
/// undivided candidate, so prose the partition cannot classify stays in front
/// of the code and fails the mandatory structural gate instead of being
/// silently split off. Two sibling fenced programs partition the same way and
/// the second fence reaches that gate as residual structure — they are never
/// joined into one source.
fn partition_reply(text: &str) -> (&str, &str) {
    let lines = reply_lines(text);
    let Some(opener) = lines.iter().position(|line| !line.text.trim().is_empty()) else {
        return (text, "");
    };
    if !lines[opener].text.trim_start().starts_with(CODE_FENCE) {
        return (text, "");
    }
    let Some(offset) = lines[opener + 1..]
        .iter()
        .position(|line| line.text.trim() == CODE_FENCE)
    else {
        return (text, "");
    };
    let split = lines[opener + 1 + offset].end;
    (&text[..split], &text[split..])
}

/// Removes ONE whole line-oriented markdown fence.
///
/// The opener must be the entire first non-empty line and the matching closer
/// the entire final non-empty line; both delimiter lines are removed in full,
/// including their terminators. The opener's language token is IGNORED — the
/// old `js`/`javascript` whitelist and `ts`/`typescript`/`readscript`
/// rejection are gone, because a language tag is not a parseability proof.
/// Anything else is left alone for the mandatory structural gate.
///
/// # Errors
///
/// A lone fence delimiter is its own first and last non-empty line: there is
/// no pair to remove and no interior to execute, so it is an invalid body.
fn strip_one_whole_fence(input: &str) -> EngineExecutorResult<Option<&str>> {
    let lines = reply_lines(input);
    let Some(first) = lines.iter().position(|line| !line.text.trim().is_empty()) else {
        return Ok(None);
    };
    if !lines[first].text.trim_start().starts_with(CODE_FENCE) {
        return Ok(None);
    }
    let Some(last) = lines.iter().rposition(|line| !line.text.trim().is_empty()) else {
        return Ok(None);
    };
    if last == first {
        return Err(
            Error::InvalidClaimBody("executor LLM response has an unpaired code fence").into(),
        );
    }
    if lines[last].text.trim() != CODE_FENCE {
        return Ok(None);
    }
    Ok(Some(&input[lines[first + 1].start..lines[last].start]))
}

/// Removes ONE whole line-oriented `<exec>` / `</exec>` wrapper.
///
/// Same byte rule as the fence: `<exec>` must be the entire first non-empty
/// line and `</exec>` the entire final non-empty line, and both delimiter
/// lines go in full. Exactly one pair strips and the helper NEVER recurses, so
/// a nested second wrapper survives and the mandatory structural gate refuses
/// it. That is also why this needs no error channel of its own.
fn strip_one_whole_exec_wrapper(input: &str) -> Option<&str> {
    let lines = reply_lines(input);
    let first = lines.iter().position(|line| !line.text.trim().is_empty())?;
    let last = lines
        .iter()
        .rposition(|line| !line.text.trim().is_empty())?;
    if first == last
        || lines[first].text.trim() != CODE_RUN_EXEC_OPEN
        || lines[last].text.trim() != CODE_RUN_EXEC_CLOSE
    {
        return None;
    }
    Some(&input[lines[first + 1].start..lines[last].start])
}

/// The mandatory structural gate every healed reply passes through.
///
/// Healing removes packaging exactly once; whatever wrapper, tag, or fence
/// structure SURVIVES that is not packaging the executor is allowed to guess
/// at, so it returns the existing typed invalid-body error and reaches the
/// existing caller-owned re-execute path. No error variant and no second
/// retry loop is introduced.
///
/// The executable-source preflight is deliberately a shape check, not a
/// parser: general JavaScript syntax errors are NOT structural garbage and
/// stay on the existing runtime-error path.
fn mandatory_structural_gate(code: &str, trailing_speak: &str) -> EngineExecutorResult<()> {
    if code.is_empty() {
        return Err(Error::InvalidClaimBody("executor LLM response missing plain JS").into());
    }
    if has_residual_wire_structure_in_source(code) {
        return Err(Error::InvalidClaimBody(
            "executor LLM response kept wire packaging after healing",
        )
        .into());
    }
    if has_residual_wire_structure_in_prose(trailing_speak) {
        return Err(Error::InvalidClaimBody(
            "executor LLM response trailed a second program instead of prose",
        )
        .into());
    }
    if !looks_like_plain_js(code) {
        return Err(
            Error::InvalidClaimBody("executor LLM response is not executable plain JS").into(),
        );
    }
    Ok(())
}

/// Whether a structural token begins a source line outside JavaScript
/// strings, template literals, and comments.
///
/// This uses the exact state transition helper the console healer uses. A
/// token-looking line inside a template or block comment is source bytes, not
/// residual packaging. Real line-oriented wrapper/fence structure in code
/// state still fails closed.
fn has_residual_wire_structure_in_source(text: &str) -> bool {
    let mut cursor = 0_usize;
    let mut state = SourceState::Code;
    let mut line_prefix_blank = true;
    while cursor < text.len() {
        let rest = &text[cursor..];
        if state == SourceState::Code && line_prefix_blank && starts_with_wire_token(rest) {
            return true;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        let width = advance_source_state(&mut state, rest, ch);
        let span = &text[cursor..cursor + width];
        line_prefix_blank = if span.contains('\n') {
            true
        } else {
            line_prefix_blank && span.trim().is_empty()
        };
        cursor += width;
    }
    false
}

/// Trailing prose is not JavaScript. Apostrophes and backticks in natural
/// language cannot open source literals that hide a second program.
fn has_residual_wire_structure_in_prose(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .any(starts_with_wire_token)
}

fn starts_with_wire_token(text: &str) -> bool {
    text.starts_with(CODE_RUN_EXEC_OPEN)
        || text.starts_with(CODE_RUN_EXEC_CLOSE)
        || text.starts_with(CODE_RUN_CONSOLE_OPEN)
        || text.starts_with(CODE_RUN_CONSOLE_CLOSE)
        || text.starts_with(CODE_FENCE)
}

/// One line of a reply, with the byte spans the one-shot strippers need.
struct ReplyLine<'a> {
    text: &'a str,
    /// Byte offset where this line's content begins.
    start: usize,
    /// Byte offset just past this line's content, before its terminator.
    end: usize,
}

/// Splits `input` into lines, keeping each line's byte span so a delimiter
/// line can be removed IN FULL, terminator included.
fn reply_lines(input: &str) -> Vec<ReplyLine<'_>> {
    let mut lines = Vec::new();
    let mut start = 0_usize;
    loop {
        let Some(offset) = input[start..].find('\n') else {
            lines.push(ReplyLine {
                text: &input[start..],
                start,
                end: input.len(),
            });
            return lines;
        };
        let newline = start + offset;
        let end = if newline > start && input.as_bytes()[newline - 1] == b'\r' {
            newline - 1
        } else {
            newline
        };
        lines.push(ReplyLine {
            text: &input[start..end],
            start,
            end,
        });
        start = newline + 1;
    }
}

/// Which half of a partitioned reply a console scan is walking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleRegion {
    /// The program candidate: JavaScript, so the scan tracks source state and
    /// `<exec>` wrapper depth and recognizes console blocks only at depth 0.
    Candidate,
    /// The ONE-1686 trailing region: prose, so the scan keeps its round-1
    /// recognition forms and tracks no source state — an apostrophe in
    /// English must not open a string that swallows a forged console block.
    Trailing,
}

/// Minimal JavaScript source state, tracked only well enough that a console
/// token inside a string, template literal, or comment is left ALONE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceState {
    Code,
    LineComment,
    BlockComment,
    Single,
    Double,
    Template,
}

/// Deletes top-level `<console>` … `</console>` blocks and counts them.
///
/// `heal_executor_reply` calls this once for the program candidate and once
/// for the trailing region, then sums both discard counts. The two regions
/// are different languages, so they get different recognition rules — see
/// [`ConsoleRegion`] — but the discard itself is identical and literal: the
/// bytes are dropped, never stored anywhere.
///
/// # Errors
///
/// An opener with no matching `</console>` in its region is an invalid body,
/// never speak bytes.
fn partition_top_level_console_blocks(
    input: &str,
    region: ConsoleRegion,
) -> EngineExecutorResult<(String, u32)> {
    ConsoleScanner::new(input, region).run()
}

/// The source-aware scanner behind [`partition_top_level_console_blocks`].
struct ConsoleScanner<'a> {
    input: &'a str,
    region: ConsoleRegion,
    out: String,
    discarded: u32,
    state: SourceState,
    /// Line-oriented `<exec>` / `</exec>` nesting depth.
    depth: u32,
    /// Everything before the cursor on this line is whitespace.
    line_prefix_blank: bool,
    /// The cursor sits immediately after a closer token that began a line.
    after_closer: bool,
    cursor: usize,
}

impl<'a> ConsoleScanner<'a> {
    fn new(input: &'a str, region: ConsoleRegion) -> Self {
        Self {
            input,
            region,
            out: String::with_capacity(input.len()),
            discarded: 0,
            state: SourceState::Code,
            depth: 0,
            line_prefix_blank: true,
            after_closer: false,
            cursor: 0,
        }
    }

    fn run(mut self) -> EngineExecutorResult<(String, u32)> {
        while self.cursor < self.input.len() {
            if !self.take_wire_token()? {
                self.take_source_span();
            }
        }
        Ok((self.out, self.discarded))
    }

    /// Consumes one wrapper/fence/console token when the cursor sits in a
    /// position where the grammar can carry one: at a line start, or
    /// immediately after a closer token that itself began a line.
    fn take_wire_token(&mut self) -> EngineExecutorResult<bool> {
        if self.state != SourceState::Code {
            return Ok(false);
        }
        let rest = &self.input[self.cursor..];
        // The trailing half is prose, not JavaScript. A complete forged
        // console block is packaging even when embedded inline after words.
        if self.region == ConsoleRegion::Trailing && rest.starts_with(CODE_RUN_CONSOLE_OPEN) {
            self.discard_console_block()?;
            return Ok(true);
        }
        if !(self.line_prefix_blank || self.after_closer) {
            return Ok(false);
        }
        if self.region == ConsoleRegion::Candidate && rest.starts_with(CODE_RUN_EXEC_OPEN) {
            self.depth = self.depth.saturating_add(1);
            self.keep_token(CODE_RUN_EXEC_OPEN, false);
        } else if rest.starts_with(CODE_RUN_EXEC_CLOSE) {
            self.depth = self.depth.saturating_sub(1);
            self.keep_token(CODE_RUN_EXEC_CLOSE, true);
        } else if self.region == ConsoleRegion::Trailing && rest.starts_with(CODE_FENCE) {
            // The candidate side has no fence-closer form left to honour: its
            // fence was already stripped.
            self.keep_token(CODE_FENCE, true);
        } else if self.depth == 0 && rest.starts_with(CODE_RUN_CONSOLE_OPEN) {
            self.discard_console_block()?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    /// Copies a recognized structural token through unchanged. Only console
    /// blocks are ever deleted; a surviving wrapper token is the mandatory
    /// structural gate's business, not the scanner's.
    fn keep_token(&mut self, token: &str, closer: bool) {
        self.out.push_str(token);
        self.cursor += token.len();
        self.line_prefix_blank = false;
        self.after_closer = closer;
    }

    /// Deletes one whole console block, plus the line it owned outright.
    fn discard_console_block(&mut self) -> EngineExecutorResult<()> {
        let recognition_continues =
            self.line_prefix_blank || self.after_closer || self.region == ConsoleRegion::Trailing;
        let body_at = self.cursor + CODE_RUN_CONSOLE_OPEN.len();
        let Some(offset) = self.input[body_at..].find(CODE_RUN_CONSOLE_CLOSE) else {
            return Err(Error::InvalidClaimBody(
                "executor LLM response has an unterminated console block",
            )
            .into());
        };
        let mut next = body_at + offset + CODE_RUN_CONSOLE_CLOSE.len();
        let newline = self.input[next..].find('\n').map(|at| next + at);
        let rest_of_line = &self.input[next..newline.unwrap_or(self.input.len())];
        let owned_the_line = self.line_prefix_blank && rest_of_line.trim().is_empty();
        if owned_the_line {
            // Take the blank prefix and the terminator with it, so a discard
            // cannot glue two surviving lines together.
            while self.out.ends_with([' ', '\t']) {
                self.out.pop();
            }
            next = newline.map_or(self.input.len(), |at| at + 1);
        }
        self.cursor = next;
        self.discarded = self
            .discarded
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "executor discarded console blocks",
            ))?;
        // A discard is itself a recognized closer. Preserve the grammar
        // position so glued sibling blocks are consumed one after another;
        // do not make the deleted bytes turn a nonblank prefix blank.
        self.line_prefix_blank = owned_the_line || self.line_prefix_blank;
        self.after_closer = recognition_continues;
        Ok(())
    }

    /// Copies the next source span through, advancing the source state.
    fn take_source_span(&mut self) {
        let rest = &self.input[self.cursor..];
        let Some(ch) = rest.chars().next() else {
            self.cursor = self.input.len();
            return;
        };
        let width = if self.region == ConsoleRegion::Trailing {
            ch.len_utf8()
        } else {
            advance_source_state(&mut self.state, rest, ch)
        };
        let end = self.cursor + width;
        let span = &self.input[self.cursor..end];
        self.out.push_str(span);
        self.cursor = end;
        self.line_prefix_blank = if span.contains('\n') {
            true
        } else {
            self.line_prefix_blank && span.trim().is_empty()
        };
        self.after_closer = false;
    }

    // Source-state transitions live in the shared helper below so healing and
    // residual-structure detection cannot disagree about literals/comments.
}

/// Applies one JavaScript source-state transition and returns the consumed
/// UTF-8 byte width. This intentionally recognizes only the lexical forms the
/// wire grammar needs to protect: strings, template literals, and comments.
fn advance_source_state(state: &mut SourceState, rest: &str, ch: char) -> usize {
    match *state {
        SourceState::Code => advance_code_state(state, rest, ch),
        SourceState::LineComment => {
            if ch == '\n' {
                *state = SourceState::Code;
            }
            ch.len_utf8()
        }
        SourceState::BlockComment => {
            if rest.starts_with("*/") {
                *state = SourceState::Code;
                return 2;
            }
            ch.len_utf8()
        }
        SourceState::Single | SourceState::Double | SourceState::Template => {
            advance_quoted_state(state, rest, ch)
        }
    }
}

fn advance_code_state(state: &mut SourceState, rest: &str, ch: char) -> usize {
    if rest.starts_with("//") {
        *state = SourceState::LineComment;
        return 2;
    }
    if rest.starts_with("/*") {
        *state = SourceState::BlockComment;
        return 2;
    }
    *state = match ch {
        '\'' => SourceState::Single,
        '"' => SourceState::Double,
        '`' => SourceState::Template,
        _ => SourceState::Code,
    };
    ch.len_utf8()
}

fn advance_quoted_state(state: &mut SourceState, rest: &str, ch: char) -> usize {
    if ch == '\\' {
        // The escaped character cannot close the literal.
        return 1 + rest[1..].chars().next().map_or(0, char::len_utf8);
    }
    let closes = match *state {
        SourceState::Single => ch == '\'',
        SourceState::Double => ch == '"',
        _ => ch == '`',
    };
    // Only a template literal spans lines; recovering the other two at the
    // newline keeps one stray quote from swallowing the rest of the reply.
    if closes || (ch == '\n' && *state != SourceState::Template) {
        *state = SourceState::Code;
    }
    ch.len_utf8()
}

/// The executable-source preflight: a SHAPE check on the healed program.
///
/// It refuses prose, not imperfect JavaScript. A structurally clean source
/// with a genuine syntax error still reaches the sandbox and fails on the
/// existing runtime-error path, which is the boundary this ticket keeps.
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

/// The durable "this step already spoke its last word" marker (ONE-1686).
///
/// Content-addressed into the run's own routed raw-output store, so its
/// presence is readable WITHOUT the replay record that a crash or a
/// `ConcurrentWrite` may have prevented from landing. The bytes name the run,
/// the step and the bubble's order and nothing else — deliberately not the
/// text, because "at most one trailing bubble per completed step" must hold
/// even if a re-run's backend produced a different observation.
fn fallback_speech_marker(
    run_id: EntityId,
    seq: u64,
    order: u32,
) -> EngineExecutorResult<(CodeRunRawOutput, Vec<u8>)> {
    let path = fallback_speech_marker_path(seq);
    let text = serde_json::to_string(&json!({
        "schema_version": REPLAY_METADATA_SCHEMA_VERSION,
        "run_id": run_id.to_hex(),
        "step_seq": seq,
        "order": order,
    }))?;
    let raw = text_output_bytes(&path, &text);
    let marker = CodeRunRawOutput::from_bytes(path, &raw)?;
    Ok((marker, raw))
}

fn fallback_speech_marker_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}{FALLBACK_SPEECH_MARKER_SUFFIX}")
}

fn script_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.generated.js")
}

fn observation_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.observation.txt")
}

fn implicit_speak_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.implicit-speak.txt")
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
