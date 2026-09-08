//! Public API surface of the engine-native executor: limits, config, errors, and code-mode step/outcome types.

use crate::code_run::{
    CodeRunDeterminism, CodeRunReplayRecord, SelfCall, SelfDispatchOutcome, SelfDurableWait,
};
use crate::code_sandbox::SandboxBoundaryContract;
use crate::dreamer_wake::{BudgetLegibilityEnvelope, WakePassDeadline, current_legibility};
use crate::entity_id::EntityId;
use crate::llm::BudgetGuard;
use crate::{Error, LlmError, ModelId, ModelLocality, ModelTierRef, Result};
use std::path::PathBuf;

pub const ENGINE_EXECUTOR_SOFT_STEP_LIMIT: u32 = 6;

pub const ENGINE_EXECUTOR_HARD_STEP_LIMIT: u32 = 50;

pub const ENGINE_EXECUTOR_PURPOSE_NAME: &str = "engine_native_executor";

pub const ENGINE_EXECUTOR_FALLBACK_NAME: &str = "engine_native_js_executor_v1";

/// Reserved guest response key carrying the budget legibility envelope
/// (ONE-1305; guest-visible contract — the key name is pinned).
pub const GUEST_BUDGET_RESPONSE_KEY: &str = "budget";

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
    pub(super) fn envelope(&self) -> BudgetLegibilityEnvelope {
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
