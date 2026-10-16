//! Public API surface of the engine-native executor: limits, config, errors, and code-mode step/outcome types.

use crate::code_run::{
    CodeRunDeterminism, CodeRunReplayRecord, ResultFacet, SelfCall, SelfDispatchOutcome,
    SelfDurableWait, WaitKey,
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

/// The call purpose of a run's compaction pass (agent-runtime-v1 §d7).
pub const ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME: &str = "engine_native_executor_compaction";

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
    /// The run's host door refused a call the executor makes for the run,
    /// with the door's stable code.
    #[error("the run's host door refused its call: {code}")]
    HostRefused { code: String },
}

impl EngineExecutorError {
    /// The variant, for a log line, which never carries the error's text: an
    /// engine error's can quote what the vault holds, a model error's a reply
    /// or a provider's error body, a canonicalization error's the request.
    pub(crate) fn variant(&self) -> &'static str {
        match self {
            Self::Engine(_) => "engine",
            Self::Llm(_) => "llm",
            Self::CanonicalRequest(_) => "canonical_request",
            Self::HostRefused { .. } => "host_refused",
        }
    }

    /// An engine error's kind, for the same log line.
    pub(crate) fn engine_kind(&self) -> Option<crate::ErrorKind> {
        match self {
            Self::Engine(error) => Some(error.kind()),
            _ => None,
        }
    }
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
    /// Immutable seat pin; absent on explicit legacy runs without a manifest.
    pub seat_effort: Option<crate::llm::ReasoningEffort>,
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

/// Where one frame of a step's streamed result goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsCodeModeStream<'a> {
    /// `console.log` lines: the observation of a step that does not finish.
    Console,
    /// The `finish` answer. `start` marks its first frame: a later finish
    /// starts the answer over.
    Finish { start: bool },
    /// A value passed to `store`. `start` marks its first frame: each store
    /// streams a value of its own, which the host takes when the call lands.
    Store { start: bool },
    /// The step's `/mnt/outputs` file at this path, appended to.
    File(&'a str),
}

/// One call a program makes of its run's own results. The host answers it
/// from the run's record and body store: it takes no bridge seq and leaves
/// no bridge row, as a chunk read does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsResultCall {
    /// `store(value, name?)`: the value just streamed to the store target,
    /// stored and bound under `name`, or under the next free `r<n>`.
    Store { name: Option<String> },
    /// `describe(r)`: the card of one of the run's results.
    Describe(JsResultTarget),
    /// `slice`, `search`, `query` or `chunks` of one of the run's results:
    /// the facet, and its input less the reference.
    Read {
        target: JsResultTarget,
        facet: ResultFacet,
        input: serde_json::Value,
    },
}

/// How a program names one of its run's results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsResultRef {
    /// A name the run bound (`r7`).
    Name(String),
    /// A result's handle, as its card gives it or as model context cites it.
    Handle(String),
}

/// A result reference, and the byte range of its body it is narrowed to:
/// `<name-or-handle>#<start>-<end>`, as a chunk names one. A range persists
/// nothing; every read of it is a read of its parent, checked as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsResultTarget {
    pub reference: JsResultRef,
    /// `[start, end)` in the parent's bytes.
    pub range: Option<(u64, u64)>,
}

impl JsResultTarget {
    /// Reads a reference as a program writes it: a range suffix first, then
    /// a handle (any text with a colon, which no name has) or a name.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let range = text.rsplit_once('#').and_then(|(parent, suffix)| {
            let (start, end) = suffix.split_once('-')?;
            let canonical = |digits: &str| {
                digits
                    .parse::<u64>()
                    .ok()
                    .filter(|value| value.to_string() == digits)
            };
            Some((parent, (canonical(start)?, canonical(end)?)))
        });
        let (parent, range) = match range {
            Some((parent, range)) => (parent, Some(range)),
            None => (text, None),
        };
        let reference = if parent.contains(':') {
            JsResultRef::Handle(parent.to_owned())
        } else {
            JsResultRef::Name(parent.to_owned())
        };
        Self { reference, range }
    }
}

/// Host import bridge exposed to a JS runtime component.
pub trait JsCodeModeHost {
    /// Takes one frame of the step's streamed result into the host's own
    /// body store, as it is written. A host with no store answers `false`,
    /// and the runtime keeps the frame for the step's outcome instead.
    fn write_output(&mut self, _stream: JsCodeModeStream<'_>, _frame: &[u8]) -> Result<bool> {
        Ok(false)
    }

    /// Resolves only a reserved recoverable-output virtual path. Other hosts
    /// deny by default; the linked sandbox.fs.read_file bridge routes normal
    /// file reads to its existing adapter.
    fn read_recoverable_output(&mut self, _path: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Stores a reply too large for one message (its JSON past
    /// `RESULT_REPLY_INLINE_BYTES`) as a result of the run, bound to the next
    /// free name, and answers the card the guest gets in its place. A host
    /// with no result store answers `None`.
    fn store_reply(&mut self, _reply: &serde_json::Value) -> Result<Option<serde_json::Value>> {
        Ok(None)
    }

    /// Answers one call a program makes of its run's own results with the
    /// reply the guest gets: `{"output": card}` (or a facet's reply), or a
    /// `denied` refusal. A host with no result store refuses it.
    fn result_call(&mut self, _call: JsResultCall) -> Result<serde_json::Value> {
        Err(Error::InvalidConfig(
            "results need a result store".to_owned(),
        ))
    }

    /// Dispatches one typed `self.*` call through the host-owned traps.
    /// Every response carries the budget legibility envelope inside a wake
    /// pass (design D5: attached to EVERY host-call response) — including
    /// the typed `Denied`/`Failed` error outcomes, which return as `Ok`
    /// responses here while the executor fails the step afterwards. `Err`
    /// is reserved for infrastructure failures with no guest-visible
    /// response at all.
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse>;

    /// Dispatches one `self.*` call that runs a step of its own while the
    /// caller's step waits on the reply: `self.skills.call` runs an
    /// agent-callable skill (OF-353). `runtime` is a fresh sibling of the
    /// runtime whose step made the call, its pinned component and budget
    /// with a store of its own. A host that runs no nested step answers the
    /// call as any other.
    fn dispatch_self_nested(
        &mut self,
        call: SelfCall,
        _runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchResponse> {
        self.dispatch_self(call)
    }
}

/// Runtime seam for the CODE-1 plain-JS guest component.
pub trait JsCodeModeRuntime {
    fn bind_foreign_egress(
        &mut self,
        _relay: std::sync::Arc<dyn oneiron_container::EgressRelay>,
    ) -> Result<()> {
        Err(crate::Error::InvalidConfig(
            "runtime has no isolated foreign execution lane".into(),
        ))
    }

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

/// A step's outcome. A runtime whose host took the streamed result
/// ([`JsCodeModeHost::write_output`]) leaves `observation` and `outputs`
/// empty; the host holds the bodies.
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
    Yielded {
        next_step_seq: u64,
    },
    HardStepLimitReached,
    /// The window reached its budget with no accepted swap (agent-runtime-v1
    /// §d7). Not terminal: the same run continues once a swap lands.
    WindowFull {
        next_step_seq: u64,
        reason: super::compaction::WindowFullReason,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineExecutorOutcome {
    pub status: EngineExecutorStatus,
    pub steps_run: u32,
    pub replay_record: CodeRunReplayRecord,
    pub seat_receipt: Option<crate::llm::seat::SeatChoiceReceipt>,
    /// The run's compaction after this call, when the host keeps a seat.
    pub compaction: Option<super::compaction::CompactionReport>,
}

impl EngineExecutorOutcome {
    /// The wait a Waiting run parked on, keyed as its reply is delivered;
    /// `None` for any other status.
    #[must_use]
    pub fn parked_wait(&self) -> Option<ParkedWait> {
        let EngineExecutorStatus::Waiting(wait) = &self.status else {
            return None;
        };
        let parked = self.replay_record.step_checkpoints.last()?;
        Some(ParkedWait {
            key: super::record::wait_key(&self.replay_record, wait),
            step_hash: parked.state_hash,
            wait: wait.clone(),
        })
    }
}

/// A parked run's wait: the key its reply is delivered under, the parked
/// step's state hash a host binds a trap to, and the wait itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedWait {
    pub key: WaitKey,
    pub step_hash: [u8; 32],
    pub wait: SelfDurableWait,
}
