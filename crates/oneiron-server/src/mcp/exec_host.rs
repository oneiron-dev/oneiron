//! MCP code-execution host seam and the engine-native host binding.

use super::actors::McpResolvedActor;
use super::run_seats::RunSeats;
use crate::admission::Admission;
use crate::wire_telemetry::{LimitQuestions, LimitRow};
use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::code_run::{GatedActorWrite, SpawnHostSeat};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeRuntime, RunCompaction,
};
use oneiron::llm::seat::{SeatDecisions, SeatKind, SeatTask};
use oneiron::{BudgetGuard, BudgetLease, EntityId, LlmBackend, Vault, WriteActor};
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// The ONE place an MCP-derived durable id is minted (ONE-1704 M3).
///
/// Every axis of the IMMUTABLE connector-scope identity is mixed in — the
/// credential-fingerprint-derived STREAM connection, the actor, its gate
/// identity, and the registered world/facet ceiling — so two credentials for
/// the SAME actor with disjoint scopes can never map one reused key onto one
/// row. Nothing a caller sends reaches this: the key is a caller-chosen label,
/// the identity is not.
///
/// Both callers route through here: the `execute_code` durable run handle and
/// the retained edit adapter's idempotency row. There is no second derivation.
#[must_use]
pub fn mcp_scoped_identity_id(namespace: &str, key: &str, actor: &McpResolvedActor) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mcp.scoped-identity.v2");
    hasher.update(&(namespace.len() as u64).to_be_bytes());
    hasher.update(namespace.as_bytes());
    // Credential identity: the stream connection id IS the registered
    // credential's fingerprint, never an actor field or a tool argument.
    hasher.update(&(actor.stream_connection.0.len() as u64).to_be_bytes());
    hasher.update(actor.stream_connection.0.as_bytes());
    hasher.update(actor.actor_ref.as_bytes());
    hasher.update(&(actor.gate_actor_class.len() as u64).to_be_bytes());
    hasher.update(actor.gate_actor_class.as_bytes());
    hasher.update(&(actor.gate_actor_ref.len() as u64).to_be_bytes());
    hasher.update(actor.gate_actor_ref.as_bytes());
    // The immutable registered scope ceiling.
    if let Some(world_ref) = actor.scope.world_ref {
        hasher.update(b"w1");
        hasher.update(world_ref.as_bytes());
    } else {
        hasher.update(b"w0");
    }
    if let Some(facet_ref) = actor.scope.facet_ref {
        hasher.update(b"f1");
        hasher.update(facet_ref.as_bytes());
    } else {
        hasher.update(b"f0");
    }
    // A several-facet ceiling also binds every facet it reads; a one-facet
    // one hashes as before.
    if let oneiron::federation::ScopeAxis::Some(facets) = &actor.scope.facets
        && facets.len() > 1
    {
        hasher.update(b"fs");
        hasher.update(&(facets.len() as u64).to_be_bytes());
        for facet in facets {
            hasher.update(facet.0.as_bytes());
        }
    }
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}

/// The DURABLE run id one `execute_code` handle resolves to.
///
/// Deterministic, so re-calling with the same `run_ref` under the same
/// credential scope re-enters the SAME persisted replay record — that is the
/// resume door. A second credential's identical handle is a different run.
#[must_use]
pub fn mcp_code_run_id(run_ref: &str, actor: &McpResolvedActor) -> EntityId {
    mcp_scoped_identity_id("execute_code.run", run_ref, actor)
}

/// One `execute_code` call as the injected host receives it.
///
/// The actor is the RESOLVED connector actor; nothing here is caller-shaped
/// except the task text and the run handle label.
pub struct McpCodeExecutionRequest<'a> {
    /// The vault this connector's durable run lives in. Supplied by the door
    /// the call arrived at, so the host binds no vault of its own.
    pub vault: Arc<Vault>,
    pub actor: &'a McpResolvedActor,
    /// The caller's handle onto the durable run.
    pub run_ref: &'a str,
    /// The REPL task the durable run carries out.
    pub task: &'a str,
    /// The durable run id [`mcp_code_run_id`] derived for this handle.
    pub run_id: EntityId,
    /// The door each code-mode verb call takes: the SDK verb table under this
    /// call's connector, with its admission and gate.
    pub verbs: Arc<dyn oneiron::code_run::AgentVerbDoor>,
}

impl fmt::Debug for McpCodeExecutionRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpCodeExecutionRequest")
            .field("actor", &self.actor)
            .field("run_ref", &self.run_ref)
            .field("run_id", &self.run_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpCodeExecutionError {
    #[error("no execute_code host is bound on this server")]
    HostUnbound,
    #[error("execute_code run is already active; retry the same run_ref")]
    RunBusy,
    #[error(
        "execute_code waited past limits.queue_wait_timeout_ms for a run's turn; no run was started; retry"
    )]
    RunWaitedOut,
    #[error("execute_code run binding failed: {0}")]
    RunBinding(String),
    #[error("execute_code run failed: {0}")]
    Run(String),
}

impl McpCodeExecutionError {
    /// The stable wire code this refusal carries.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::HostUnbound => super::MCP_CODE_HOST_UNBOUND_CODE,
            Self::RunBusy => "code_run_busy",
            Self::RunWaitedOut => "code_run_waited_out",
            Self::RunBinding(_) => "code_run_binding_failed",
            Self::Run(_) => "code_run_failed",
        }
    }
}

/// The server-local, INJECTED `execute_code` seam.
///
/// ONE-1704 owns the MCP bridge, not a new engine runtime: the host is bound
/// once by route/provider wiring and this crate never evaluates anything of its
/// own. With no host bound, `execute_code` fails CLOSED — it does not fall back
/// to a gateway-local loop.
pub trait McpCodeExecutionHost: Send + Sync {
    /// Only a host with a verified production interpreter may enter tools/list.
    fn production_runtime_available(&self) -> bool {
        false
    }

    fn execute<'a>(
        &'a self,
        request: McpCodeExecutionRequest<'a>,
    ) -> Pin<
        Box<dyn Future<Output = Result<EngineExecutorOutcome, McpCodeExecutionError>> + Send + 'a>,
    >;

    /// The engine-native host behind this seam, for a host worker that runs
    /// on the same provider and run permits; `None` for any other host.
    fn engine_native(&self) -> Option<&McpEngineNativeCodeHost> {
        None
    }
}

/// The engine-native pieces one durable run needs, bound by the HOST.
///
/// The server owns no LLM backend or budget lease, so the provider binds
/// these to the engine runtime. The shipped QuickJS provider verifies its artifact. The ADAPTER below
/// — not the provider — is what constructs `HostSelfDispatcher`/`GatedActorWrite`
/// and enters the sandbox/REPL through `EngineNativeExecutor`.
pub trait McpCodeModeProvider: Send + Sync {
    /// Defaults closed for fixture and custom providers.
    fn production_runtime_available(&self) -> bool {
        false
    }

    /// The backend the durable REPL generates each step against.
    fn backend(&self) -> &dyn LlmBackend;
    /// The admission lease every generated step is charged to.
    fn lease(&self) -> &BudgetLease;
    /// A FRESH sandbox/REPL runtime for one run.
    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send>;
    /// A fresh sandbox runtime for one reader child, never a sibling of its
    /// parent's. A provider that can share compiled code across children
    /// overrides it.
    fn reader_runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        self.runtime()
    }
    /// The backend one reader child's model calls go through, each spent on
    /// `meter`, its own child scope's guard. `None`: the provider has no
    /// metered backend to give, and the child does not run.
    fn reader_backend(&self, _meter: BudgetGuard) -> Option<Arc<dyn LlmBackend>> {
        None
    }
    /// The input window, in tokens, of the model reader children and
    /// summaries run on; `None` when the host knows none, and a seat names
    /// [`oneiron::code_run::DEFAULT_READER_WINDOW_TOKENS`].
    fn reader_window_tokens(&self) -> Option<u64> {
        None
    }
    /// The executor configuration for this run, in the vault it lives in.
    fn executor_config(
        &self,
        vault: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig>;
    /// A compaction seat for a run the host holds none for, its summaries
    /// bylined `byline`, its passes queued in `credential`'s turn, its calls
    /// spent under `spend` when the run spends under a scope; `None` keeps
    /// the run's window raw.
    fn compaction(
        &self,
        _byline: WriteActor,
        _credential: &str,
        _spend: Option<&SpendScopeId>,
    ) -> Option<RunCompaction> {
        None
    }
    /// The host's typed seat pick, above the raw backend; absent for legacy vaults.
    fn seat_decisions(&self) -> Option<&SeatDecisions> {
        None
    }
    /// Host-owned capability profile, never taken from execute_code arguments.
    fn seat_facet(&self) -> Option<&str> {
        None
    }
    /// Shadow mode's type check of each generated program; absent when the
    /// host's `[models.code_mode.check]` mode is `off`.
    fn code_check(&self) -> Option<&oneiron_code_check::ShadowCheck> {
        None
    }
}

/// Builds one run's compaction seat from the run's write actor, the
/// credential its passes queue under (its registered fingerprint's stream
/// connection) and the spend scope its calls spend under, if any.
pub type RunCompactionSeat =
    Arc<dyn Fn(WriteActor, &str, Option<&SpendScopeId>) -> RunCompaction + Send + Sync>;

/// Builds one reader child's backend over the host's model, its calls spent
/// on the guard it is given.
pub type ReaderMeter = Arc<dyn Fn(BudgetGuard) -> Arc<dyn LlmBackend> + Send + Sync>;

/// How many `execute_code` runs one server works on at once.
///
/// Each run is an OS thread with its own reactor and sandbox runtime, so the
/// bound is on runs, not calls: a run holds its place until its worker ends,
/// whether or not its caller is still waiting. Past the bound a run waits its
/// turn, round-robin across credentials; it is never refused for count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeRunLimits {
    /// Runs at once, across every credential.
    pub total: usize,
    /// How long a run waits for its turn.
    pub wait: Duration,
}

/// What one run may come to in memory: its sandbox store's ceiling eight
/// times over, for the interpreter, the reactor and the run's own state.
const RUN_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

impl CodeRunLimits {
    /// The runs this machine has room for: four a core, as runs mostly wait
    /// on model calls, and no more than its memory holds.
    #[must_use]
    pub fn runs_for_this_machine() -> usize {
        let by_cores = crate::machine::cores().saturating_mul(4);
        let by_memory = crate::machine::memory_bytes().map_or(by_cores, |bytes| {
            usize::try_from(bytes / RUN_MEMORY_BYTES).unwrap_or(usize::MAX)
        });
        by_cores.min(by_memory).max(1)
    }
}

impl Default for CodeRunLimits {
    fn default() -> Self {
        Self {
            total: Self::runs_for_this_machine(),
            wait: crate::config::LimitsConfig::default().queue_wait(),
        }
    }
}

/// The PRODUCTION adapter: the injected provider, entered through the engine's
/// own durable executor.
pub struct McpEngineNativeCodeHost {
    provider: Arc<dyn McpCodeModeProvider>,
    active: Arc<Mutex<HashSet<EntityId>>>,
    seats: Arc<Mutex<RunSeats>>,
    /// Keyed by the credential's stream connection, its registered
    /// fingerprint.
    runs: Admission<String>,
    /// Where each run's seat to spawn reader children comes from; none
    /// binds no seat, and `self.spawn` answers `reader_spawn_unbound`.
    reader_seats: Option<Arc<crate::server::ReaderSeats>>,
}

impl fmt::Debug for McpEngineNativeCodeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpEngineNativeCodeHost").finish()
    }
}

impl McpEngineNativeCodeHost {
    /// A host running at most `limits.total` runs at once; past it a run
    /// waits, and the crossing asks in `questions`.
    #[must_use]
    pub fn new(
        provider: Arc<dyn McpCodeModeProvider>,
        limits: CodeRunLimits,
        questions: Arc<LimitQuestions>,
    ) -> Self {
        Self {
            provider,
            active: Arc::new(Mutex::new(HashSet::new())),
            seats: Arc::default(),
            runs: Admission::new(LimitRow::CodeRuns, questions, limits.total, limits.wait),
            reader_seats: None,
        }
    }

    /// Lends each run a seat to spawn reader children under, from `seats`,
    /// which notes where the run's caller sits for its children's reads.
    #[must_use]
    pub(crate) fn with_reader_seats(mut self, seats: Arc<crate::server::ReaderSeats>) -> Self {
        self.reader_seats = Some(seats);
        self
    }

    /// The provider every run of this host executes on.
    pub(crate) fn provider(&self) -> &Arc<dyn McpCodeModeProvider> {
        &self.provider
    }

    /// The permits every run of this host waits its turn for, an
    /// `execute_code` run's and a host worker's alike.
    pub(crate) fn runs(&self) -> &Admission<String> {
        &self.runs
    }
}

impl McpCodeExecutionHost for McpEngineNativeCodeHost {
    fn production_runtime_available(&self) -> bool {
        self.provider.production_runtime_available()
    }

    fn engine_native(&self) -> Option<&McpEngineNativeCodeHost> {
        Some(self)
    }

    fn execute<'a>(
        &'a self,
        request: McpCodeExecutionRequest<'a>,
    ) -> Pin<
        Box<dyn Future<Output = Result<EngineExecutorOutcome, McpCodeExecutionError>> + Send + 'a>,
    > {
        let vault = Arc::clone(&request.vault);
        let provider = Arc::clone(&self.provider);
        let active = Arc::clone(&self.active);
        let seats = Arc::clone(&self.seats);
        let write_actor = request.actor.write_actor();
        let placement = (request.actor.scope.world_ref, request.actor.scope.facet_ref);
        let verbs = Arc::clone(&request.verbs);
        // The gated run source is HOST-derived: the caller's handle is a label
        // inside it, never the WHO.
        let run_ref = format!("mcp.execute_code:{}", request.run_ref);
        let reader_seats = self.reader_seats.clone();
        let runs = &self.runs;
        Box::pin(async move {
            let changed =
                || McpCodeExecutionError::RunBinding("provider changed scoped run identity".into());
            if request.run_id != mcp_code_run_id(request.run_ref, request.actor) {
                return Err(changed());
            }
            let guard = ActiveRun::acquire(active, request.run_id)?;
            // The run's children spend under its launch's root scope, on a
            // clock one window from its first spawn.
            let reader_seat = reader_seats.as_ref().and_then(|lent| {
                crate::server::run_launch_scope(request.run_id).map(|spend| {
                    lent.seat(
                        request.run_id,
                        spend,
                        request.actor.locality(),
                        provider.reader_window_tokens(),
                    )
                })
            });
            // Past the bound the run waits its credential's turn. The permit
            // moves into the worker below, so a caller who hangs up frees
            // nothing its run still holds.
            let permit = runs
                .admit(request.actor.stream_connection.0.clone())
                .await
                .map_err(|_| McpCodeExecutionError::RunWaitedOut)?;
            // Read under single-flight: what the provider derives from the
            // run's record is not raced by another attempt making it.
            let config = provider
                .executor_config(&vault, request.run_id, request.task)
                .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?;
            if config.run_id != request.run_id || config.task != request.task {
                return Err(changed());
            }
            let run_id = request.run_id;
            let mut seat = seats
                .lock()
                .map_err(|_| McpCodeExecutionError::RunBinding("run seats poisoned".into()))?
                .take(run_id)
                .or_else(|| {
                    provider.compaction(write_actor, &request.actor.stream_connection.0, None)
                });
            if let Some(seat) = seat.as_mut() {
                // Its summaries are born where the run's credential writes.
                seat.place(placement.0, placement.1);
            }
            let (sender, receiver) = tokio::sync::oneshot::channel();
            // The engine REPL driver holds `&mut dyn JsCodeModeRuntime` across
            // its own awaits, so its future is deliberately not `Send`. It runs
            // on its OWN thread with its OWN current-thread reactor; the
            // gateway task holds no lock and only awaits the answer, so a
            // durable wait never becomes a held connection.
            let worker = std::thread::Builder::new()
                .name("mcp-execute-code".to_owned())
                .spawn(move || {
                    let outcome = run_engine_native_code_mode(
                        &vault,
                        provider.as_ref(),
                        write_actor,
                        &run_ref,
                        &config,
                        verbs,
                        reader_seat,
                        seat.as_mut(),
                    );
                    if let (Some(seat), Ok(mut seats)) = (seat, seats.lock()) {
                        let ended = outcome.as_ref().is_ok_and(|outcome| {
                            matches!(
                                outcome.status,
                                EngineExecutorStatus::Complete
                                    | EngineExecutorStatus::HardStepLimitReached
                            )
                        });
                        seats.put(run_id, seat, ended);
                    }
                    // Completion must release single-flight and the run's
                    // permit before waking an awaiter that may immediately
                    // re-enter this persisted run or start another.
                    drop(guard);
                    drop(permit);
                    let _ = sender.send(outcome);
                })
                .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
            // Detached on purpose: the caller awaits the answer instead of
            // blocking a runtime worker to join it.
            drop(worker);
            receiver.await.map_err(|_| {
                McpCodeExecutionError::Run("execute_code worker ended without a result".to_owned())
            })?
        })
    }
}

/// Enters the EXISTING sandbox/REPL substrate for one durable run.
///
/// This is the whole of what `execute_code` means now: bind the gated write at
/// the host boundary, hand the engine its own runtime, and let
/// `EngineNativeExecutor` own every step, replay row, and terminal marker. The
/// server evaluates nothing and opens no second vault-write path. A run with
/// a seat may spawn reader children under it.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the run's host binding"
)]
fn run_engine_native_code_mode(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    write_actor: WriteActor,
    run_ref: &str,
    config: &EngineExecutorConfig,
    verbs: Arc<dyn oneiron::code_run::AgentVerbDoor>,
    reader_seat: Option<SpawnHostSeat>,
    compaction: Option<&mut RunCompaction>,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    let mut gated_write = GatedActorWrite::new(vault, write_actor, run_ref)
        .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?
        .with_agent_verb_door(verbs);
    if let Some(seat) = reader_seat {
        gated_write = gated_write.with_reader_spawn(seat);
    }
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
    enter_engine_native_run(
        vault,
        provider,
        &gated_write,
        config,
        format!("mcp-execute-code:{}", config.run_id.to_hex()),
        compaction,
        &reactor,
        None,
    )
    .map_err(|error| match error {
        EngineRunError::Binding(error) => McpCodeExecutionError::RunBinding(error),
        EngineRunError::Run(error) => McpCodeExecutionError::Run(error.to_string()),
    })
}

/// Why one entry of an engine-native run did not end: its seat could not be
/// bound, or the executor failed, kept typed so a host can tell a model
/// call that failed for a passing reason from any other failure; only the
/// MCP wire states it as text.
#[derive(Debug)]
pub(crate) enum EngineRunError {
    Binding(String),
    Run(oneiron::engine_executor::EngineExecutorError),
}

impl EngineRunError {
    /// The model call's own failure, when that is why the run stopped.
    pub(crate) fn llm(&self) -> Option<&oneiron::LlmError> {
        match self {
            Self::Run(oneiron::engine_executor::EngineExecutorError::Llm(error)) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for EngineRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(error) => f.write_str(error),
            Self::Run(error) => write!(f, "{error}"),
        }
    }
}

/// A host's own setup failure is a binding failure.
impl From<String> for EngineRunError {
    fn from(error: String) -> Self {
        Self::Binding(error)
    }
}

/// One entry of an engine-native run through `bound`, the write door its
/// host bound: `execute_code`'s credential-gated door, or a leased attempt's
/// own dispatcher. A manifest-backed run is born on its model seat first,
/// warm under `warm_scope`.
///
/// A run that spends under a scope (`spend`: a pumped agent run's, OF-533)
/// makes its model calls on a meter that scope bounds, and what they used is
/// booked on the scope once the entry ends, whatever it answered. With none,
/// the calls run on the provider's own meter.
#[allow(clippy::too_many_arguments)]
pub(crate) fn enter_engine_native_run(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    bound: &GatedActorWrite<'_>,
    config: &EngineExecutorConfig,
    warm_scope: String,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
    spend: Option<&SpendScopeId>,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let binding = |error: oneiron::Error| EngineRunError::Binding(error.to_string());
    let Some(scope) = spend else {
        return enter_on(
            vault,
            provider,
            provider.backend(),
            bound,
            config,
            warm_scope,
            compaction,
            reactor,
        );
    };
    let dispatcher = AgentDispatcher::new(vault);
    let guard = dispatcher.guard_for_scope(scope).map_err(binding)?;
    // The backend a reader child's calls take, on this scope's guard.
    let backend = provider.reader_backend(guard.clone()).ok_or_else(|| {
        EngineRunError::Binding("this code-mode provider cannot meter a spend scope".into())
    })?;
    let entered = enter_on(
        vault,
        provider,
        backend.as_ref(),
        bound,
        config,
        warm_scope,
        compaction,
        reactor,
    );
    dispatcher
        .record_guard_spend(scope, guard.read().used_units)
        .map_err(binding)?;
    entered
}

#[allow(clippy::too_many_arguments)]
fn enter_on(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    backend: &dyn LlmBackend,
    bound: &GatedActorWrite<'_>,
    config: &EngineExecutorConfig,
    warm_scope: String,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let binding = |error: oneiron::Error| EngineRunError::Binding(error.to_string());
    let mut runtime = provider.runtime();
    let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let has_seat = vault.model_manifest().map_err(binding)?.is_some()
        || vault
            .model_seat_receipt(config.run_id)
            .map_err(binding)?
            .is_some();
    let seat = if has_seat {
        let decisions = provider.seat_decisions().ok_or_else(|| {
            EngineRunError::Binding("manifest-backed run requires seat decisions".into())
        })?;
        let facet = provider.seat_facet().ok_or_else(|| {
            EngineRunError::Binding("manifest-backed run requires a capability profile".into())
        })?;
        let task = SeatTask {
            kind: SeatKind::Attempt,
            warm_scope,
            task: config.task.clone(),
            purpose: oneiron::CallPurpose::Other {
                name: oneiron::engine_executor::ENGINE_EXECUTOR_PURPOSE_NAME.into(),
            },
            facet: facet.to_owned(),
            required: Vec::new(),
            min_context_tokens: 1,
            locality: config.model_locality,
            override_model: None,
            override_effort: None,
        };
        Some(
            vault
                .birth_model_seat(config.run_id, &task, decisions)
                .map_err(binding)?,
        )
    } else {
        None
    };
    let mut routed_config = config.clone();
    let mut executor = EngineNativeExecutor::new(vault, backend, provider.lease(), runtime, bound);
    if let Some(seat) = &seat {
        routed_config.model = seat.model().clone();
        routed_config.model_locality = seat.locality();
        routed_config.seat_effort = Some(seat.effort());
        executor = executor.with_model_seat(seat);
    }
    if let Some(seat) = compaction {
        executor = executor.with_compaction(seat);
    }
    if let Some(shadow) = provider.code_check() {
        executor = executor.with_code_check(shadow);
    }
    reactor
        .block_on(executor.run(&routed_config))
        .map_err(EngineRunError::Run)
}

/// A disconnected caller cannot release single-flight while its worker writes.
struct ActiveRun {
    active: Arc<Mutex<HashSet<EntityId>>>,
    run_id: EntityId,
}
impl ActiveRun {
    fn acquire(
        active: Arc<Mutex<HashSet<EntityId>>>,
        run_id: EntityId,
    ) -> Result<Self, McpCodeExecutionError> {
        {
            let mut runs = active
                .lock()
                .map_err(|_| McpCodeExecutionError::RunBinding("run registry poisoned".into()))?;
            if !runs.insert(run_id) {
                return Err(McpCodeExecutionError::RunBusy);
            }
        }
        Ok(Self { active, run_id })
    }
}
impl Drop for ActiveRun {
    fn drop(&mut self) {
        if let Ok(mut runs) = self.active.lock() {
            runs.remove(&self.run_id);
        }
    }
}

static MCP_CODE_EXECUTION_HOST: OnceLock<Arc<dyn McpCodeExecutionHost>> = OnceLock::new();

/// Binds the process's `execute_code` host. Route/provider wiring only.
///
/// Returns `false` when a host is already bound: the seam is set once, so no
/// request-time input can swap the substrate under a live connector.
pub fn bind_mcp_code_execution_host(host: Arc<dyn McpCodeExecutionHost>) -> bool {
    MCP_CODE_EXECUTION_HOST.set(host).is_ok()
}

/// The bound `execute_code` host, or `None` when this process bound none.
#[must_use]
pub fn mcp_code_execution_host() -> Option<&'static Arc<dyn McpCodeExecutionHost>> {
    MCP_CODE_EXECUTION_HOST.get()
}
