//! MCP code-execution host seam and the engine-native host binding.

use super::LiveLeaseBackend;
use super::actors::McpResolvedActor;
use super::run_seats::RunSeats;
use crate::admission::Admission;
use crate::ai_host::live_lease::LeaseLine;
use crate::ai_host::payer_funding::{PayerFault, scope_funding};
use crate::wire_telemetry::{LimitQuestions, LimitRow};
use oneiron::agent_def::AgentModel;
use oneiron::agent_dispatch::{AgentDispatcher, SpawnPlanReceipt, SpendScopeId};
use oneiron::code_run::{
    CompactionHostBinding, GatedActorWrite, SpawnHostSeat, bind_compaction_caller,
};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeRuntime, RunCompaction,
};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::llm::seat::{ModelSeat, SeatDecisions, SeatKind, SeatTask};
use oneiron::task_type::TaskTypeRef;
use oneiron::{BudgetGuard, BudgetLease, EntityId, LlmBackend, ModelLocality, Vault, WriteActor};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

mod active_run;
mod description_route;
mod off_record_run;
use self::active_run::ActiveRuns;
pub(crate) use self::off_record_run::{OffRecordRunSession, off_record_run_id};

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
    #[error(
        "execute_code waited past limits.queue_wait_timeout_ms for a run's turn; no run was started; retry"
    )]
    RunWaitedOut,
    #[error("execute_code run binding failed: {0}")]
    RunBinding(String),
    #[error("execute_code run failed: {0}")]
    Run(String),
    /// A model call no provider answered stopped the run (FIX 3194): its
    /// step is kept, and the same `run_ref` enters it again from its next
    /// step once `retry_after` seconds have passed.
    #[error(
        "execute_code run stopped: no provider answered a model call; call again with the same run_ref in {retry_after} s"
    )]
    ProviderUnavailable { retry_after: u64 },
}

impl McpCodeExecutionError {
    /// The stable wire code this refusal carries.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::HostUnbound => super::MCP_CODE_HOST_UNBOUND_CODE,
            Self::RunWaitedOut => "code_run_waited_out",
            Self::RunBinding(_) => "code_run_binding_failed",
            Self::Run(_) => "code_run_failed",
            Self::ProviderUnavailable { .. } => "model_unavailable",
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
    /// `meter` (its own child scope's guard, or [`Self::host_meter`]) and
    /// billed to `payer` when a room's scope pays (OF-531). `None`: the
    /// provider has no metered backend to give, and the child does not run.
    fn reader_backend(
        &self,
        _meter: BudgetGuard,
        _payer: Option<PayerPerson>,
    ) -> Option<Arc<dyn LlmBackend>> {
        None
    }
    /// The meter the host runs a run's own model calls on when the run
    /// spends under no scope (served code mode's shared guard): the reader
    /// children of such a run spend on it too. `None`: the provider has none
    /// to lend, and such a child does not run.
    fn host_meter(&self) -> Option<BudgetGuard> {
        None
    }
    /// The input window, in tokens, of the model reader children and
    /// summaries run on; `None` when the host knows none, and a seat names
    /// [`oneiron::code_run::DEFAULT_READER_WINDOW_TOKENS`].
    fn reader_window_tokens(&self) -> Option<u64> {
        None
    }
    /// The ports scoped child `job` (FIX 7507) runs its lent verbs on: the
    /// host's registered adapters, each serving exact verbs. The default
    /// registers none, so a job that lends a port reports it unbound and
    /// never runs as a read child in its place.
    fn scoped_child_ports(
        &self,
        _job: &oneiron::code_run::ReaderJob,
    ) -> Option<Arc<dyn oneiron::code_run::ScopedChildPorts>> {
        None
    }
    /// The per-job profiles a host's own scoped children run on (FIX
    /// 7508): a host that queues one registers its backend, meter, model and
    /// ports here by its task before it queues it. The default keeps none,
    /// and every scoped child runs as before.
    fn scoped_child_hosts(&self) -> Option<&oneiron::code_run::ScopedChildHosts> {
        None
    }
    /// The executor configuration for this run, in the vault it lives in.
    fn executor_config(
        &self,
        vault: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig>;
    /// [`Self::executor_config`] for a run its host entered through `bound`,
    /// the dispatcher it bound to the run on the run's own route: what the
    /// config reads from the run's record (its first start) is read there,
    /// so a session-bound run reads its room's record, never base's. The
    /// default reads nothing of the record: it answers
    /// [`Self::executor_config`].
    fn executor_config_on(
        &self,
        vault: &Vault,
        _bound: &GatedActorWrite<'_>,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        self.executor_config(vault, run_id, task)
    }
    /// The model the code-mode template runs on, read without entering a
    /// run (FIX 4659). The default reads it from the config of a run keyed
    /// by `caller`, which nothing enters; a provider that holds its template
    /// answers it directly.
    fn template_model(&self, vault: &Vault, caller: EntityId) -> oneiron::Result<oneiron::ModelId> {
        self.executor_config(vault, caller, "")
            .map(|config| config.model)
    }
    /// A compaction seat for a run the host holds none for, its summaries
    /// bylined by the actor `host` authenticated (who also writes them, when
    /// its profile names `self`, FIX 4465), its passes queued in
    /// `credential`'s turn, its calls spent under `spend` when the run spends
    /// under a scope; `None` keeps the run's window raw.
    fn compaction(
        &self,
        _host: CompactionHostBinding,
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
    /// The host's type-feedback service (FIX 8277), shared by every run;
    /// absent, each step's feedback says no checker is attached.
    fn code_check(&self) -> Option<&oneiron::engine_executor::TypeFeedback> {
        None
    }
    /// The seats a leased agent's planned spawns choose among
    /// (`[models.planner]`); absent, the host lends no planner.
    fn planner(&self) -> Option<&crate::config::models::PlannerSettings> {
        None
    }
    /// The runs' browser planner states (CUA E5): one per run, beside its
    /// browser seat, which the run's guest door binds and feeds and this
    /// provider's backend routes each step's call by, on the same meter and
    /// payer. `None`: every step's call takes the chat role, as before.
    fn browser_planner(&self) -> Option<&crate::ai_host::browser_planner::BrowserPlannerRuns> {
        None
    }
    /// Where this provider's own backend serves `pick`, a planned child's
    /// model, when it lists that model and can route it exactly now (FIX
    /// 2310, Engine C1/C2). `None`, as for a provider with no list: the child
    /// runs as it would today.
    fn planned_route(&self, _vault: &Vault, _pick: &oneiron::ModelId) -> Option<ModelLocality> {
        None
    }
    /// The backend a planned child's own calls go through, on `meter` and
    /// billed to `payer` as [`Self::reader_backend`]'s are, bound to
    /// `planned`: its pick exactly when its host pinned it, else the
    /// provider's own model with the substitution on its receipts (FIX
    /// 2310). `None`: the provider has none, and the child takes the backend
    /// it would take today.
    fn planned_backend(
        &self,
        _meter: BudgetGuard,
        _payer: Option<PayerPerson>,
        _planned: &PlannedModel,
    ) -> Option<Arc<dyn LlmBackend>> {
        None
    }
    /// [`Self::compaction`] for a planned child (FIX 2310, Engine C5): its
    /// live admission sees the same binding its calls do. The default is
    /// [`Self::compaction`]'s.
    fn planned_compaction(
        &self,
        host: CompactionHostBinding,
        credential: &str,
        spend: Option<&SpendScopeId>,
        _planned: &PlannedModel,
    ) -> Option<RunCompaction> {
        self.compaction(host, credential, spend)
    }
}

/// A planned child that no seat binds (FIX 2310, OF-541): the run, the
/// model its frozen plan picked, and whether its host pinned the run to it
/// at the run's first entry. A pinned child runs its pick exactly; any
/// other runs the provider's own model, and each call another model
/// answers is marked on its receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedModel {
    pub child: EntityId,
    pub pick: oneiron::ModelId,
    pub exact: bool,
}

impl PlannedModel {
    /// Marks the call `run` admitted when `ran`, the model that answered
    /// it, is not the pick: nothing substitutes silently.
    pub(crate) fn answered(&self, run: &RunAdmission, ran: oneiron::ModelId) {
        if ran != self.pick {
            run.record_plan_model_substituted(self.child, self.pick.clone(), ran);
        }
    }
}

/// Where a provider's backend serves a planned child's pick, when it can
/// route it exactly (`McpCodeModeProvider::planned_route`).
pub type PlannedRoute =
    Arc<dyn Fn(&Vault, &oneiron::ModelId) -> Option<ModelLocality> + Send + Sync>;

/// Builds a planned child's backend over the host's model, on the guard it
/// is given and billed to the payer, when one is given, bound to its plan
/// (`McpCodeModeProvider::planned_backend`).
pub type PlannedMeter = Arc<
    dyn Fn(BudgetGuard, Option<PayerPerson>, &PlannedModel) -> Arc<dyn LlmBackend> + Send + Sync,
>;

/// Builds one run's compaction seat from the run's authenticated host
/// binding (its write actor, its caller's place and its proof), the
/// credential its passes queue under (its registered fingerprint's stream
/// connection) and the spend scope its calls spend under, if any.
pub type RunCompactionSeat =
    Arc<dyn Fn(CompactionHostBinding, &str, Option<&SpendScopeId>) -> RunCompaction + Send + Sync>;

/// Builds one reader child's backend over the host's model, its calls spent
/// on the guard it is given and billed to the payer, when one is given.
pub type ReaderMeter =
    Arc<dyn Fn(BudgetGuard, Option<PayerPerson>) -> Arc<dyn LlmBackend> + Send + Sync>;

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
    /// Each run's single flight: one entry at a time, the next in arrival
    /// order (FIX 9505).
    active: ActiveRuns,
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
            active: ActiveRuns::new(limits.wait),
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
        let active = &self.active;
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
            // A second entry of a run still running waits behind it, in
            // arrival order, holding no permit while it waits (FIX 9505).
            let guard = active.acquire(request.run_id).await?;
            // The run spends under no scope, so its children spend on the
            // host's meter, as its own calls do, on a clock one window from
            // its first spawn.
            let reader_seat = reader_seats.as_ref().map(|lent| {
                lent.seat(
                    request.run_id,
                    None,
                    request.actor.destination(),
                    provider.reader_window_tokens(),
                )
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
            // The slip the caller's credential proved at admission: it and
            // its parent are the run's own lineage (FIX 4705). Never a tool
            // argument.
            let opener = request
                .actor
                .auth
                .as_ref()
                .and_then(|auth| auth.verified_slip())
                .cloned();
            let mut seat = seats
                .lock()
                .map_err(|_| McpCodeExecutionError::RunBinding("run seats poisoned".into()))?
                .take(run_id)
                .or_else(|| {
                    // The host's own binding of the caller: the actor its
                    // credential writes as, where its connection sits and
                    // the slip it proved. Never a tool argument.
                    let host = bind_compaction_caller(
                        write_actor,
                        request.actor.locality(),
                        opener.clone(),
                    );
                    provider.compaction(host, &request.actor.stream_connection.0, None)
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
                        opener.as_ref(),
                        reader_seat,
                        seat.as_mut(),
                    );
                    if let (Some(seat), Ok(mut seats)) = (seat, seats.lock()) {
                        let ended = outcome.as_ref().is_ok_and(|outcome| {
                            matches!(outcome.status, EngineExecutorStatus::Complete)
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
/// a seat may spawn reader children under it. A run its caller's credential
/// admitted binds that slip's lineage as its own (FIX 4705).
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
    opener: Option<&oneiron::authority::VerifiedSlip>,
    reader_seat: Option<SpawnHostSeat>,
    compaction: Option<&mut RunCompaction>,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    let mut gated_write = GatedActorWrite::new(vault, write_actor, run_ref)
        .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?
        .with_agent_verb_door(verbs);
    if let Some(opener) = opener {
        gated_write = gated_write.with_opener_credential(opener);
    }
    if let Some(seat) = reader_seat {
        gated_write = gated_write.with_reader_spawn(seat);
    }
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
    let seat = engine_run_seat(
        vault,
        provider,
        config,
        format!("mcp-execute-code:{}", config.run_id.to_hex()),
        None,
        Vec::new(),
    )
    .map_err(McpCodeExecutionError::RunBinding)?;
    enter_engine_native_run(
        vault,
        provider,
        &gated_write,
        config,
        compaction,
        &reactor,
        None,
        seat.as_ref(),
        // An `execute_code` run is no planned child.
        None,
    )
    .map_err(|error| match error.provider_outage() {
        Some(retry_after) => McpCodeExecutionError::ProviderUnavailable { retry_after },
        None => match error {
            EngineRunError::Binding(error) => McpCodeExecutionError::RunBinding(error),
            EngineRunError::Run(error) => McpCodeExecutionError::Run(error.to_string()),
            EngineRunError::Payer(fault) => McpCodeExecutionError::RunBinding(fault.to_string()),
        },
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
    /// The run's spend scope names no payer it can bill (OF-531).
    Payer(PayerFault),
}

impl EngineRunError {
    /// The model call's own failure, when that is why the run stopped.
    pub(crate) fn llm(&self) -> Option<&oneiron::LlmError> {
        match self {
            Self::Run(oneiron::engine_executor::EngineExecutorError::Llm(error)) => Some(error),
            _ => None,
        }
    }

    /// The seconds until a host door's model call that no provider answered
    /// may be sent again, when that outage is why the run stopped (FIX 3194).
    pub(crate) fn provider_outage(&self) -> Option<u64> {
        match self {
            Self::Run(oneiron::engine_executor::EngineExecutorError::Engine(
                oneiron::Error::ProviderUnavailable { retry_after },
            )) => Some(*retry_after),
            _ => None,
        }
    }
}

impl fmt::Display for EngineRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(error) => f.write_str(error),
            Self::Run(error) => write!(f, "{error}"),
            Self::Payer(fault) => write!(f, "{fault}"),
        }
    }
}

/// A host's own setup failure is a binding failure.
impl From<String> for EngineRunError {
    fn from(error: String) -> Self {
        Self::Binding(error)
    }
}

/// The meter one entry of a run that spends under a scope makes its model
/// calls on (OF-533): a guard that scope bounds, opened by the entry's host so
/// the run's other calls (its `ai.speech`, FIX 3194) spend on the same one,
/// and the payer a room-paid scope bills (OF-531).
pub(crate) struct ScopeMeter<'a> {
    pub(crate) scope: &'a SpendScopeId,
    pub(crate) guard: BudgetGuard,
    pub(crate) payer: Option<PayerPerson>,
    /// The entry's one live lease on `guard`, lent to its other calls on
    /// the same meter so they look before they are admitted and book once
    /// (FIX 11747).
    pub(crate) lease: LeaseLine,
}

impl<'a> ScopeMeter<'a> {
    /// Opens `scope`'s meter for one entry: its guard's limit is what the
    /// scope may still spend.
    pub(crate) fn open(vault: &Vault, scope: &'a SpendScopeId) -> Result<Self, EngineRunError> {
        // A room-paid scope's calls bill its root payer (OF-531), else it holds.
        let payer = scope_funding(vault, Some(scope), false).map_err(EngineRunError::Payer)?;
        let guard = AgentDispatcher::new(vault)
            .guard_for_scope(scope)
            .map_err(|error| EngineRunError::Binding(error.to_string()))?;
        Ok(Self {
            lease: LeaseLine::new(scope.clone(), guard.clone()),
            scope,
            guard,
            payer,
        })
    }
}

/// One entry of an engine-native run through `bound`, the write door its
/// host bound: `execute_code`'s credential-gated door, or a leased attempt's
/// own dispatcher. A manifest-backed run runs on `seat`, the model seat its
/// host bore it on (`engine_run_seat`); a run with none takes its configured
/// model.
///
/// A run that spends under a scope (`spend`: a pumped agent run's, OF-533)
/// makes its model calls on the meter its host opened for the entry, read
/// live ([`LiveLease`]): each call is admitted against what the scope has
/// left then, and what no call's look booked is booked once the entry ends,
/// whatever it answered. With none, the calls run on the provider's own meter.
///
/// A planned child no seat binds (`planned`, FIX 2310) makes its calls
/// through the provider's planned backend on that same meter and payer,
/// bound to its plan; with a provider that has none, through the backend it
/// takes today.
#[allow(clippy::too_many_arguments)]
pub(crate) fn enter_engine_native_run(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    bound: &GatedActorWrite<'_>,
    config: &EngineExecutorConfig,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
    spend: Option<ScopeMeter<'_>>,
    seat: Option<&ModelSeat>,
    planned: Option<&PlannedModel>,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let Some(ScopeMeter {
        guard,
        payer,
        lease,
        ..
    }) = spend
    else {
        let own = planned
            .and_then(|planned| provider.planned_backend(provider.host_meter()?, None, planned));
        let backend: &dyn LlmBackend = match &own {
            Some(backend) => backend.as_ref(),
            None => provider.backend(),
        };
        return enter_on(
            vault, provider, backend, bound, config, compaction, reactor, seat,
        );
    };
    // The backend a reader child's calls take, on this scope's guard; a
    // planned child's is bound to its plan as well.
    let backend = planned
        .and_then(|planned| provider.planned_backend(guard.clone(), payer.clone(), planned))
        .or_else(|| provider.reader_backend(guard.clone(), payer));
    let backend = backend.ok_or_else(|| {
        EngineRunError::Binding("this code-mode provider cannot meter a spend scope".into())
    })?;
    // The lease the entry's door and planner runner were lent: one ledger.
    let live = lease.on(vault);
    let entered = enter_on(
        vault,
        provider,
        &LiveLeaseBackend::new(&live, backend.as_ref()),
        bound,
        config,
        compaction,
        reactor,
        seat,
    );
    live.book_rest()
        .map_err(|error| EngineRunError::Binding(error.to_string()))?;
    entered
}

/// The model a planned child's seat is born on (OF-541): the one its plan
/// picked, so the child runs the model its receipt states. The seat pool
/// admits that model alone, so a host that cannot seat it refuses the
/// birth rather than seat another. The plan's effort is not pinned: it
/// follows the plan's care, and the seat's own ladder picks the effort
/// that model takes. An unplanned run pins nothing.
fn planned_seat(plan: Option<&SpawnPlanReceipt>) -> Option<oneiron::ModelId> {
    plan.map(|plan| plan.plan.model.clone())
}

/// The seat a run's model calls are bound to: born once for `run_id` on a
/// manifest-backed vault, or the one it was born on; `None` on a vault with
/// neither, whose run takes its configured model. `task` builds the birth's
/// task from the host's capability profile. A run, a reader child and a
/// summary job are each born on one this way. `parent_at`, the cutoff of the
/// parent a child is born under, bounds a fresh pick (FIX 8230); `None`, the
/// seat budget alone.
pub(crate) fn run_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    run_id: EntityId,
    parent_at: Option<Instant>,
    task: impl FnOnce(&str) -> SeatTask,
) -> Result<Option<ModelSeat>, String> {
    seat_for(
        vault,
        provider,
        run_id,
        SeatPin::Base(None),
        parent_at,
        task,
    )
}

impl dyn McpCodeModeProvider + '_ {
    /// [`run_seat`] for a run its host bound on `bound`'s route (FIX 2594):
    /// the same eligibility and effort rules, its prior receipt read and its
    /// seat born on that route, so a session-bound run's pin is its room's,
    /// never base's. A reader child and a summary job in an off-record
    /// session are each born on one this way; a canonical one's route is
    /// base, as [`run_seat`]'s is.
    pub(crate) fn run_seat_on(
        &self,
        vault: &Vault,
        bound: &GatedActorWrite<'_>,
        run_id: EntityId,
        parent_at: Option<Instant>,
        task: impl FnOnce(&str) -> SeatTask,
    ) -> Result<Option<ModelSeat>, String> {
        seat_for(vault, self, run_id, SeatPin::Routed(bound), parent_at, task)
    }
}

/// An agent run's seat (DOOR-111 S5), born as `run_seat` births one and
/// stamped with `type_ref`, the stamp its dispatch carried, so the run's
/// route reads with its own stamp. A manifest-free vault still bears none.
pub(crate) fn task_run_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    run_id: EntityId,
    type_ref: &TaskTypeRef,
    task: impl FnOnce(&str) -> SeatTask,
) -> Result<Option<ModelSeat>, String> {
    let pin = SeatPin::Base(Some(type_ref));
    seat_for(vault, provider, run_id, pin, None, task)
}

/// Where a run's seat pin is read and born: the base vault, generic or
/// stamped with the type its dispatch carried, or the route its host bound
/// the run's dispatcher on, generic.
enum SeatPin<'p, 'd> {
    Base(Option<&'p TaskTypeRef>),
    Routed(&'p GatedActorWrite<'d>),
}

/// The one birth every seat shares, wherever `pin` puts it. The model
/// catalog and manifest are the vault's own; the run's prior receipt is read
/// where its pin lives.
fn seat_for(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    run_id: EntityId,
    pin: SeatPin<'_, '_>,
    parent_at: Option<Instant>,
    task: impl FnOnce(&str) -> SeatTask,
) -> Result<Option<ModelSeat>, String> {
    let has_seat = vault
        .model_manifest()
        .map_err(|error| error.to_string())?
        .is_some()
        || match &pin {
            SeatPin::Base(_) => vault.model_seat_receipt(run_id),
            SeatPin::Routed(bound) => bound.model_seat_receipt(run_id),
        }
        .map_err(|error| error.to_string())?
        .is_some();
    if !has_seat {
        return Ok(None);
    }
    let decisions = provider
        .seat_decisions()
        .ok_or("manifest-backed run requires seat decisions")?;
    let facet = provider
        .seat_facet()
        .ok_or("manifest-backed run requires a capability profile")?;
    let task = task(facet);
    match pin {
        // A typed run is born on its description route when one applies (FIX 11307).
        SeatPin::Base(Some(type_ref)) => {
            description_route::task_seat(vault, run_id, type_ref, &task, decisions, parent_at)
        }
        SeatPin::Base(None) => vault.birth_model_seat(run_id, &task, decisions, parent_at),
        SeatPin::Routed(bound) => {
            bound.birth_model_seat(vault, run_id, &task, decisions, parent_at)
        }
    }
    .map(Some)
    .map_err(|error| error.to_string())
}

/// The seat an engine-native run is born on (`run_seat`), warm under
/// `warm_scope`, from `config`'s task as it stands now. A host that adds to
/// the task later lends this one seat to each entry, so the seat's task
/// stays the run's own. A planned child (`plan`: the receipt its spawn
/// froze, OF-541) is born on the seat its plan picked (`planned_seat`).
/// An agent's run is born on a model its definition lists (`listed`, FIX
/// 4472); a run with no agent, or an agent that lists none, passes none.
pub(crate) fn engine_run_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    config: &EngineExecutorConfig,
    warm_scope: String,
    plan: Option<&SpawnPlanReceipt>,
    listed: Vec<AgentModel>,
) -> Result<Option<ModelSeat>, String> {
    let model = planned_seat(plan);
    run_seat(vault, provider, config.run_id, None, |facet| {
        engine_seat_task(config, facet, warm_scope, model, listed)
    })
}

/// An agent run's seat as `engine_run_seat` births one, stamped with its
/// dispatch's `type_ref` (`task_run_seat`).
pub(crate) fn task_engine_run_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    config: &EngineExecutorConfig,
    warm_scope: String,
    type_ref: &TaskTypeRef,
    plan: Option<&SpawnPlanReceipt>,
    listed: Vec<AgentModel>,
) -> Result<Option<ModelSeat>, String> {
    let model = planned_seat(plan);
    task_run_seat(vault, provider, config.run_id, type_ref, |facet| {
        engine_seat_task(config, facet, warm_scope, model, listed)
    })
}

/// The task an engine-native run's seat is born for, from `config` as it
/// stands now.
fn engine_seat_task(
    config: &EngineExecutorConfig,
    facet: &str,
    warm_scope: String,
    override_model: Option<oneiron::ModelId>,
    listed: Vec<AgentModel>,
) -> SeatTask {
    SeatTask {
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
        override_model,
        override_effort: None,
        listed,
    }
}

#[allow(clippy::too_many_arguments)]
fn enter_on(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    backend: &dyn LlmBackend,
    bound: &GatedActorWrite<'_>,
    config: &EngineExecutorConfig,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
    seat: Option<&ModelSeat>,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let mut runtime = provider.runtime();
    let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let mut routed_config = config.clone();
    let mut executor = EngineNativeExecutor::new(vault, backend, provider.lease(), runtime, bound);
    if let Some(seat) = seat {
        routed_config.model = seat.model().clone();
        routed_config.model_locality = seat.locality();
        routed_config.seat_effort = Some(seat.effort());
        executor = executor.with_model_seat(seat);
    }
    if let Some(seat) = compaction {
        executor = executor.with_compaction(seat);
    }
    if let Some(feedback) = provider.code_check() {
        executor = executor.with_code_check(feedback);
    }
    reactor
        .block_on(executor.run(&routed_config))
        .map_err(EngineRunError::Run)
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
