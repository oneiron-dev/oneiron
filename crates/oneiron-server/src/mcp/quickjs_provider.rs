//! Production MCP provider over the hash-pinned engine QuickJS component.

use super::{
    McpCodeModeProvider, PlannedMeter, PlannedModel, PlannedRoute, ReaderMeter, RunCompactionSeat,
};
use oneiron::agent_dispatch::SpendScopeId;
use oneiron::code_run::{
    CodeRunDeterminism, CompactionHostBinding, GatedActorWrite, ReaderJob, ScopedChildHosts,
    ScopedChildPorts,
};
use oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron::code_sandbox::wasmtime_runtime::{ComponentBudget, WasmtimeComponentRuntime};
use oneiron::engine_executor::{
    EngineExecutorConfig, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
    RunCompaction, TypeFeedback,
};
use oneiron::llm::SingleRouteBackend;
use oneiron::llm::run_admission::{PayerPerson, RunReceiptSink};
use oneiron::llm::seat::SeatDecisions;
use oneiron::{
    BudgetGuard, BudgetLease, EntityId, LlmBackend, LlmError, ModelId, ModelLocality, Vault,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::ai_host::browser_planner::BrowserPlannerRuns;
use crate::models::{InjectedRuns, LoggedReceipts, ModelRouter};

/// The first-party component this repository builds and reviews, and the
/// manifest that pins it.
const CHECKED_IN_COMPONENT: &[u8] =
    include_bytes!("../../../../components/code-run-quickjs/artifacts/quickjs-first-party.wasm");
const CHECKED_IN_MANIFEST: &str =
    include_str!("../../../../components/code-run-quickjs/artifacts/manifest.json");

/// The checked-in component, verified against its reviewed SHA-256 pin and
/// readiness-probed. Compiles the component, so call it off the async runtime.
pub fn checked_in_quickjs_runtime() -> oneiron::Result<QuickJsRuntimeFactory> {
    let invalid =
        || oneiron::Error::InvalidConfig("QuickJS manifest has no first-party pin".into());
    let manifest: serde_json::Value =
        serde_json::from_str(CHECKED_IN_MANIFEST).map_err(|_| invalid())?;
    let text = manifest["artifacts"]["first-party"]["sha256"]
        .as_str()
        .filter(|text| text.len() == 64 && text.is_ascii())
        .ok_or_else(invalid)?;
    let mut pin = [0; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    QuickJsRuntimeFactory::from_component(CHECKED_IN_COMPONENT, pin, ComponentBudget::default())
}

/// The lease the executor hands every call. The backend below admits and
/// settles each call on its own permit and never charges this one, so it
/// comes from a meter of its own that pays for nothing, never the host's.
fn carrier_lease() -> Result<BudgetLease, oneiron::llm::BudgetDenied> {
    let carrier = BudgetGuard::with_reserve_units(
        "code-mode-carrier",
        1,
        1,
        oneiron::BudgetExhaustionPolicy::Suspend,
    );
    let lease = carrier.admit()?.lease;
    carrier.abort(&lease)?;
    Ok(lease)
}

/// Host configuration, never caller-chosen runtime bytes or native JS source.
/// Construction requires the factory's successful artifact readiness probe.
pub struct McpQuickJsProvider {
    runtime: Arc<QuickJsRuntimeFactory>,
    backend: Arc<dyn LlmBackend>,
    lease: BudgetLease,
    config: EngineExecutorConfig,
    /// Builds each run's compaction seat; none keeps every window raw.
    compaction: Option<RunCompactionSeat>,
    seat_router: Option<(SeatDecisions, String)>,
    /// The router whose served set each seat birth admits its pick from
    /// (FIX 2745); none serves no set, so the birth admits all, as before.
    served_router: Option<Arc<ModelRouter>>,
    /// The seats a leased agent's planned spawns choose among.
    planner: Option<crate::config::models::PlannerSettings>,
    /// Each run's clock is frozen at its first start, and a resumed run keeps
    /// it; otherwise every run shares the configured frozen clock.
    clock_from_first_start: bool,
    /// The host's own model and meter, when the host injected them: rebound
    /// to the server's run receipts when the server takes this provider.
    injected: Option<(Arc<dyn SingleRouteBackend>, BudgetGuard)>,
    /// The host's one type-feedback service, shared by every run.
    code_check: Option<TypeFeedback>,
    /// Builds each reader child's backend on its own meter; none runs no
    /// child.
    reader_meter: Option<ReaderMeter>,
    /// The meter the host runs this provider's own model calls on, lent to
    /// the reader children of a run that spends under no scope; none runs
    /// no such child.
    host_meter: Option<BudgetGuard>,
    /// The runtime reader children are made fresh from, compiled once at
    /// the first child.
    reader_template: Mutex<Option<WasmtimeComponentRuntime>>,
    /// The input window of the model reader children and summaries run
    /// on, in tokens, when the host knows it.
    reader_window_tokens: Option<u64>,
    /// Where this provider's backend serves a planned child's pick, when it
    /// can route it exactly (FIX 2310); none lists no model, so no child is
    /// pinned.
    planned_route: Option<PlannedRoute>,
    /// Builds a planned child's backend on its own meter, bound to its plan;
    /// none runs the child on the backend it takes today.
    planned_meter: Option<PlannedMeter>,
    /// Builds each pinned child's compaction seat, its live admission bound
    /// to the pick as its calls are (Engine C5); none takes `compaction`.
    pinned_compaction: Option<RunCompactionSeat>,
    /// The runs' browser planner states (CUA E5) this provider's backend
    /// routes each step's call by; none routes every call as before.
    browser_planner: Option<Arc<BrowserPlannerRuns>>,
    /// The profiles the scoped children a host queues itself run on, by
    /// task (FIX 7508), and the ports they lend.
    scoped_hosts: ScopedChildHosts,
}

/// A reader child's backend over the host-injected model: its calls are
/// runs on the child's own meter, billed to its payer when a room's scope
/// pays (OF-531), their receipts written to `receipts`.
fn injected_meter(
    backend: Arc<dyn SingleRouteBackend>,
    receipts: Arc<dyn RunReceiptSink>,
) -> ReaderMeter {
    Arc::new(move |meter: BudgetGuard, payer: Option<PayerPerson>| {
        Arc::new(InjectedRuns::funded(
            Arc::clone(&backend),
            meter,
            Arc::clone(&receipts),
            payer,
        )) as Arc<dyn LlmBackend>
    })
}

/// A planned child's backend over the host-injected model (FIX 2310): its
/// calls run as [`injected_meter`]'s do, each answered by the model it
/// names, and one that is not the child's pick is marked on `receipts`. The
/// host lists no model, so no child is pinned (Engine C1).
fn injected_planned(
    backend: Arc<dyn SingleRouteBackend>,
    receipts: Arc<dyn RunReceiptSink>,
) -> PlannedMeter {
    Arc::new(
        move |meter: BudgetGuard, payer: Option<PayerPerson>, planned: &PlannedModel| {
            Arc::new(
                InjectedRuns::funded(Arc::clone(&backend), meter, Arc::clone(&receipts), payer)
                    .with_plan(planned.clone()),
            ) as Arc<dyn LlmBackend>
        },
    )
}

impl McpQuickJsProvider {
    /// A provider over the host's own model. Every model call a generated
    /// step makes is its own run on `meter`, admitted and sent through the
    /// run's gate, so `backend` is a [`SingleRouteBackend`]: one request per
    /// call, which the gate wraps.
    pub fn new(
        runtime: Arc<QuickJsRuntimeFactory>,
        backend: Arc<dyn SingleRouteBackend>,
        meter: BudgetGuard,
        config: EngineExecutorConfig,
    ) -> Result<Self, oneiron::engine_executor::EngineExecutorError> {
        let lease = carrier_lease().map_err(LlmError::from)?;
        let models = InjectedRuns::new(
            Arc::clone(&backend),
            meter.clone(),
            Arc::new(LoggedReceipts),
        );
        let mut provider = Self::gated(runtime, Arc::new(models), lease, config)?;
        provider.reader_meter = Some(injected_meter(
            Arc::clone(&backend),
            Arc::new(LoggedReceipts),
        ));
        provider.planned_meter = Some(injected_planned(
            Arc::clone(&backend),
            Arc::new(LoggedReceipts),
        ));
        provider.host_meter = Some(meter.clone());
        provider.injected = Some((backend, meter));
        Ok(provider)
    }

    /// A provider over a backend that admits and settles each call itself,
    /// through a run's gate (code mode's own). The executor hands `lease` to
    /// every call, and the backend never charges it.
    pub(crate) fn gated(
        runtime: Arc<QuickJsRuntimeFactory>,
        backend: Arc<dyn LlmBackend>,
        lease: BudgetLease,
        config: EngineExecutorConfig,
    ) -> Result<Self, oneiron::engine_executor::EngineExecutorError> {
        config.validate()?;
        Ok(Self {
            runtime,
            backend,
            lease,
            config,
            compaction: None,
            seat_router: None,
            served_router: None,
            planner: None,
            clock_from_first_start: false,
            injected: None,
            code_check: None,
            reader_meter: None,
            host_meter: None,
            reader_template: Mutex::new(None),
            reader_window_tokens: None,
            planned_route: None,
            planned_meter: None,
            pinned_compaction: None,
            browser_planner: None,
            scoped_hosts: ScopedChildHosts::default(),
        })
    }

    /// Writes the host-injected model's run receipts to `receipts`.
    pub(crate) fn with_run_receipts(mut self, receipts: Arc<dyn RunReceiptSink>) -> Self {
        if let Some((backend, meter)) = &self.injected {
            self.reader_meter = Some(injected_meter(Arc::clone(backend), Arc::clone(&receipts)));
            self.planned_meter = Some(injected_planned(Arc::clone(backend), Arc::clone(&receipts)));
            self.backend = Arc::new(InjectedRuns::new(
                Arc::clone(backend),
                meter.clone(),
                receipts,
            ));
        }
        self
    }

    /// Each reader child's model calls go through the backend `meter`
    /// builds on the child's own guard.
    #[must_use]
    pub(crate) fn with_reader_meter(mut self, meter: ReaderMeter) -> Self {
        self.reader_meter = Some(meter);
        self
    }

    /// A planned child no seat binds (FIX 2310) is pinned to its pick where
    /// `route` serves it exactly, and runs on the backend `meter` builds on
    /// its own guard, bound to its plan.
    #[must_use]
    pub(crate) fn with_planned_models(mut self, route: PlannedRoute, meter: PlannedMeter) -> Self {
        self.planned_route = Some(route);
        self.planned_meter = Some(meter);
        self
    }

    /// A pinned child's window compacts on a seat `seat` builds, whose live
    /// admission keeps the child's pick (Engine C5).
    #[must_use]
    pub(crate) fn with_pinned_compaction(mut self, seat: RunCompactionSeat) -> Self {
        self.pinned_compaction = Some(seat);
        self
    }

    /// Each run's browser planner state (CUA E5) lives in `runs`, the one
    /// this provider's backend routes the run's step calls by; the run's
    /// guest door binds it there.
    #[must_use]
    pub(crate) fn with_browser_planner(mut self, runs: Arc<BrowserPlannerRuns>) -> Self {
        self.browser_planner = Some(runs);
        self
    }

    /// The reader children of a run that spends under no scope spend on
    /// `meter`, the one the host runs this provider's own calls on.
    #[must_use]
    pub(crate) fn with_host_meter(mut self, meter: BudgetGuard) -> Self {
        self.host_meter = Some(meter);
        self
    }

    /// The input window, in tokens, of the model reader children and
    /// summaries run on: what `readAll` sizes its chunks and groups by.
    #[must_use]
    pub(crate) fn with_reader_window_tokens(mut self, tokens: u64) -> Self {
        self.reader_window_tokens = (tokens > 0).then_some(tokens);
        self
    }

    /// Freeze each run's clock at its first start instead of the configured
    /// instant: a live host's runs see the time they started, and a run
    /// resumed after a restart keeps the clock its record was made with.
    #[must_use]
    pub fn with_clock_from_first_start(mut self) -> Self {
        self.clock_from_first_start = true;
        self
    }

    /// Each run's window compacts by itself on a seat `seat` builds
    /// (agent-runtime-v1 §d7).
    #[must_use]
    pub fn with_compaction(mut self, seat: RunCompactionSeat) -> Self {
        self.compaction = Some(seat);
        self
    }

    /// Feedback mode: type-check every generated program beside its run
    /// and hand what the check found back with its step (FIX 8277). Nothing
    /// waits on a check or is refused for it.
    #[must_use]
    pub fn with_code_check(mut self, feedback: TypeFeedback) -> Self {
        self.code_check = Some(feedback);
        self
    }

    /// Each seat birth admits only the models `router` serves now, with
    /// where each runs (FIX 2745); without it the birth admits all, as
    /// before. The snapshot is read live per birth, never cached here.
    #[must_use]
    pub(crate) fn with_served_router(mut self, router: Arc<ModelRouter>) -> Self {
        self.served_router = Some(router);
        self
    }

    /// Install the host's typed seat pick and profile for manifest-backed runs.
    #[must_use]
    pub fn with_model_seat_router(
        mut self,
        decisions: SeatDecisions,
        facet: impl Into<String>,
    ) -> Self {
        self.seat_router = Some((decisions, facet.into()));
        self
    }

    /// Lend leased agent runs the host's planner over `planner`'s seats.
    #[must_use]
    pub fn with_planner(mut self, planner: crate::config::models::PlannerSettings) -> Self {
        self.planner = Some(planner);
        self
    }

    /// One run's config: the template's, bound to `run_id` and `task`. When
    /// this host freezes each run's clock at its first start, `first_start`
    /// reads that start from the run's own record, and only a run with none
    /// yet takes the current time. The run's RNG is bound to the run and the
    /// interpreter pin either way.
    fn run_config(
        &self,
        vault: &Vault,
        run_id: EntityId,
        task: &str,
        first_start: impl FnOnce() -> oneiron::Result<Option<u64>>,
    ) -> oneiron::Result<EngineExecutorConfig> {
        let mut config = self.config.clone();
        config.run_id = run_id;
        config.task = task.to_owned();
        if self.clock_from_first_start {
            config.determinism.frozen_unix_ms = match first_start()? {
                Some(frozen_unix_ms) => frozen_unix_ms,
                None => vault.now_recorded_at().saturating_mul(1000),
            };
        }
        // The run's stable determinism marker also binds the interpreter pin.
        // Resume under another artifact fails the existing config-hash check.
        let mut rng = blake3::Hasher::new_keyed(&self.config.determinism.rng_seed);
        rng.update(b"oneiron:mcp-quickjs-run:v1");
        rng.update(run_id.as_bytes());
        rng.update(&self.runtime.sha256());
        config.determinism = CodeRunDeterminism::new(
            config.determinism.frozen_unix_ms,
            *rng.finalize().as_bytes(),
        );
        Ok(config)
    }
}

impl McpCodeModeProvider for McpQuickJsProvider {
    fn production_runtime_available(&self) -> bool {
        true
    }
    fn seat_decisions(&self) -> Option<&SeatDecisions> {
        self.seat_router.as_ref().map(|(decisions, _)| decisions)
    }
    fn seat_facet(&self) -> Option<&str> {
        self.seat_router.as_ref().map(|(_, facet)| facet.as_str())
    }
    fn seat_served(&self) -> Option<BTreeMap<ModelId, ModelLocality>> {
        self.served_router
            .as_ref()
            .map(|router| router.served_models())
    }
    fn planner(&self) -> Option<&crate::config::models::PlannerSettings> {
        self.planner.as_ref()
    }
    fn browser_planner(&self) -> Option<&BrowserPlannerRuns> {
        self.browser_planner.as_deref()
    }
    fn code_check(&self) -> Option<&TypeFeedback> {
        self.code_check.as_ref()
    }
    fn backend(&self) -> &dyn LlmBackend {
        self.backend.as_ref()
    }
    fn compaction(
        &self,
        host: CompactionHostBinding,
        credential: &str,
        spend: Option<&SpendScopeId>,
    ) -> Option<RunCompaction> {
        self.compaction
            .as_ref()
            .map(|seat| seat(host, credential, spend))
    }
    fn lease(&self) -> &BudgetLease {
        &self.lease
    }
    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        match self.runtime.runtime() {
            Ok(runtime) => Box::new(runtime),
            Err(_) => Box::new(UnavailableRuntime),
        }
    }
    /// A child shares the template's compiled code and nothing else: each
    /// is fresh, with no store, capability or adapter of another run's.
    fn reader_runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        let mut template = self
            .reader_template
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if template.is_none() {
            *template = self.runtime.runtime().ok();
        }
        match template.as_ref() {
            Some(template) => Box::new(template.fresh()),
            None => Box::new(UnavailableRuntime),
        }
    }
    fn reader_backend(
        &self,
        meter: BudgetGuard,
        payer: Option<PayerPerson>,
    ) -> Option<Arc<dyn LlmBackend>> {
        self.reader_meter.as_ref().map(|build| build(meter, payer))
    }
    fn host_meter(&self) -> Option<BudgetGuard> {
        self.host_meter.clone()
    }
    fn planned_route(&self, vault: &Vault, pick: &ModelId) -> Option<ModelLocality> {
        self.planned_route
            .as_ref()
            .and_then(|route| route(vault, pick))
    }
    fn planned_backend(
        &self,
        meter: BudgetGuard,
        payer: Option<PayerPerson>,
        planned: &PlannedModel,
    ) -> Option<Arc<dyn LlmBackend>> {
        self.planned_meter
            .as_ref()
            .map(|build| build(meter, payer, planned))
    }
    fn planned_compaction(
        &self,
        host: CompactionHostBinding,
        credential: &str,
        spend: Option<&SpendScopeId>,
        planned: &PlannedModel,
    ) -> Option<RunCompaction> {
        match &self.pinned_compaction {
            Some(seat) if planned.exact => Some(seat(host, credential, spend)),
            _ => self.compaction(host, credential, spend),
        }
    }
    fn reader_window_tokens(&self) -> Option<u64> {
        self.reader_window_tokens
    }
    fn scoped_child_hosts(&self) -> Option<&ScopedChildHosts> {
        Some(&self.scoped_hosts)
    }
    /// A scoped child its host profiled lends the ports of its profile.
    fn scoped_child_ports(&self, job: &ReaderJob) -> Option<Arc<dyn ScopedChildPorts>> {
        self.scoped_hosts.ports(job.task)
    }
    fn executor_config(
        &self,
        vault: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        self.run_config(vault, run_id, task, || {
            Ok(vault
                .get_code_run_replay_record(&run_id)?
                .map(|record| record.determinism.frozen_unix_ms))
        })
    }
    /// A session-bound run's first start is its room's record's: a resumed
    /// entry keeps the clock, and so the config, its first entry froze.
    fn executor_config_on(
        &self,
        vault: &Vault,
        bound: &GatedActorWrite<'_>,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        self.run_config(vault, run_id, task, || {
            Ok(bound
                .recorded_determinism(run_id)?
                .map(|determinism| determinism.frozen_unix_ms))
        })
    }
    fn template_model(
        &self,
        _vault: &Vault,
        _caller: EntityId,
    ) -> oneiron::Result<oneiron::ModelId> {
        Ok(self.config.model.clone())
    }
}

struct UnavailableRuntime;
impl JsCodeModeRuntime for UnavailableRuntime {
    fn run_step(
        &mut self,
        _: JsCodeModeStep<'_>,
        _: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        Err(oneiron::Error::InvalidConfig(
            "QuickJS runtime factory unavailable".into(),
        ))
    }
}
