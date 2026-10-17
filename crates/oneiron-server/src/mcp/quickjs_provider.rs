//! Production MCP provider over the hash-pinned engine QuickJS component.

use super::{McpCodeModeProvider, ReaderMeter, RunCompactionSeat};
use oneiron::agent_dispatch::SpendScopeId;
use oneiron::code_run::CodeRunDeterminism;
use oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron::code_sandbox::wasmtime_runtime::{ComponentBudget, WasmtimeComponentRuntime};
use oneiron::engine_executor::{
    EngineExecutorConfig, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
    RunCompaction,
};
use oneiron::llm::SingleRouteBackend;
use oneiron::llm::run_admission::RunReceiptSink;
use oneiron::llm::seat::SeatDecisions;
use oneiron::{BudgetGuard, BudgetLease, EntityId, LlmBackend, LlmError, Vault, WriteActor};
use oneiron_code_check::ShadowCheck;
use std::sync::{Arc, Mutex, PoisonError};

use crate::models::{InjectedRuns, LoggedReceipts};

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
    /// The seats a leased agent's planned spawns choose among.
    planner: Option<crate::config::models::PlannerSettings>,
    /// Each run's clock is frozen at its first start, and a resumed run keeps
    /// it; otherwise every run shares the configured frozen clock.
    clock_from_first_start: bool,
    /// The host's own model and meter, when the host injected them: rebound
    /// to the server's run receipts when the server takes this provider.
    injected: Option<(Arc<dyn SingleRouteBackend>, BudgetGuard)>,
    code_check: Option<Arc<ShadowCheck>>,
    /// Builds each reader child's backend on its own meter; none runs no
    /// child.
    reader_meter: Option<ReaderMeter>,
    /// The runtime reader children are made fresh from, compiled once at
    /// the first child.
    reader_template: Mutex<Option<WasmtimeComponentRuntime>>,
    /// The input window of the model reader children and summaries run
    /// on, in tokens, when the host knows it.
    reader_window_tokens: Option<u64>,
}

/// A reader child's backend over the host-injected model: its calls are
/// runs on the child's own meter, their receipts written to `receipts`.
fn injected_meter(
    backend: Arc<dyn SingleRouteBackend>,
    receipts: Arc<dyn RunReceiptSink>,
) -> ReaderMeter {
    Arc::new(move |meter: BudgetGuard| {
        Arc::new(InjectedRuns::new(
            Arc::clone(&backend),
            meter,
            Arc::clone(&receipts),
        )) as Arc<dyn LlmBackend>
    })
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
            planner: None,
            clock_from_first_start: false,
            injected: None,
            code_check: None,
            reader_meter: None,
            reader_template: Mutex::new(None),
            reader_window_tokens: None,
        })
    }

    /// Writes the host-injected model's run receipts to `receipts`.
    pub(crate) fn with_run_receipts(mut self, receipts: Arc<dyn RunReceiptSink>) -> Self {
        if let Some((backend, meter)) = &self.injected {
            self.reader_meter = Some(injected_meter(Arc::clone(backend), Arc::clone(&receipts)));
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

    /// Shadow mode: type-check every generated program before it runs and
    /// record the diagnostics beside its step. Nothing is blocked.
    #[must_use]
    pub fn with_code_check(mut self, shadow: Arc<ShadowCheck>) -> Self {
        self.code_check = Some(shadow);
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
    fn planner(&self) -> Option<&crate::config::models::PlannerSettings> {
        self.planner.as_ref()
    }
    fn code_check(&self) -> Option<&ShadowCheck> {
        self.code_check.as_deref()
    }
    fn backend(&self) -> &dyn LlmBackend {
        self.backend.as_ref()
    }
    fn compaction(
        &self,
        byline: WriteActor,
        credential: &str,
        spend: Option<&SpendScopeId>,
    ) -> Option<RunCompaction> {
        self.compaction
            .as_ref()
            .map(|seat| seat(byline, credential, spend))
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
    fn reader_backend(&self, meter: BudgetGuard) -> Option<Arc<dyn LlmBackend>> {
        self.reader_meter.as_ref().map(|build| build(meter))
    }
    fn reader_window_tokens(&self) -> Option<u64> {
        self.reader_window_tokens
    }
    fn executor_config(
        &self,
        vault: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        let mut config = self.config.clone();
        config.run_id = run_id;
        config.task = task.to_owned();
        if self.clock_from_first_start {
            config.determinism.frozen_unix_ms = match vault.get_code_run_replay_record(&run_id)? {
                Some(record) => record.determinism.frozen_unix_ms,
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
