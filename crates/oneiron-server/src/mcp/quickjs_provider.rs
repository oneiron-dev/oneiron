//! Production MCP provider over the hash-pinned engine QuickJS component.

use super::McpCodeModeProvider;
use oneiron::code_run::CodeRunDeterminism;
use oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron::code_sandbox::wasmtime_runtime::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::seat::SeatJudge;
use oneiron::{BudgetLease, EntityId, LlmBackend, Vault};
use std::sync::Arc;

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

/// Host configuration, never caller-chosen runtime bytes or native JS source.
/// Construction requires the factory's successful artifact readiness probe.
pub struct McpQuickJsProvider {
    runtime: Arc<QuickJsRuntimeFactory>,
    backend: Arc<dyn LlmBackend>,
    lease: BudgetLease,
    config: EngineExecutorConfig,
    seat_router: Option<(Arc<dyn SeatJudge>, String)>,
    /// Each run's clock is frozen at its first start, and a resumed run keeps
    /// it; otherwise every run shares the configured frozen clock.
    clock_from_first_start: bool,
}

impl McpQuickJsProvider {
    pub fn new(
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
            seat_router: None,
            clock_from_first_start: false,
        })
    }

    /// Freeze each run's clock at its first start instead of the configured
    /// instant: a live host's runs see the time they started, and a run
    /// resumed after a restart keeps the clock its record was made with.
    #[must_use]
    pub fn with_clock_from_first_start(mut self) -> Self {
        self.clock_from_first_start = true;
        self
    }

    /// Install the host's typed model judgment and profile for manifest-backed runs.
    #[must_use]
    pub fn with_model_seat_router(
        mut self,
        judge: Arc<dyn SeatJudge>,
        facet: impl Into<String>,
    ) -> Self {
        self.seat_router = Some((judge, facet.into()));
        self
    }
}

impl McpCodeModeProvider for McpQuickJsProvider {
    fn production_runtime_available(&self) -> bool {
        true
    }
    fn seat_judge(&self) -> Option<&dyn SeatJudge> {
        self.seat_router.as_ref().map(|(judge, _)| judge.as_ref())
    }
    fn seat_facet(&self) -> Option<&str> {
        self.seat_router.as_ref().map(|(_, facet)| facet.as_str())
    }
    fn backend(&self) -> &dyn LlmBackend {
        self.backend.as_ref()
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
