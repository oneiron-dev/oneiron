//! Production MCP provider over the hash-pinned engine QuickJS component.

use super::McpCodeModeProvider;
use oneiron::code_run::CodeRunDeterminism;
use oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron::engine_executor::{
    EngineExecutorConfig, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::{BudgetLease, EntityId, LlmBackend};
use std::sync::Arc;

/// Host configuration, never caller-chosen runtime bytes or native JS source.
/// Construction requires the factory's successful artifact readiness probe.
pub struct McpQuickJsProvider {
    runtime: Arc<QuickJsRuntimeFactory>,
    backend: Arc<dyn LlmBackend>,
    lease: BudgetLease,
    config: EngineExecutorConfig,
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
        })
    }
}

impl McpCodeModeProvider for McpQuickJsProvider {
    fn production_runtime_available(&self) -> bool {
        true
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
    fn executor_config(&self, run_id: EntityId, task: &str) -> EngineExecutorConfig {
        let mut config = self.config.clone();
        config.run_id = run_id;
        config.task = task.to_owned();
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
        config
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
