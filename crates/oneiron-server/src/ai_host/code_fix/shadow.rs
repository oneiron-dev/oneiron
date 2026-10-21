//! The Coach's shadow runner for a code fix's engine candidates (FIX 1661,
//! 2144): the host's [`ServerShadowRunner`], opened for one code-fix run
//! when the publisher pinned an engine candidate. Each arm runs on the
//! server's runtime while the Coach's blocking worker waits on it, as the
//! run's model calls do; never inside the Dreamer or on a runtime worker.
//! Both arms of a pair go out on the run's one meter context, and the runner
//! meters each of their calls under the Coach. Each step's program runs on a
//! fresh runtime of the checked-in QuickJS component, compiled once per run
//! on the first step's blocking worker; a server built without the code
//! sandbox has none, and its arms say so. Nothing here fetches, installs or
//! loads a candidate engine.

use std::sync::Arc;

use oneiron::code_run::shadow_runner::{
    ShadowArmLease, ShadowMeterContext, ShadowRunRequest, ShadowRunResult, ShadowRunner,
    ShadowUnavailable,
};
use oneiron::compaction::output::OutputRef;
use oneiron::dreamer_runner::maintenance::code_fix::{CodeFixShadowHost, PublisherCandidate};

use crate::ai_host::shadow_runner::{ServerShadowRunner, ShadowRuntimes};
use crate::server::SyncServer;

/// The shadow runner one code-fix run's engine candidates run on.
pub(super) struct CoachShadow {
    runner: ServerShadowRunner,
    /// The server's runtime, which every arm runs on.
    handle: tokio::runtime::Handle,
    meter: ShadowMeterContext,
}

impl CoachShadow {
    /// The runner for the code-fix run `run_id`, its arms' calls metered
    /// under `purpose` at `call_units` each. `None` when `publisher` pins no
    /// engine candidate, and when the runner cannot open (each engine
    /// candidate is then not run).
    pub(super) fn open(
        server: &Arc<SyncServer>,
        run_id: &str,
        purpose: &str,
        call_units: u64,
        publisher: &[PublisherCandidate],
    ) -> Option<Self> {
        if !publisher
            .iter()
            .any(|candidate| candidate.kind.engine_pin().is_some())
        {
            return None;
        }
        let handle = tokio::runtime::Handle::current();
        match ServerShadowRunner::new(
            Arc::downgrade(server),
            handle.clone(),
            checked_in_runtimes(),
        ) {
            Ok(runner) => Some(Self {
                runner,
                handle,
                meter: ShadowMeterContext {
                    host_run: run_id.to_owned(),
                    purpose: purpose.to_owned(),
                    call_units,
                },
            }),
            // By kind only: an engine error can quote the vault.
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "the Coach's shadow runner did not open");
                None
            }
        }
    }
}

impl CodeFixShadowHost for CoachShadow {
    fn run_arm(&self, request: ShadowRunRequest) -> oneiron::Result<ShadowRunResult> {
        // The arm runs on the server's runtime; this blocking worker waits.
        self.handle.block_on(self.runner.run(request))
    }

    fn read_arm_body(
        &self,
        lease: &ShadowArmLease,
        body: OutputRef,
    ) -> oneiron::Result<Result<Vec<u8>, ShadowUnavailable>> {
        self.runner.read_body(lease, body)
    }

    fn release_arm(&self, lease: &ShadowArmLease) {
        self.runner.release(lease);
    }

    fn arm_meter(&self) -> ShadowMeterContext {
        self.meter.clone()
    }
}

/// Each arm step's runtime: a fresh one of the checked-in QuickJS component,
/// which is compiled and readiness-probed once, on the first step's
/// blocking worker.
#[cfg(feature = "code-sandbox-wasmtime")]
fn checked_in_runtimes() -> ShadowRuntimes {
    use oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory;
    use oneiron::engine_executor::JsCodeModeRuntime;

    let component: Arc<std::sync::OnceLock<Option<QuickJsRuntimeFactory>>> = Arc::default();
    Arc::new(
        move || -> oneiron::Result<Box<dyn JsCodeModeRuntime + Send>> {
            let factory = component
                .get_or_init(|| match crate::mcp::checked_in_quickjs_runtime() {
                    Ok(factory) => Some(factory),
                    Err(error) => {
                        tracing::error!(%error, "the checked-in QuickJS component did not load");
                        None
                    }
                })
                .as_ref()
                .ok_or_else(|| {
                    oneiron::Error::InvalidConfig(
                        "the checked-in QuickJS component did not load".to_owned(),
                    )
                })?;
            let runtime: Box<dyn JsCodeModeRuntime + Send> = Box::new(factory.runtime()?);
            Ok(runtime)
        },
    )
}

/// A server built without the code sandbox runs no arm's step: each says
/// so.
#[cfg(not(feature = "code-sandbox-wasmtime"))]
fn checked_in_runtimes() -> ShadowRuntimes {
    use oneiron::engine_executor::JsCodeModeRuntime;

    Arc::new(|| -> oneiron::Result<Box<dyn JsCodeModeRuntime + Send>> {
        Err(oneiron::Error::InvalidConfig(
            "this server has no code sandbox".to_owned(),
        ))
    })
}
