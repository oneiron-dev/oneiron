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
    ShadowArmLease, ShadowBodyRef, ShadowMeterContext, ShadowRunRequest, ShadowRunResult,
    ShadowRunner, ShadowSourceAdmission, ShadowUnavailable,
};
use oneiron::dreamer_runner::maintenance::code_fix::{CodeFixShadowHost, PublisherCandidate};

use crate::ai_host::shadow_runner::{ServerShadowRunner, checked_in_runtimes};
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

    fn read_arm_body_for_model(
        &self,
        lease: &ShadowArmLease,
        body: &ShadowBodyRef,
        admission: &dyn ShadowSourceAdmission,
    ) -> oneiron::Result<Result<Vec<u8>, ShadowUnavailable>> {
        // FIX 9468: the questions read an arm's body through the runner's
        // model release alone.
        self.runner.read_body_for_model(lease, body, admission)
    }

    fn release_arm(&self, lease: &ShadowArmLease) {
        self.runner.release(lease);
    }

    fn arm_meter(&self) -> ShadowMeterContext {
        self.meter.clone()
    }
}
