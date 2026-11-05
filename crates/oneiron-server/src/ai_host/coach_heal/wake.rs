//! The installed Coach worker's resources, lent to an invoked wake pass.

use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::code_fix::PublisherCandidate;
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution};

use crate::server::SyncServer;

#[derive(Clone)]
pub(in crate::ai_host) struct WakeHost {
    publisher: Arc<[PublisherCandidate]>,
    serve: tokio::runtime::Handle,
}

impl WakeHost {
    pub(super) fn new(publisher: Arc<[PublisherCandidate]>) -> Self {
        Self {
            publisher,
            serve: tokio::runtime::Handle::current(),
        }
    }
}

/// Holds the actual server and the installed worker's immutable resources
/// for the pass, so support cannot disappear after admission.
#[derive(Clone)]
pub(in crate::ai_host) struct WakeExecutor {
    server: Arc<SyncServer>,
    host: WakeHost,
}

impl WakeExecutor {
    pub(in crate::ai_host) fn for_server(server: Arc<SyncServer>) -> Option<Self> {
        let host = server.ai.coach_heal_wake.get()?.clone();
        Some(Self { server, host })
    }

    pub(in crate::ai_host) async fn execute(
        &self,
        admitted: &DreamerAdmittedAttempt,
        now: u64,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let server = Arc::clone(&self.server);
        let publisher = Arc::clone(&self.host.publisher);
        let facet = admitted.status.payload.attempt_type.clone();
        let admitted = admitted.clone();
        // run_one and its model bridges block on the served runtime, not
        // the Dreamer supervisor's current-thread runtime. Await all work
        // before returning the lease to the driver's sole settlement path.
        match self
            .host
            .serve
            .spawn_blocking(move || super::run_one(&server, &admitted, &publisher, now))
            .await
        {
            // The Coach's model and decision lines already paid their calls;
            // like the worker, release the queue's admission reservation.
            Ok(Ok(())) => Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            }),
            Ok(Err(error)) => Ok(DreamerAttemptExecution::Failed {
                reason: format!("{facet} failed: {:?}", error.kind()),
                completed_units: 0,
            }),
            // Preserve the driver's executor-panic containment and stop it
            // from reusing this executor after a panicking Coach call.
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(oneiron::Error::InvalidConfig(
                "the Coach heal worker stopped".into(),
            )),
        }
    }
}
