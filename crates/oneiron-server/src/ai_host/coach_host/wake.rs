//! The installed host Coach's complete dispatcher, lent to a wake pass.

use std::sync::Arc;

use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerRunnerStore};

use crate::server::SyncServer;

#[derive(Clone)]
pub(in crate::ai_host) struct WakeExecutor {
    server: Arc<SyncServer>,
    serve: tokio::runtime::Handle,
}

impl WakeExecutor {
    pub(in crate::ai_host) fn for_server(server: Arc<SyncServer>) -> Option<Self> {
        let serve = server.ai.coach_host_wake.get()?.clone();
        Some(Self { server, serve })
    }

    pub(in crate::ai_host) async fn execute(
        &self,
        admitted: &DreamerAdmittedAttempt,
        now: u64,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let server = Arc::clone(&self.server);
        let facet = admitted.status.payload.attempt_type.clone();
        let admitted = admitted.clone();
        match self
            .serve
            .spawn_blocking(move || {
                super::run_one(&server, &admitted, now)?;
                // Read once, under the worker's exact native predicate.
                // The dispatcher may have parked triage on its part children.
                super::super::feedback_triage::yielded_park(
                    &DreamerRunnerStore::new(server.vault()),
                    &admitted,
                    now,
                )
            })
            .await
        {
            // Report only the park the native dispatcher actually wrote;
            // the driver preserves that row and refunds its own reservation.
            Ok(Ok(Some(park))) => Ok(DreamerAttemptExecution::Park {
                reason: park.reason,
                cause: park.cause,
            }),
            // Model calls already paid on their original Coach lines.
            Ok(Ok(None)) => Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            }),
            Ok(Err(error)) => Ok(DreamerAttemptExecution::Failed {
                reason: format!("{facet} failed: {:?}", error.kind()),
                completed_units: 0,
            }),
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(oneiron::Error::InvalidConfig(
                "the Coach host worker stopped".into(),
            )),
        }
    }
}
