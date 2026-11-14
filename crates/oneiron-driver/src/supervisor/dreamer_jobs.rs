//! The host adapter for the Dreamer's job crate (untangle 6.9c PR 4,
//! S69-RUN = A): a strength attempt runs `oneiron_dreamer::strength_archive`
//! over a client bound to that attempt, never over a `&Vault`.

use std::sync::Arc;

use oneiron::dreamer_runner::DreamerParkCause;
use oneiron::dreamer_runner::maintenance::{MAINTENANCE_QUEUE_KIND, strength};
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor, Result, Vault,
    WakeAttemptContext,
};
use oneiron_dreamer::strength_archive;
use oneiron_remote::OneironClient;

/// Wraps a pass's executor chain with the Dreamer's job arms. A strength
/// attempt (`dreamer.maintenance` / `dreamer.consolidation_strength`) runs
/// the strength archive job over the client of its own binding
/// (`Vault::bind_dreamer_attempt`, `OneironClient::for_dreamer_attempt`),
/// which the engine proves at every call; every other attempt goes to
/// `inner`.
///
/// Installed by the production factory always. With no vault lent
/// (`ConsolidationExecutorFactory::with_dreamer_job_vault`), a strength
/// attempt parks, resumable, like the other host facets
/// (`oneiron::dreamer_runner::maintenance::strength::unlent`).
pub struct DreamerJobsExecutor<E> {
    inner: E,
    vault: Option<Arc<Vault>>,
}

impl<E> DreamerJobsExecutor<E> {
    #[must_use]
    pub fn new(inner: E, vault: Option<Arc<Vault>>) -> Self {
        Self { inner, vault }
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for DreamerJobsExecutor<E> {
    fn runs_coach_host_jobs(&self) -> bool {
        self.inner.runs_coach_host_jobs()
    }

    fn runs_coach_heals(&self) -> bool {
        self.inner.runs_coach_heals()
    }

    async fn execute_partition_window<'w>(
        &mut self,
        window: &mut [(&'w DreamerAdmittedAttempt, WakeAttemptContext<'w>)],
    ) -> Vec<Result<DreamerAttemptExecution>> {
        self.inner.execute_partition_window(window).await
    }

    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if !is_strength_attempt(attempt) {
            return self.inner.execute(attempt, ctx).await;
        }
        let Some(vault) = self.vault.as_ref() else {
            return Ok(strength::unlent());
        };
        Ok(run_strength_archive(vault, attempt, ctx.now_ms))
    }
}

/// Whether `attempt` is a strength job on the maintenance lane.
fn is_strength_attempt(attempt: &DreamerAdmittedAttempt) -> bool {
    attempt.status.attempt.kind == MAINTENANCE_QUEUE_KIND
        && attempt.status.payload.attempt_type == strength::CONSOLIDATION_STRENGTH_FACET
}

/// Binds `attempt`, runs the strength archive over the bound client at the
/// attempt's clock `now_ms`, and settles the attempt: completed at zero
/// units, as the native arm was, or parked for a retry when the engine
/// refused the binding or the job stopped. Items the engine refused inside
/// a batch complete the attempt: their receipts are the record.
fn run_strength_archive(
    vault: &Arc<Vault>,
    attempt: &DreamerAdmittedAttempt,
    now_ms: u64,
) -> DreamerAttemptExecution {
    let binding = match vault.bind_dreamer_attempt(attempt) {
        Ok(binding) => binding,
        Err(error) => {
            return retry_park(format!(
                "the strength attempt's binding was refused ({}): {}",
                error.code, error.message
            ));
        }
    };
    let client = OneironClient::for_dreamer_attempt(binding);
    match strength_archive::run(&client, strength_archive::Input { now_ms }) {
        Ok(outcome) => {
            tracing::info!(
                examined = outcome.examined,
                archived = outcome.archived,
                refused = outcome.refused,
                batches = outcome.batches,
                "strength archive job ran"
            );
            DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings: Vec::new(),
            }
        }
        Err(error) => retry_park(format!("the strength archive job stopped: {error}")),
    }
}

/// A refusal park: the attempt resumes as the same try after its retry delay.
fn retry_park(reason: String) -> DreamerAttemptExecution {
    tracing::warn!(%reason, "strength attempt parked");
    DreamerAttemptExecution::Park {
        reason,
        cause: DreamerParkCause::Retry,
    }
}
