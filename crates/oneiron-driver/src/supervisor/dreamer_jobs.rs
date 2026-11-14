//! The host adapter for the Dreamer's job crate (untangle 6.9c PR 4,
//! S69-RUN = A): a strength attempt runs `oneiron_dreamer::strength_archive`
//! over a client bound to that attempt, never over a `&Vault`.
//!
//! A conflict settlement attempt (untangle 6.9d S69D4) runs
//! `oneiron_dreamer::conflict_settle` over the client of its own binding,
//! with the host's lent decisions, on a scoped thread the job joins.

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::dreamer_runner::DreamerDecisionLender;
use oneiron::dreamer_runner::DreamerParkCause;
use oneiron::dreamer_runner::maintenance::{MAINTENANCE_QUEUE_KIND, conflict_settle, strength};
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor, Result, Vault,
    WakeAttemptContext,
};
use oneiron_dreamer::{conflict_settle as conflict_job, strength_archive};
use oneiron_remote::OneironClient;

/// The cursor after the last conflict a settlement run asked about, shared by
/// every factory the host builds with it. A run starts after the held cursor
/// and stores where it left off, so the next run resumes there. Cloned handles
/// share one cursor. The default holds no cursor, so the first run starts at
/// the first conflict.
#[derive(Clone, Default)]
pub struct ConflictSettleCursor {
    inner: Arc<Mutex<Option<String>>>,
}

/// Wraps a pass's executor chain with the Dreamer's job arms. A strength
/// attempt (`dreamer.maintenance` / `dreamer.consolidation_strength`) runs
/// the strength archive job over the client of its own binding
/// (`Vault::bind_dreamer_attempt`, `OneironClient::for_dreamer_attempt`),
/// which the engine proves at every call. A conflict settlement attempt
/// (`dreamer.maintenance` / `dreamer.conflict_settle`) runs the conflict
/// settle job over the client of its own binding, with the host's lent
/// decisions when one is lent, on a scoped thread the attempt joins. Every
/// other attempt goes to `inner`.
///
/// Installed by the production factory always. With no vault lent
/// (`ConsolidationExecutorFactory::with_dreamer_job_vault`), a strength or
/// conflict settlement attempt parks, resumable, like the other host facets
/// (`oneiron::dreamer_runner::maintenance::strength::unlent`,
/// `oneiron::dreamer_runner::maintenance::conflict_settle::unlent`).
pub struct DreamerJobsExecutor<E> {
    inner: E,
    vault: Option<Arc<Vault>>,
    conflict_lender: Option<Arc<dyn DreamerDecisionLender>>,
    conflict_cursor: ConflictSettleCursor,
}

impl<E> DreamerJobsExecutor<E> {
    #[must_use]
    pub fn new(inner: E, vault: Option<Arc<Vault>>) -> Self {
        Self {
            inner,
            vault,
            conflict_lender: None,
            conflict_cursor: ConflictSettleCursor::default(),
        }
    }

    /// Lends the conflict settlement arm its host decisions and shared cursor.
    /// The factory calls this with what it holds, so every pass shares one
    /// cursor. A direct user that never calls it keeps no lender and its own
    /// default cursor.
    #[must_use]
    pub(crate) fn with_conflict_settle(
        self,
        lender: Option<Arc<dyn DreamerDecisionLender>>,
        cursor: ConflictSettleCursor,
    ) -> Self {
        Self {
            conflict_lender: lender,
            conflict_cursor: cursor,
            ..self
        }
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
        if is_strength_attempt(attempt) {
            let Some(vault) = self.vault.as_ref() else {
                return Ok(strength::unlent());
            };
            return Ok(run_strength_archive(vault, attempt, ctx.now_ms));
        }
        if is_conflict_settle_attempt(attempt) {
            let Some(vault) = self.vault.as_ref() else {
                return Ok(conflict_settle::unlent());
            };
            return Ok(run_conflict_settle(
                vault,
                attempt,
                self.conflict_lender.clone(),
                &self.conflict_cursor,
            ));
        }
        self.inner.execute(attempt, ctx).await
    }
}

/// Whether `attempt` is a strength job on the maintenance lane.
fn is_strength_attempt(attempt: &DreamerAdmittedAttempt) -> bool {
    attempt.status.attempt.kind == MAINTENANCE_QUEUE_KIND
        && attempt.status.payload.attempt_type == strength::CONSOLIDATION_STRENGTH_FACET
}

/// Whether `attempt` is a conflict settlement job on the maintenance lane.
fn is_conflict_settle_attempt(attempt: &DreamerAdmittedAttempt) -> bool {
    attempt.status.attempt.kind == MAINTENANCE_QUEUE_KIND
        && attempt.status.payload.attempt_type != conflict_settle::CONFLICT_SETTLE_FACET
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

/// Binds `attempt`, lends the host decisions when one is lent, and runs the
/// conflict settle job over the bound client from the shared cursor, on a
/// scoped thread the attempt joins. The ladder may block on the server
/// runtime, so the job runs off the pass thread with no runtime passed in.
/// A run that settles stores where it left off and completes at zero units,
/// as the native arm was. A refused binding, a stopped job, a thread that
/// did not spawn, or a thread that panicked parks for a retry with the
/// cursor unchanged.
fn run_conflict_settle(
    vault: &Arc<Vault>,
    attempt: &DreamerAdmittedAttempt,
    lender: Option<Arc<dyn DreamerDecisionLender>>,
    cursor: &ConflictSettleCursor,
) -> DreamerAttemptExecution {
    let binding = match vault.bind_dreamer_attempt(attempt) {
        Ok(binding) => binding,
        Err(error) => {
            return conflict_retry_park(format!(
                "the conflict settlement attempt's binding was refused ({}): {}",
                error.code, error.message
            ));
        }
    };
    let binding = match lender {
        Some(lender) => binding.lend_decisions(lender),
        None => binding,
    };
    let client = OneironClient::for_dreamer_attempt(binding);
    let after = cursor
        .inner
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let input = conflict_job::Input {
        after: after.clone(),
    };
    let joined = std::thread::scope(|scope| {
        let handle = match std::thread::Builder::new()
            .name("conflict-settle".to_owned())
            .spawn_scoped(scope, move || conflict_job::run(&client, &input))
        {
            Ok(handle) => handle,
            Err(error) => {
                return Err(format!("the conflict settle thread did not spawn: {error}"));
            }
        };
        handle
            .join()
            .map_err(|_| "the conflict settle thread panicked".to_owned())
    });
    match joined {
        Err(reason) => conflict_retry_park(reason),
        Ok(Err(error)) => conflict_retry_park(format!("the conflict settle job stopped: {error}")),
        Ok(Ok(outcome)) => {
            *cursor.inner.lock().unwrap_or_else(PoisonError::into_inner) =
                outcome.last.clone().or(after);
            tracing::info!(
                facet = conflict_settle::CONFLICT_SETTLE_FACET,
                asked = outcome.asked,
                settled = outcome.settled,
                refused = outcome.refused,
                left_parked = outcome.left_parked,
                batches = outcome.batches,
                "conflict settle job ran"
            );
            DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings: Vec::new(),
            }
        }
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

/// A conflict settlement refusal park: the attempt resumes as the same try
/// after its retry delay, with the shared cursor unchanged.
fn conflict_retry_park(reason: String) -> DreamerAttemptExecution {
    tracing::warn!(
        facet = conflict_settle::CONFLICT_SETTLE_FACET,
        %reason,
        "conflict settle attempt parked"
    );
    DreamerAttemptExecution::Park {
        reason,
        cause: DreamerParkCause::Retry,
    }
}
