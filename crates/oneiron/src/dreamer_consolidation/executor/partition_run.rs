//! The prepared partition run `execute` ends in: the branch's resources at
//! the wake's pin, the partition's model work, and what its outcome settles
//! (accepted candidates, a checkpoint, a park or a deferral).

use super::super::{PreparedConsolidationAttempt, PreparedWake};
use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;

impl ConsolidationExecutor<'_> {
    /// Runs `plan`, prepared on `wake`, and settles its outcome.
    pub(super) async fn execute_prepared_partition(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &PreparedConsolidationAttempt,
        wake: &PreparedWake,
    ) -> Result<DreamerAttemptExecution> {
        let payload = plan.input().clone();
        // A turn demoted since the wake prepared it waits for its promotion
        // (FIX 3861), as one away at preparation does.
        let resources = match BranchResources::open_prepared(ctx.vault, self.actor, plan, wake) {
            Err(error) if super::super::residency::waits_on_residency(&error) => {
                return Ok(super::super::residency::residency_deferral(
                    ctx.now_ms,
                    0,
                    Vec::new(),
                ));
            }
            resources => resources?,
        };
        let run_id = attempt.status.attempt.run_id.clone();
        let mut charges = StepChargeTally::default();
        match self
            .run_partition_attempt(
                &payload,
                &resources,
                ctx,
                attempt.status.attempt.id,
                run_id,
                &mut charges,
            )
            .await
        {
            // A finished partition lands while its landing window is still
            // open, even past the pass ceiling (FIX 11570): its model steps
            // are done, so there is nothing left to checkpoint for. It
            // checkpoints only once that window has closed.
            Ok(PartitionRun::Completed { .. }) if ctx.deadline.landing_closed() => {
                Ok(charges.checkpoint())
            }
            // A held partition still checkpoints past the ceiling, as today.
            Ok(PartitionRun::Held { .. }) if ctx.deadline.expired() => Ok(charges.checkpoint()),
            Ok(PartitionRun::Checkpoint) => Ok(charges.checkpoint()),
            // A refused extraction, a refused citation (FIX 7274) among
            // them, retries as the same try after its retry delay (FIX 7218,
            // Engine 10-21): a private park would keep its row leased.
            Ok(PartitionRun::Refused { reason }) => {
                Ok(charges.park_for(&reason, DreamerParkCause::Retry))
            }
            // A turn demoted after the model answered waits too (FIX 6060),
            // settling what the attempt already spent.
            Ok(PartitionRun::Completed { candidates }) => {
                if let Err(error) = resources
                    .accept_until(resources.scope(), self.sink, candidates, ctx.deadline)
                    .await
                {
                    return super::super::residency::spent_or_deferred(error, ctx, &charges);
                }
                Ok(DreamerAttemptExecution::Completed {
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                })
            }
            Ok(PartitionRun::Held {
                candidates,
                retry_at_ms,
            }) => {
                if let Err(error) = resources
                    .accept_until(resources.scope(), self.sink, candidates, ctx.deadline)
                    .await
                {
                    return super::super::residency::spent_or_deferred(error, ctx, &charges);
                }
                Ok(DreamerAttemptExecution::Deferred {
                    completed_units: charges.units,
                    retry_at: retry_at_ms.div_ceil(1_000),
                    step_hashes: charges.step_hashes.clone(),
                })
            }
            // The step layer already parked the trapped attempt; Park it for resume
            // WITHOUT accepting candidates or completing it (#485-1, #485-2).
            Ok(PartitionRun::Trapped) => {
                Ok(charges.park_for("durable step trapped for resume", DreamerParkCause::Signal))
            }
            // The error leaves as it is; what the partition already spent
            // settles with it (FIX 7432).
            Err(crate::llm::DurableStepError::Engine(error)) => {
                super::super::residency::spent_or_deferred(error, ctx, &charges)
            }
            // Every other failure parks with what the attempt spent, a
            // refused conflict read's paid usage included (FIX 414).
            Err(other) => Ok(super::failure::park_partition_failure_with_spend(
                other,
                &mut charges,
            )),
        }
    }
}
