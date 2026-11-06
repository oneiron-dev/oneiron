//! The prepared partition run `execute` ends in: the branch's resources at
//! the wake's pin, the partition's model work, and what its outcome settles
//! (accepted candidates, a checkpoint, a park or a deferral).

use std::collections::BTreeSet;
use std::time::Instant;

use crate::EntityId;

use super::super::stage_log::{PartitionStages, ms_since};
use super::super::{PreparedConsolidationAttempt, PreparedWake};
use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;

/// A partition opened at its wake pin, ready for its model work.
pub(super) struct PartitionStarted<'a> {
    pub(super) payload: rmpv::Value,
    pub(super) resources: BranchResources<'a>,
    /// The peers this attempt's widening newly assigned beyond its
    /// queued originals, with the readings this branch froze of their
    /// words at its open and the partition each was read under: recorded
    /// as taken only once the run completes, under `widened_round`
    /// (FIX 12246). A held run stamps none of them.
    pub(super) widened: Vec<(EntityId, [u8; 32], [u8; 32])>,
    /// The queued originals, for the stamp's carrier-round guard.
    pub(super) originals: Vec<EntityId>,
    /// The queued originals' frozen readings and partitions, for
    /// stamping members no round has taken yet on completion.
    pub(super) returned: Vec<(EntityId, [u8; 32], [u8; 32])>,
    /// The projection round this attempt itself carries, for the
    /// latest-round bookkeeping its widened stamp owes; `None` for an
    /// unkeyed attempt, which records no assignment at all.
    pub(super) widened_round: Option<[u8; 32]>,
    pub(super) charges: StepChargeTally,
}

/// A partition at its open: already settled (a residency wait), or
/// running with its opened branch.
pub(super) enum PartitionStart<'a> {
    Early(DreamerAttemptExecution),
    Running(Box<PartitionStarted<'a>>),
}

impl ConsolidationExecutor<'_> {
    /// Runs `plan`, prepared on `wake`, and settles its outcome. However it
    /// ends, it logs one line of its stages' wall ms (L07 DREAM-OBSERVE).
    pub(super) async fn execute_prepared_partition(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &PreparedConsolidationAttempt,
        wake: &PreparedWake,
    ) -> Result<DreamerAttemptExecution> {
        let mut stages = PartitionStages::start(wake.prepared_ms());
        let executed = self
            .run_prepared_partition(attempt, ctx, plan, wake, &mut stages)
            .await;
        stages.log(attempt, plan.turn_ids().len(), &executed);
        executed
    }

    async fn run_prepared_partition(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &PreparedConsolidationAttempt,
        wake: &PreparedWake,
        stages: &mut PartitionStages,
    ) -> Result<DreamerAttemptExecution> {
        let started = match self.start_partition(attempt, ctx, plan, wake, stages)? {
            PartitionStart::Early(done) => return Ok(done),
            PartitionStart::Running(started) => *started,
        };
        let PartitionStarted {
            payload,
            resources,
            widened,
            originals,
            returned,
            widened_round,
            mut charges,
        } = started;
        let run_started = Instant::now();
        let run = self
            .run_partition_attempt(
                &payload,
                &resources,
                ctx,
                attempt.status.attempt.id,
                attempt.status.attempt.run_id.clone(),
                &mut charges,
                stages,
            )
            .await;
        stages.close_model_run(run_started);
        self.settle_partition_run(
            &resources,
            run,
            &widened,
            widened_round,
            &originals,
            &returned,
            ctx,
            &mut charges,
            stages,
        )
        .await
    }

    /// Opens `plan`'s branch resources at the wake pin: the payload the
    /// run decodes, the widened turns an accepted commit records as
    /// taken, and a fresh charge tally. A turn demoted since the wake
    /// prepared it waits for its promotion (FIX 3861), as one away at
    /// preparation does; that wait ends the partition before any model
    /// work.
    pub(super) fn start_partition<'a>(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'a>,
        plan: &PreparedConsolidationAttempt,
        wake: &'a PreparedWake,
        stages: &mut PartitionStages,
    ) -> Result<PartitionStart<'a>> {
        let payload = plan.input().clone();
        let opened = Instant::now();
        let resources = BranchResources::open_prepared(ctx.vault, self.actor, plan, wake);
        stages.branch_ms = ms_since(opened);
        let resources = match resources {
            Err(error) if super::super::residency::waits_on_residency(&error) => {
                return Ok(PartitionStart::Early(
                    super::super::residency::residency_deferral(ctx.now_ms, 0, Vec::new()),
                ));
            }
            resources => resources?,
        };
        // The widened peers carry the readings this branch froze of their
        // words at its open and the partition each was read under: a
        // window slot's finish re-opens its branch, but the stamp owes
        // the words as first read, never a reread.
        let widened: Vec<(EntityId, [u8; 32], [u8; 32])> = Self::widened_turns(attempt, plan)
            .into_iter()
            .filter_map(|turn| {
                let reading = resources.taken_reading(&turn).ok()?;
                let partition = resources.taken_partition(&turn).ok()?;
                Some((turn, reading, partition))
            })
            .collect();
        // The queued originals, with the same frozen readings and
        // partitions: the stamp's carrier guard revalidates the ids,
        // and members no round has taken yet (an away chunk member at
        // enqueue) are stamped from these when this run completes.
        let originals = Self::queued_originals(attempt);
        let returned: Vec<(EntityId, [u8; 32], [u8; 32])> = originals
            .iter()
            .filter_map(|turn| {
                let reading = resources.taken_reading(turn).ok()?;
                let partition = resources.taken_partition(turn).ok()?;
                Some((*turn, reading, partition))
            })
            .collect();
        // The projection round this attempt itself carries: a deferral
        // requeues this same row, and a successor copies kind + dedupe
        // key, so the id names the live round its window or chunk made.
        let widened_round = attempt
            .status
            .attempt
            .dedupe_key
            .as_deref()
            .map(|dedupe_key| {
                crate::dreamer_wake::projection_round_id(&attempt.status.attempt.kind, dedupe_key)
            });
        Ok(PartitionStart::Running(Box::new(PartitionStarted {
            payload,
            resources,
            widened,
            originals,
            returned,
            widened_round,
            charges: StepChargeTally::default(),
        })))
    }

    /// Settles one partition run's outcome: an accepted commit, a
    /// checkpoint, a park or a deferral, each carrying what the attempt
    /// already spent.
    pub(super) async fn settle_partition_run(
        &mut self,
        resources: &BranchResources<'_>,
        run: crate::llm::DurableStepResult<PartitionRun>,
        widened: &[(EntityId, [u8; 32], [u8; 32])],
        widened_round: Option<[u8; 32]>,
        originals: &[EntityId],
        returned: &[(EntityId, [u8; 32], [u8; 32])],
        ctx: &WakeAttemptContext<'_>,
        charges: &mut StepChargeTally,
        stages: &mut PartitionStages,
    ) -> Result<DreamerAttemptExecution> {
        match run {
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
                if let Err(error) = self
                    .commit_candidates(
                        &resources,
                        candidates,
                        widened,
                        widened_round,
                        originals,
                        returned,
                        ctx,
                        stages,
                    )
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
                if let Err(error) = self
                    .commit_candidates(
                        &resources,
                        candidates,
                        &[],
                        widened_round,
                        &[],
                        &[],
                        ctx,
                        stages,
                    )
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
            Err(crate::model_step_error::DurableStepError::Engine(error)) => {
                super::super::residency::spent_or_deferred(error, ctx, &charges)
            }
            // Every other failure parks with what the attempt spent, a
            // refused conflict read's paid usage included (FIX 414).
            Err(other) => Ok(super::failure::park_partition_failure_with_spend(
                other, charges,
            )),
        }
    }

    /// The prepared partition path's identity gates and scope pin,
    /// shared by the serial `execute` and a partition window's slot
    /// admission.
    pub(super) fn pin_prepared_partition(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &PreparedConsolidationAttempt,
    ) -> Result<()> {
        if plan.attempt_id() != attempt.status.attempt.id
            || !plan.matches_queued(&attempt.status.payload.input)
            || (ctx.prepared_wake.is_some()
                && self.scope.as_ref().is_some()
                && self.scope.as_ref() != plan.scope())
        {
            return Err(invalid_consolidation(
                "executor scope/identity differs from prepared attempt",
            ));
        }
        let branch_scope = super::super::branch_scope::pin_execution_scope(
            ctx.vault,
            attempt.status.attempt.id,
            plan.scope(),
        )?;
        if branch_scope.as_ref() != plan.scope() {
            return Err(invalid_consolidation(
                "prepared branch scope changed after the wake pin",
            ));
        }
        // FIX 7729: a child its preparation narrowed holds only what it runs.
        let narrowed = plan.branch().bucket_set();
        if super::super::partition::decode_partition_payload(&attempt.status.payload.input)
            .is_ok_and(|queued| queued.bucket_set() != narrowed)
        {
            super::super::running_buckets::record_running_buckets(
                ctx.vault,
                attempt.status.attempt.id,
                attempt.status.attempt.attempt_count,
                &narrowed,
            )?;
        }
        Ok(())
    }

    /// Hands `candidates` to the sink, its wall ms the commit stage. On an
    /// accepted commit it also records the frozen readings this branch's
    /// widening assigned (`widened`) as taken - only for widened turns
    /// still live, still reading as frozen, and still in the partition
    /// they were read under when the stamp runs -
    /// with the latest-round bookkeeping that assignment owes under
    /// this attempt's own round
    /// (`widened_round`), in the stamp's own commit after the candidates'
    /// (FIX 12246). The same stamp fills queued originals no round has
    /// taken (`returned` - an away chunk member at enqueue - revalidated
    /// against `originals`; fired returned stamps join `current`), and
    /// skips entirely when a gap erasure
    /// retired the carrier round. An attempt with no round of its own
    /// records nothing.
    async fn commit_candidates(
        &mut self,
        resources: &BranchResources<'_>,
        candidates: Vec<VerifiedCandidate>,
        widened: &[(EntityId, [u8; 32], [u8; 32])],
        widened_round: Option<[u8; 32]>,
        originals: &[EntityId],
        returned: &[(EntityId, [u8; 32], [u8; 32])],
        ctx: &WakeAttemptContext<'_>,
        stages: &mut PartitionStages,
    ) -> Result<()> {
        let started = Instant::now();
        let accepted = resources
            .accept_until(
                resources.scope(),
                self.sink,
                candidates,
                ctx.deadline,
                stages.landing(),
            )
            .await;
        stages.commit_ms = ms_since(started);
        // No carrier round (an unkeyed attempt) means no assignment record
        // at all, exactly as hold_in_txn skips dedupe-less outcomes: taken
        // without its round's membership and latest move would suppress
        // the turns while an older turn still holds. Unstamped, they
        // re-enter through the usual doors.
        if accepted.is_ok()
            && widened_round.is_some()
            && (!widened.is_empty() || !returned.is_empty())
        {
            // A failed stamp never fails the commit the extraction already
            // landed; it only costs a later duplicate extraction.
            let stamped = ctx.vault.with_write_txn_grouped(|txn| {
                // A gap erasure of an original (or its cited MESSAGE)
                // retired the carrier round with the member's GIVEN row:
                // recreating it here would resurrect retired membership
                // under words the erase already released. Skip the whole
                // stamp; unstamped turns re-enter through the usual doors.
                let Some(carrier) = widened_round else {
                    return Ok(());
                };
                if !crate::dreamer_wake::carrier_round_live_in_txn(
                    ctx.vault, txn, &carrier, originals,
                )? {
                    return Ok(());
                }
                // A widened turn erased or rewritten since the branch
                // opened is not stamped at its frozen reading: an erasure
                // in the gap already deleted its row, and moved-on words
                // re-enter through the usual doors.
                let mut current = Vec::new();
                for (turn, reading, partition) in widened {
                    // A same-text republish that moved the turn's partition
                    // reads as frozen but was extracted under other axes:
                    // new work there, never stamped here.
                    if crate::dreamer_wake::reading_current_in_txn(ctx.vault, txn, turn, *reading)?
                        && crate::dreamer_consolidation::turn_partition_hash_in_txn(
                            ctx.vault, txn, turn,
                        )? == Some(*partition)
                    {
                        current.push((*turn, *reading));
                    }
                }
                for (turn, reading) in &current {
                    crate::dreamer_wake::take_reading_in_txn(ctx.vault, txn, turn, *reading)?;
                }
                // Originals no round has taken (an away chunk member at
                // enqueue) are stamped at their frozen readings now that
                // the run that extracted them has landed; each fired
                // stamp joins the assignment the widened turns carry, so
                // the chain moves past the returned words and their
                // riders release with the widened ones'.
                for (turn, reading, partition) in returned {
                    if crate::dreamer_wake::take_returned_in_txn(
                        ctx.vault, txn, turn, *reading, *partition,
                    )? {
                        current.push((*turn, *reading));
                    }
                }
                crate::dreamer_wake::note_assignment_in_txn(ctx.vault, txn, widened_round, &current)
            });
            if let Err(error) = stamped {
                tracing::warn!(
                    turns = widened.len() + returned.len(),
                    kind = ?error.kind(),
                    "widened turns were not recorded as taken"
                );
            }
        }
        accepted
    }

    /// The turn ids `plan` runs beyond the attempt's queued originals: the
    /// peers a Micro selection retry's widening newly assigned (FIX 12246).
    /// Empty for every other scope and for branches widening kept to their
    /// originals; an unreadable queued payload also yields empty (no stamp
    /// is the safe direction: a later widening re-takes the words).
    /// The attempt's queued originals (Micro only): the ids the stamp's
    /// carrier guard revalidates and the completion stamp owes its
    /// untaken members. Empty for every other scope and for an
    /// unreadable queued payload.
    fn queued_originals(attempt: &DreamerAdmittedAttempt) -> Vec<EntityId> {
        if attempt.status.attempt.kind.as_str()
            != crate::dreamer_runner::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        {
            return Vec::new();
        }
        super::super::partition::decode_partition_payload(&attempt.status.payload.input)
            .map(|queued| queued.turn_ids().into_iter().collect())
            .unwrap_or_default()
    }

    fn widened_turns(
        attempt: &DreamerAdmittedAttempt,
        plan: &PreparedConsolidationAttempt,
    ) -> Vec<EntityId> {
        if attempt.status.attempt.kind.as_str()
            != crate::dreamer_runner::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        {
            return Vec::new();
        }
        let Ok(queued) =
            super::super::partition::decode_partition_payload(&attempt.status.payload.input)
        else {
            return Vec::new();
        };
        let originals: BTreeSet<EntityId> = queued.turn_ids().into_iter().collect();
        plan.turn_ids()
            .iter()
            .copied()
            .filter(|turn| !originals.contains(turn))
            .collect()
    }
}
