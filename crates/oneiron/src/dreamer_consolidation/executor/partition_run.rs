//! The prepared partition run `execute` ends in: the branch's resources at
//! the wake's pin, the partition's model work, and what its outcome settles
//! (accepted candidates, a checkpoint, a park or a deferral).

use std::collections::BTreeSet;
use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::task::Poll;
use std::time::Instant;

use crate::EntityId;
use crate::entity_id::bytes_to_hex_lower;

use super::super::parallel::PartitionPrefix;
use super::super::stage_log::{PartitionStages, ms_since};
use super::super::{PreparedConsolidationAttempt, PreparedWake};
use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;

/// A partition opened at its wake pin, ready for its model work.
struct PartitionStarted<'a> {
    payload: rmpv::Value,
    resources: BranchResources<'a>,
    /// The peers this attempt's widening newly assigned beyond its
    /// queued originals, with the readings this branch froze of their
    /// words at its open and the partition each was read under: recorded
    /// as taken only once the run completes, under `widened_round`
    /// (FIX 12246). A held run stamps none of them.
    widened: Vec<(EntityId, [u8; 32], [u8; 32])>,
    /// The queued originals, for the stamp's carrier-round guard.
    originals: Vec<EntityId>,
    /// The queued originals' frozen readings and partitions, for
    /// stamping members no round has taken yet on completion.
    returned: Vec<(EntityId, [u8; 32], [u8; 32])>,
    /// The projection round this attempt itself carries, for the
    /// latest-round bookkeeping its widened stamp owes; `None` for an
    /// unkeyed attempt, which records no assignment at all.
    widened_round: Option<[u8; 32]>,
    charges: StepChargeTally,
}

/// A partition at its open: already settled (a residency wait), or
/// running with its opened branch.
enum PartitionStart<'a> {
    Early(DreamerAttemptExecution),
    Running(Box<PartitionStarted<'a>>),
}

/// Why a window's finishes stopped before a slot: a pass-ending
/// error from an earlier slot, or a panic in one. Either way nothing
/// more runs this pass (the serial pass ends at the error; a
/// panicking executor is never reused, FIX 7322), so the slot settles
/// without committing (FIX 12487 round 2).
#[derive(Clone, Copy)]
enum WindowStopped {
    PassEndingError,
    Panic,
}

impl WindowStopped {
    /// The durable reason a stopped slot's park carries.
    fn park_reason(self) -> &'static str {
        match self {
            WindowStopped::PassEndingError => "partition window stopped after a pass-ending error",
            WindowStopped::Panic => "partition window stopped after an executor panic",
        }
    }
}

/// One slot of a partition window, from its admission to its finish.
enum WindowSlotRun<'a> {
    /// Decided at admission (a gate failure, or a residency wait at the
    /// open); the stage clock is present once the partition opened.
    Settled(Option<PartitionStages>, Result<DreamerAttemptExecution>),
    /// Not a plain prepared partition: executes serially in its place.
    Serial,
    /// Opened; its prefix runs (or ran) beside the window's other slots
    /// and its finish lands in window order.
    Running {
        started: Box<PartitionStarted<'a>>,
        stages: PartitionStages,
        run_id: Option<String>,
        run_started: Instant,
        prefix: Option<crate::llm::DurableStepResult<PartitionPrefix>>,
    },
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
    fn start_partition<'a>(
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
    async fn settle_partition_run(
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

    /// Runs one driver window of plain Micro partitions (FIX 12487):
    /// every slot is pinned and opened in admission order, the
    /// extraction prefixes run side by side, then each slot finishes
    /// serially in order against its branch re-opened at the finish —
    /// the live state a serial pass would read in that position — so
    /// the committed rows equal the serial run's. The driver gates the
    /// window to plain partitions; a slot of any other shape takes the
    /// serial `execute` in its place as a second lock.
    pub(super) async fn run_partition_window<'w>(
        &mut self,
        window: &mut [(&'w DreamerAdmittedAttempt, WakeAttemptContext<'w>)],
    ) -> Vec<Result<DreamerAttemptExecution>> {
        let mut slots: Vec<WindowSlotRun<'w>> = window
            .iter()
            .map(|(attempt, ctx)| self.admit_window_slot(attempt, ctx))
            .collect();
        // The prefixes, side by side, their outputs kept in slot order.
        let mut jobs = Vec::new();
        for (index, (slot, (attempt, ctx))) in slots.iter_mut().zip(window.iter()).enumerate() {
            if let WindowSlotRun::Running {
                started, run_id, ..
            } = slot
            {
                jobs.push((
                    index,
                    self.extract_partition_prefix(
                        &started.payload,
                        &started.resources,
                        ctx,
                        attempt.status.attempt.id,
                        run_id.clone(),
                        &mut started.charges,
                    ),
                ));
            }
        }
        let (indices, prefixes): (Vec<_>, Vec<_>) = jobs.into_iter().unzip();
        let width = prefixes.len().max(1);
        let outcomes = super::super::sieve_ports::ordered_slots(prefixes, width).await;
        for (index, outcome) in indices.into_iter().zip(outcomes) {
            if let WindowSlotRun::Running { prefix, .. } = &mut slots[index] {
                *prefix = Some(outcome);
            }
        }
        // The finishes, one by one in admission order. Each finish is
        // panic-contained on its own (FIX 12487 round 2): a panic in
        // one slot keeps the decided outcomes of the slots finished
        // before it (claims they already committed settle as
        // completed), marks the panicking slot with the shared panic
        // error so the driver ends the pass on it (FIX 7322), and
        // stops the window. A pass-ending error (the driver's own
        // owner-act rule) stops it the same way: later slots settle
        // without committing, as the serial pass never reaches them.
        let mut results = Vec::with_capacity(window.len());
        let mut stopped: Option<WindowStopped> = None;
        for (slot, (attempt, ctx)) in slots.into_iter().zip(window.iter_mut()) {
            let mut finish = pin!(self.finish_window_slot(slot, *attempt, ctx, stopped));
            let caught = poll_fn(|task_cx| {
                match std::panic::catch_unwind(AssertUnwindSafe(|| finish.as_mut().poll(task_cx))) {
                    Ok(poll) => poll.map(Ok),
                    Err(panic) => Poll::Ready(Err(panic)),
                }
            })
            .await;
            let result = match caught {
                Ok(result) => result,
                // The payload is dropped unread, as at the driver's
                // containment: a panic message can quote the row the
                // executor was working on, and logs never carry world
                // text. The attempt id says where to look.
                Err(_payload) => {
                    tracing::error!(
                        attempt_id = %bytes_to_hex_lower(attempt.status.attempt.id.as_bytes()),
                        kind = "executor_panic",
                        "dreamer attempt executor panicked; parking the admitted attempt"
                    );
                    if stopped.is_none() {
                        stopped = Some(WindowStopped::Panic);
                    }
                    Err(crate::dreamer_wake::executor_panic_error())
                }
            };
            if stopped.is_none()
                && result
                    .as_ref()
                    .is_err_and(|error| crate::dreamer_wake::executor_error_ends_pass(error.kind()))
            {
                stopped = Some(WindowStopped::PassEndingError);
            }
            results.push(result);
        }
        results
    }

    /// One window slot at its admission: the serial gates and open, in
    /// window order. What is not a plain prepared Micro partition — an
    /// unprepared or direct call, another attempt shape, a thing branch
    /// with its own scoped agent — stays serial in its place.
    fn admit_window_slot<'w>(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'w>,
    ) -> WindowSlotRun<'w> {
        if attempt.status.payload.attempt_type
            != crate::dreamer_runner::DreamerConsolidationScope::Micro.as_str()
        {
            return WindowSlotRun::Serial;
        }
        let (Some(plan), Some(wake)) = (ctx.prepared_attempt, ctx.prepared_wake) else {
            return WindowSlotRun::Serial;
        };
        if plan.branch().thing.is_some() {
            return WindowSlotRun::Serial;
        }
        match ctx
            .vault
            .dreamer_actor_for_attempt(attempt.status.attempt.id)
        {
            Ok(actor) if actor == self.actor => {}
            Ok(_) => {
                return WindowSlotRun::Settled(
                    None,
                    Err(invalid_consolidation(
                        "executor actor is not the queued Dreamer authority",
                    )),
                );
            }
            Err(error) => return WindowSlotRun::Settled(None, Err(error)),
        }
        if let Err(error) = self.pin_prepared_partition(attempt, ctx, plan) {
            return WindowSlotRun::Settled(None, Err(error));
        }
        let mut stages = PartitionStages::start(wake.prepared_ms());
        match self.start_partition(attempt, ctx, plan, wake, &mut stages) {
            Ok(PartitionStart::Early(done)) => WindowSlotRun::Settled(Some(stages), Ok(done)),
            Ok(PartitionStart::Running(started)) => WindowSlotRun::Running {
                started,
                stages,
                run_id: attempt.status.attempt.run_id.clone(),
                run_started: Instant::now(),
                prefix: None,
            },
            Err(error) => WindowSlotRun::Settled(Some(stages), Err(error)),
        }
    }

    /// One window slot's serial position: its finish and settle, with
    /// its stage line, in admission order. Once the window has
    /// `stopped`, the slot still settles in its place but runs and
    /// commits nothing: a stored outcome stands, a never-run shape
    /// parks, an extracted prefix is accounted and parked (FIX 12487
    /// round 2).
    async fn finish_window_slot<'w>(
        &mut self,
        slot: WindowSlotRun<'w>,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'w>,
        stopped: Option<WindowStopped>,
    ) -> Result<DreamerAttemptExecution> {
        let turns = ctx.prepared_attempt.map_or(0, |plan| plan.turn_ids().len());
        match slot {
            WindowSlotRun::Settled(stages, executed) => {
                if let Some(stages) = stages {
                    stages.log(attempt, turns, &executed);
                }
                executed
            }
            WindowSlotRun::Serial => match stopped {
                None => self.execute(attempt, ctx).await,
                // Never ran: no prefix, no spend. After a panic it
                // takes the panic outcome; after a pass-ending error
                // it parks resumable at zero.
                Some(WindowStopped::Panic) => Err(crate::dreamer_wake::executor_panic_error()),
                Some(stop) => Ok(StepChargeTally::default()
                    .park_for(stop.park_reason(), DreamerParkCause::Retry)),
            },
            WindowSlotRun::Running {
                started,
                mut stages,
                run_id,
                run_started,
                prefix,
            } => {
                let PartitionStarted {
                    payload,
                    resources,
                    widened,
                    originals,
                    returned,
                    widened_round,
                    mut charges,
                } = *started;
                let executed = match prefix.expect("a running slot's prefix ran") {
                    Err(error) => {
                        stages.close_model_run(run_started);
                        self.settle_partition_run(
                            &resources,
                            Err(error),
                            &widened,
                            widened_round,
                            &originals,
                            &returned,
                            ctx,
                            &mut charges,
                            &mut stages,
                        )
                        .await
                    }
                    Ok(PartitionPrefix::Done(run)) => {
                        stages.close_model_run(run_started);
                        if let Some(stop) = stopped
                            && !matches!(run, PartitionRun::Checkpoint)
                        {
                            // A running slot's Done is its cancel
                            // checkpoint; never settle any other run
                            // past the stop - Completed and Held
                            // commit.
                            Ok(charges.park_for(stop.park_reason(), DreamerParkCause::Retry))
                        } else {
                            self.settle_partition_run(
                                &resources,
                                Ok(run),
                                &widened,
                                widened_round,
                                &originals,
                                &returned,
                                ctx,
                                &mut charges,
                                &mut stages,
                            )
                            .await
                        }
                    }
                    Ok(PartitionPrefix::Extracted(extracted)) => {
                        if let Some(stop) = stopped {
                            // The window stopped ahead of this slot:
                            // account the prefix and park without
                            // finishing - the serial pass never reaches
                            // its commit.
                            stages.close_model_run(run_started);
                            match super::super::parallel::tally_extracted_outcomes(
                                ctx.vault,
                                attempt.status.attempt.id,
                                *extracted,
                                &mut charges,
                            ) {
                                Ok(true) => {
                                    self.settle_partition_run(
                                        &resources,
                                        Ok(PartitionRun::Trapped),
                                        &widened,
                                        widened_round,
                                        &originals,
                                        &returned,
                                        ctx,
                                        &mut charges,
                                        &mut stages,
                                    )
                                    .await
                                }
                                Ok(false) => {
                                    Ok(charges
                                        .park_for(stop.park_reason(), DreamerParkCause::Retry))
                                }
                                Err(error) => {
                                    super::super::residency::spent_or_deferred(error, ctx, &charges)
                                }
                            }
                        } else {
                            // The finish reads live state (admitted priors,
                            // candidate signals): re-open the branch now, so
                            // it sees what the serial order before it landed.
                            let plan = ctx.prepared_attempt.expect("a running slot is prepared");
                            let wake = ctx.prepared_wake.expect("a running slot is prepared");
                            match BranchResources::open_prepared(ctx.vault, self.actor, plan, wake)
                            {
                                Ok(fresh) => {
                                    // The prefix rendered its slices over the
                                    // priors admitted at its own open; when a
                                    // finish before this slot changed that set,
                                    // its labels no longer meet the fresh pins
                                    // and a candidate citing a closed head
                                    // would drop whole at parse. Discard the
                                    // prefix, account its spend, and run the
                                    // partition serially over the fresh branch
                                    // instead (FIX 12487 round 1). The stamp
                                    // still takes the admission-time frozen
                                    // widened/originals/returned values.
                                    let run = if fresh.admitted_prior_ids()
                                        == resources.admitted_prior_ids()
                                    {
                                        self.finish_partition_run(
                                            *extracted,
                                            &fresh,
                                            ctx,
                                            attempt.status.attempt.id,
                                            &mut charges,
                                            &mut stages,
                                        )
                                        .await
                                    } else {
                                        match super::super::parallel::tally_extracted_outcomes(
                                            ctx.vault,
                                            attempt.status.attempt.id,
                                            *extracted,
                                            &mut charges,
                                        ) {
                                            // A trapped slice already parked
                                            // the attempt under its durable
                                            // trap: settle the trapped exit;
                                            // the rerun must not extract past
                                            // it (FIX 12487 round 2).
                                            Ok(true) => Ok(PartitionRun::Trapped),
                                            Ok(false) => {
                                                self.run_partition_attempt(
                                                    &payload,
                                                    &fresh,
                                                    ctx,
                                                    attempt.status.attempt.id,
                                                    run_id,
                                                    &mut charges,
                                                    &mut stages,
                                                )
                                                .await
                                            }
                                            Err(error) => Err(error.into()),
                                        }
                                    };
                                    stages.close_model_run(run_started);
                                    self.settle_partition_run(
                                        &fresh,
                                        run,
                                        &widened,
                                        widened_round,
                                        &originals,
                                        &returned,
                                        ctx,
                                        &mut charges,
                                        &mut stages,
                                    )
                                    .await
                                }
                                Err(error) => {
                                    stages.close_model_run(run_started);
                                    // The finish that tallies the paid
                                    // extraction never runs on this arm:
                                    // account its steps first, so the
                                    // deferral settles the spend beside its
                                    // receipts instead of refunding at zero
                                    // (FIX 12487 round 1). A tally failure is
                                    // a genuine store failure and propagates.
                                    let trapped = super::super::parallel::tally_extracted_outcomes(
                                        ctx.vault,
                                        attempt.status.attempt.id,
                                        *extracted,
                                        &mut charges,
                                    )?;
                                    if trapped {
                                        // The trap decided first, at prefix
                                        // time; the reopen failure is moot
                                        // (the signal-resumed attempt
                                        // re-opens fresh then). Deferring
                                        // instead would requeue behind the
                                        // standing trap park (FIX 12487
                                        // round 2).
                                        self.settle_partition_run(
                                            &resources,
                                            Ok(PartitionRun::Trapped),
                                            &widened,
                                            widened_round,
                                            &originals,
                                            &returned,
                                            ctx,
                                            &mut charges,
                                            &mut stages,
                                        )
                                        .await
                                    } else {
                                        super::super::residency::spent_or_deferred(
                                            error, ctx, &charges,
                                        )
                                    }
                                }
                            }
                        }
                    }
                };
                stages.log(attempt, turns, &executed);
                executed
            }
        }
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
