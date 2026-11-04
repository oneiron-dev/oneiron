//! One window of plain Micro partitions (FIX 12487): slots pinned and
//! opened in admission order, extraction prefixes side by side, then
//! serial finishes in order against branches re-opened at the finish,
//! so the committed rows equal the serial run's. Split from
//! `partition_run` (FIX 12774); the serial run and its settle stay there.

use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::task::Poll;
use std::time::Instant;

use crate::entity_id::bytes_to_hex_lower;

use super::super::parallel::PartitionPrefix;
use super::super::stage_log::PartitionStages;
use super::partition_run::{PartitionStart, PartitionStarted};
use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;

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
                            match super::super::step_charge::tally_extracted_outcomes(
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
                                        match super::super::step_charge::tally_extracted_outcomes(
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
                                    let trapped =
                                        super::super::step_charge::tally_extracted_outcomes(
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
}
