//! One window of plain Micro or Meso partitions (FIX 12487): slots pinned and
//! opened in admission order; each slot's extraction prefix side by side,
//! and its finish at once after its own prefix (FIX 21927); then the
//! settles in admission order. A finish that ran ahead of an earlier
//! slot's settle lands only while no earlier slot committed and its
//! admitted priors still hold; else the slot runs again over its branch
//! re-opened in its place, so the committed rows equal the serial run's.
//! Split from `partition_run` (FIX 12774); the serial run and its settle
//! stay there.

use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::pin::{Pin, pin};
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
    /// Opened; its job runs (or ran) beside the window's other slots and
    /// it settles in window order.
    Running {
        started: Box<PartitionStarted<'a>>,
        stages: PartitionStages,
        run_id: Option<String>,
        run_started: Instant,
        work: Option<SlotWork>,
    },
    /// A sieve rung job: it runs whole (its span's evidence, its reading
    /// and its own commit) beside the prefixes, and its outcome, kept
    /// here, settles in window order.
    Rung(Option<Result<DreamerAttemptExecution>>),
}

/// What a running slot's side-by-side job ended with.
enum SlotWork {
    /// Its extraction prefix: a stop, an error, or extracted replies whose
    /// finish waits for the slot's place (the tournament arm).
    Prefix(crate::llm::DurableStepResult<PartitionPrefix>),
    /// Its finish, run at once after its own prefix extracted (FIX
    /// 21927), over the branch the slot opened: the run its settle lands
    /// in admission order. `live` when the finish got past its step tally
    /// to reads an earlier slot's commit could change.
    Finished {
        run: crate::llm::DurableStepResult<PartitionRun>,
        live: bool,
    },
    /// The job panicked; its containment logged the attempt.
    Panicked,
}

/// Polls `job` with its own panic containment: `None` once it panicked.
/// The payload is dropped unread, as at the driver's containment: a panic
/// message can quote the row the executor was working on, and logs never
/// carry world text. The attempt id says where to look.
async fn contained<F: Future>(job: F, attempt: &DreamerAdmittedAttempt) -> Option<F::Output> {
    let mut job = pin!(job);
    poll_fn(|task_cx| {
        match std::panic::catch_unwind(AssertUnwindSafe(|| job.as_mut().poll(task_cx))) {
            Ok(poll) => poll.map(Some),
            Err(_payload) => {
                tracing::error!(
                    attempt_id = %bytes_to_hex_lower(attempt.status.attempt.id.as_bytes()),
                    kind = "executor_panic",
                    "dreamer attempt executor panicked; parking the admitted attempt"
                );
                Poll::Ready(None)
            }
        }
    })
    .await
}

/// Runs one rung job with its own panic containment: a rung commits
/// inside the window's side-by-side phase, so a sibling's panic must not
/// unwind its decided outcome away. A panic becomes this slot's shared
/// executor-panic error, which stops the window as a slot panic does.
async fn contained_rung<F: Future<Output = Result<DreamerAttemptExecution>>>(
    job: F,
    attempt: &DreamerAdmittedAttempt,
) -> Result<DreamerAttemptExecution> {
    contained(job, attempt)
        .await
        .unwrap_or_else(|| Err(crate::dreamer_wake::executor_panic_error()))
}

/// Whether `result` may have landed rows a later slot's finish reads
/// (admitted priors, candidate signals): a commit, or a serial slot's own
/// run, which may commit.
fn may_have_committed(serial: bool, result: &Result<DreamerAttemptExecution>) -> bool {
    serial
        || matches!(
            result,
            Ok(DreamerAttemptExecution::Completed { .. }
                | DreamerAttemptExecution::Deferred { .. }
                | DreamerAttemptExecution::Landed { .. })
        )
}

/// Polls `first` and `second` together until both end.
async fn both<A: Future, B: Future>(first: A, second: B) -> (A::Output, B::Output) {
    let mut first = pin!(first);
    let mut second = pin!(second);
    let (mut first_out, mut second_out) = (None, None);
    poll_fn(|task_cx| {
        if first_out.is_none()
            && let Poll::Ready(out) = first.as_mut().poll(task_cx)
        {
            first_out = Some(out);
        }
        if second_out.is_none()
            && let Poll::Ready(out) = second.as_mut().poll(task_cx)
        {
            second_out = Some(out);
        }
        match (first_out.take(), second_out.take()) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            (a, b) => {
                first_out = a;
                second_out = b;
                Poll::Pending
            }
        }
    })
    .await
}

impl ConsolidationExecutor<'_> {
    /// Runs one driver window of plain Micro or Meso partitions (FIX 12487):
    /// every slot is pinned and opened in admission order, and the slots'
    /// jobs run side by side: each slot's extraction prefix and, as soon
    /// as that prefix extracted, its finish (FIX 21927), so a slot whose
    /// prefix ends early never waits for its slowest sibling's. Then each
    /// slot settles in admission order. A finish that ran before an
    /// earlier slot's settle read the branch as its slot opened it: it
    /// lands as it ran only while no earlier slot committed and its
    /// admitted priors still hold. Otherwise the slot runs again over its
    /// branch re-opened in its place - the live state a serial pass would
    /// read there, its memoized steps replaying - so the committed rows
    /// equal the serial run's. A sieve rung job in the window runs whole
    /// beside the prefixes: its commit touches only its own span's
    /// reading, which no partition's finish reads. The driver gates the
    /// window to these shapes; a slot of any other shape takes the serial
    /// `execute` in its place as a second lock.
    pub(super) async fn run_partition_window<'w>(
        &mut self,
        window: &mut [(&'w DreamerAdmittedAttempt, WakeAttemptContext<'w>)],
    ) -> Vec<Result<DreamerAttemptExecution>> {
        let mut slots: Vec<WindowSlotRun<'w>> = window
            .iter()
            .map(|(attempt, ctx)| self.admit_window_slot(attempt, ctx))
            .collect();
        // The slot jobs and the rung jobs, side by side, their outputs kept
        // in slot order. Each slot job is panic-contained on its own, as a
        // rung job is: a sibling's panic must not unwind a finished slot's
        // run away.
        let mut jobs = Vec::new();
        let mut rungs = Vec::new();
        for (index, (slot, (attempt, ctx))) in slots.iter_mut().zip(window.iter()).enumerate() {
            match slot {
                WindowSlotRun::Running {
                    started,
                    stages,
                    run_started,
                    ..
                } => jobs.push((
                    index,
                    self.boxed_window_slot_job(started, stages, *run_started, attempt, ctx),
                )),
                WindowSlotRun::Rung(_) => rungs.push((index, self.boxed_rung_job(attempt, ctx))),
                WindowSlotRun::Settled(..) | WindowSlotRun::Serial => {}
            }
        }
        let (indices, slot_jobs): (Vec<_>, Vec<_>) = jobs.into_iter().unzip();
        let (rung_indices, rung_runs): (Vec<_>, Vec<_>) = rungs.into_iter().unzip();
        let width = slot_jobs.len().max(1);
        let rung_width = rung_runs.len().max(1);
        let (works, rung_outcomes) = both(
            super::super::sieve_ports::ordered_slots(slot_jobs, width),
            super::super::sieve_ports::ordered_slots(rung_runs, rung_width),
        )
        .await;
        let side_by_side_ended = Instant::now();
        for (index, outcome) in rung_indices.into_iter().zip(rung_outcomes) {
            if let WindowSlotRun::Rung(done) = &mut slots[index] {
                *done = Some(outcome);
            }
        }
        for (index, ended) in indices.into_iter().zip(works) {
            if let WindowSlotRun::Running { work, stages, .. } = &mut slots[index] {
                *work = Some(ended.unwrap_or(SlotWork::Panicked));
                stages.mark_window_prefixes_ended(side_by_side_ended);
            }
        }
        // The settles, one by one in admission order. Each is
        // panic-contained on its own (FIX 12487 round 2): a panic in
        // one slot keeps the decided outcomes of the slots settled
        // before it (claims they already committed settle as
        // completed), marks the panicking slot with the shared panic
        // error so the driver ends the pass on it (FIX 7322), and
        // stops the window. A pass-ending error (the driver's own
        // owner-act rule) stops it the same way: later slots settle
        // without committing, as the serial pass never reaches them.
        let mut results = Vec::with_capacity(window.len());
        let mut stopped: Option<WindowStopped> = None;
        // Once an earlier slot may have committed, a later slot's finish
        // that ran ahead of it no longer stands (FIX 21927).
        let mut committed = false;
        for (slot, (attempt, ctx)) in slots.into_iter().zip(window.iter_mut()) {
            let serial = matches!(slot, WindowSlotRun::Serial);
            let caught = {
                let mut finish =
                    self.boxed_finish_window_slot(slot, *attempt, ctx, stopped, committed);
                poll_fn(|task_cx| {
                    match std::panic::catch_unwind(AssertUnwindSafe(|| {
                        finish.as_mut().poll(task_cx)
                    })) {
                        Ok(poll) => poll.map(Ok),
                        Err(panic) => Poll::Ready(Err(panic)),
                    }
                })
                .await
            };
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
            committed |= may_have_committed(serial, &result);
            // A rung job's or a slot job's contained panic stops the
            // window as a settle's panic does.
            if stopped.is_none()
                && result
                    .as_ref()
                    .is_err_and(crate::dreamer_wake::is_executor_panic_error)
            {
                stopped = Some(WindowStopped::Panic);
            }
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
    /// window order. What is not a plain prepared Micro or Meso partition — an
    /// unprepared or direct call, another attempt shape, a thing branch
    /// with its own scoped agent — stays serial in its place.
    fn admit_window_slot<'w>(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'w>,
    ) -> WindowSlotRun<'w> {
        if super::super::selection::windowed_rung(
            &attempt.status.attempt.kind,
            &attempt.status.payload.attempt_type,
        ) {
            // The same authority check `execute` makes before any shape.
            return match ctx
                .vault
                .dreamer_actor_for_attempt(attempt.status.attempt.id)
            {
                Ok(actor) if actor == self.actor => WindowSlotRun::Rung(None),
                Ok(_) => WindowSlotRun::Settled(
                    None,
                    Err(invalid_consolidation(
                        "executor actor is not the queued Dreamer authority",
                    )),
                ),
                Err(error) => WindowSlotRun::Settled(None, Err(error)),
            };
        }
        if !super::super::selection::windowed_partition(
            &attempt.status.attempt.kind,
            &attempt.status.payload.attempt_type,
        ) {
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
                work: None,
            },
            Err(error) => WindowSlotRun::Settled(Some(stages), Err(error)),
        }
    }

    /// One running slot's side-by-side job: its extraction prefix, then,
    /// once that prefix extracted, its finish at once over the branch the
    /// slot opened (FIX 21927), up to the run its settle lands. The finish
    /// commits nothing: the commit stays in the settle, in admission
    /// order. The tournament arm's finish lands its winner as it runs, so
    /// it still waits for the slot's place.
    async fn run_window_slot_job(
        &self,
        started: &mut PartitionStarted<'_>,
        stages: &mut PartitionStages,
        run_started: Instant,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> SlotWork {
        let attempt_id = attempt.status.attempt.id;
        let prefix = self
            .boxed_extract_partition_prefix(
                &started.payload,
                &started.resources,
                ctx,
                attempt_id,
                attempt.status.attempt.run_id.clone(),
                &mut started.charges,
            )
            .await;
        // The slot's own prefix end, apart from the window's (FIX 21929).
        let prefix_ended = Instant::now();
        stages.mark_prefix_ended(prefix_ended);
        match prefix {
            Ok(PartitionPrefix::Extracted(extracted))
                if !matches!(self.strategy, DreamerClaimAuthoringStrategy::Tournament) =>
            {
                // No barrier and no queue before this finish: it waits for
                // no sibling's prefix and no earlier finish.
                stages.mark_window_prefixes_ended(prefix_ended);
                stages.mark_finish_started(prefix_ended);
                let live = !extracted.steps_decide_finish();
                let run = self
                    .boxed_finish_partition_run(
                        *extracted,
                        &started.resources,
                        ctx,
                        attempt_id,
                        &mut started.charges,
                        stages,
                    )
                    .await;
                stages.close_model_run(run_started);
                SlotWork::Finished { run, live }
            }
            prefix => SlotWork::Prefix(prefix),
        }
    }

    // The window awaits its big futures behind a box, each built in a
    // helper of its own (FIX 21927). This crate builds at opt-level 0 in
    // dev and test, where each future a function builds keeps its own
    // stack slot for the whole call. Built inline, the slot jobs and the
    // settles and re-runs of `finish_window_slot` overflowed the 2 MiB
    // test thread of `dreamer_window_finish_order`; built here, the
    // caller's frame holds only a pointer. A slot's finish now runs
    // beneath its slot job's prefix rather than beneath the window's
    // settle, so the prefix, the rung job, each slot's settle and the
    // serial `execute` are boxed as well: no frame on that path keeps a
    // whole executor future.

    /// [`Self::extract_partition_prefix`], for a window slot's prefix.
    fn boxed_extract_partition_prefix<'s>(
        &'s self,
        payload_input: &'s Value,
        resources: &'s BranchResources<'_>,
        ctx: &'s WakeAttemptContext<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        run_id: Option<String>,
        charges: &'s mut StepChargeTally,
    ) -> Pin<Box<dyn Future<Output = crate::llm::DurableStepResult<PartitionPrefix>> + 's>> {
        Box::pin(self.extract_partition_prefix(
            payload_input,
            resources,
            ctx,
            attempt_id,
            run_id,
            charges,
        ))
    }

    /// A sieve rung job behind its panic containment.
    fn boxed_rung_job<'s>(
        &'s self,
        attempt: &'s DreamerAdmittedAttempt,
        ctx: &'s WakeAttemptContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<DreamerAttemptExecution>> + 's>> {
        Box::pin(contained_rung(self.run_rung_job(attempt, ctx), attempt))
    }

    /// [`Self::finish_window_slot`], for one slot's settle.
    fn boxed_finish_window_slot<'s, 'w>(
        &'s mut self,
        slot: WindowSlotRun<'w>,
        attempt: &'s DreamerAdmittedAttempt,
        ctx: &'s mut WakeAttemptContext<'w>,
        stopped: Option<WindowStopped>,
        committed: bool,
    ) -> Pin<Box<dyn Future<Output = Result<DreamerAttemptExecution>> + 's>> {
        Box::pin(self.finish_window_slot(slot, attempt, ctx, stopped, committed))
    }

    /// The serial `execute`, for a window slot of a shape the window
    /// does not run.
    fn boxed_execute<'s>(
        &'s mut self,
        attempt: &'s DreamerAdmittedAttempt,
        ctx: &'s mut WakeAttemptContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<DreamerAttemptExecution>> + 's>> {
        Box::pin(self.execute(attempt, ctx))
    }

    /// [`Self::run_window_slot_job`] behind its panic containment.
    fn boxed_window_slot_job<'s>(
        &'s self,
        started: &'s mut PartitionStarted<'_>,
        stages: &'s mut PartitionStages,
        run_started: Instant,
        attempt: &'s DreamerAdmittedAttempt,
        ctx: &'s WakeAttemptContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Option<SlotWork>> + 's>> {
        Box::pin(contained(
            self.run_window_slot_job(started, stages, run_started, attempt, ctx),
            attempt,
        ))
    }

    /// [`Self::settle_partition_run`], for a window slot's settle.
    #[expect(
        clippy::too_many_arguments,
        reason = "it passes settle_partition_run's own arguments through"
    )]
    fn boxed_settle_partition_run<'s>(
        &'s mut self,
        resources: &'s BranchResources<'_>,
        run: crate::llm::DurableStepResult<PartitionRun>,
        widened: &'s [(EntityId, [u8; 32], [u8; 32])],
        widened_round: Option<[u8; 32]>,
        originals: &'s [EntityId],
        returned: &'s [(EntityId, [u8; 32], [u8; 32])],
        ctx: &'s WakeAttemptContext<'_>,
        charges: &'s mut StepChargeTally,
        stages: &'s mut PartitionStages,
    ) -> Pin<Box<dyn Future<Output = Result<DreamerAttemptExecution>> + 's>> {
        Box::pin(self.settle_partition_run(
            resources,
            run,
            widened,
            widened_round,
            originals,
            returned,
            ctx,
            charges,
            stages,
        ))
    }

    /// [`Self::run_partition_attempt`], for a window slot's re-run over its
    /// re-opened branch.
    #[expect(
        clippy::too_many_arguments,
        reason = "it passes run_partition_attempt's own arguments through"
    )]
    fn boxed_run_partition_attempt<'s>(
        &'s mut self,
        payload_input: &'s Value,
        resources: &'s BranchResources<'_>,
        ctx: &'s WakeAttemptContext<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        run_id: Option<String>,
        charges: &'s mut StepChargeTally,
        stages: &'s mut PartitionStages,
    ) -> Pin<Box<dyn Future<Output = crate::llm::DurableStepResult<PartitionRun>> + 's>> {
        Box::pin(self.run_partition_attempt(
            payload_input,
            resources,
            ctx,
            attempt_id,
            run_id,
            charges,
            stages,
        ))
    }

    /// [`Self::finish_partition_run`], for a window slot's finish.
    fn boxed_finish_partition_run<'s>(
        &'s self,
        extracted: super::super::parallel::ExtractedPartition,
        resources: &'s BranchResources<'_>,
        ctx: &'s WakeAttemptContext<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        charges: &'s mut StepChargeTally,
        stages: &'s mut PartitionStages,
    ) -> Pin<Box<dyn Future<Output = crate::llm::DurableStepResult<PartitionRun>> + 's>> {
        Box::pin(self.finish_partition_run(extracted, resources, ctx, attempt_id, charges, stages))
    }

    /// One window slot's serial position: its settle (and a finish its job
    /// left to it), with its stage line, in admission order. Once the
    /// window has `stopped`, the slot still settles in its place but runs
    /// and commits nothing: a stored outcome stands, a never-run shape
    /// parks, an extracted prefix or a finished run is accounted and
    /// parked (FIX 12487 round 2). Once an earlier slot `committed`, a
    /// finished run that may land runs again in its place (FIX 21927).
    async fn finish_window_slot<'w>(
        &mut self,
        slot: WindowSlotRun<'w>,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'w>,
        stopped: Option<WindowStopped>,
        committed: bool,
    ) -> Result<DreamerAttemptExecution> {
        let turns = ctx.prepared_attempt.map_or(0, |plan| plan.turn_ids().len());
        match slot {
            WindowSlotRun::Settled(stages, executed) => {
                if let Some(stages) = stages {
                    stages.log(attempt, turns, &executed);
                }
                executed
            }
            // It ran whole beside the prefixes, so its outcome stands even
            // when an earlier finish stopped the window: its work is done.
            WindowSlotRun::Rung(done) => done.unwrap_or_else(|| {
                Err(crate::Error::InvariantViolation(
                    "a window's rung job did not run",
                ))
            }),
            WindowSlotRun::Serial => match stopped {
                None => self.boxed_execute(attempt, ctx).await,
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
                work,
            } => {
                stages.mark_finish_started(Instant::now());
                let PartitionStarted {
                    payload,
                    resources,
                    widened,
                    originals,
                    returned,
                    widened_round,
                    mut charges,
                } = *started;
                let executed = match work.expect("a running slot's job ran") {
                    // Its job's containment logged it; the shared panic
                    // error stops the window here (FIX 7322).
                    SlotWork::Panicked => Err(crate::dreamer_wake::executor_panic_error()),
                    SlotWork::Finished { run, live } => match (stopped, run) {
                        // The window stopped ahead of this slot: only a
                        // checkpoint, a trap, a spent seat's refusal or an
                        // error settles, as a stopped prefix's do (review
                        // round 2 of #7340); a run that would land parks
                        // uncommitted, its spend accounted.
                        (
                            Some(_),
                            run @ (Ok(PartitionRun::Checkpoint
                            | PartitionRun::Trapped
                            | PartitionRun::SeatRefused { .. })
                            | Err(_)),
                        )
                        // A checkpoint, a trap or a seat refusal lands
                        // nothing: it stands whatever an earlier slot
                        // committed, and a re-run would ask the spent seat
                        // again before its available write.
                        | (
                            None,
                            run @ Ok(PartitionRun::Checkpoint
                            | PartitionRun::Trapped
                            | PartitionRun::SeatRefused { .. }),
                        ) => {
                            self.boxed_settle_partition_run(
                                &resources,
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
                        (Some(stop), Ok(_)) => {
                            Ok(charges.park_for(stop.park_reason(), DreamerParkCause::Retry))
                        }
                        // Its steps alone decided it (a refused slice): it
                        // read nothing an earlier slot could change.
                        (None, run) if !live => {
                            self.boxed_settle_partition_run(
                                &resources,
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
                        (None, run) => {
                            let plan = ctx.prepared_attempt.expect("a running slot is prepared");
                            let wake = ctx.prepared_wake.expect("a running slot is prepared");
                            match BranchResources::open_prepared(ctx.vault, self.actor, plan, wake)
                            {
                                // Nothing the serial order put before this
                                // slot changed what its finish read: no
                                // earlier commit, the same admitted priors.
                                // It lands as it ran, over the branch it ran
                                // on (the fallback binding its finish made is
                                // there).
                                Ok(fresh)
                                    if !committed
                                        && fresh.admitted_prior_ids()
                                            == resources.admitted_prior_ids() =>
                                {
                                    self.boxed_settle_partition_run(
                                        &resources,
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
                                // An earlier slot may have committed rows the
                                // finish reads (admitted priors, candidate
                                // signals): run the partition again over the
                                // branch re-opened here, as the serial order
                                // would. Its memoized steps replay, inside the
                                // finalize window too; its finish already
                                // accounted the paid steps.
                                Ok(fresh) => {
                                    let rerun = self
                                        .boxed_run_partition_attempt(
                                            &payload,
                                            &fresh,
                                            ctx,
                                            attempt.status.attempt.id,
                                            run_id,
                                            &mut charges,
                                            &mut stages,
                                        )
                                        .await;
                                    stages.close_model_run(run_started);
                                    self.boxed_settle_partition_run(
                                        &fresh,
                                        rerun,
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
                                // The finish accounted its steps: the
                                // deferral settles that spend.
                                Err(error) => {
                                    super::super::residency::spent_or_deferred(error, ctx, &charges)
                                }
                            }
                        }
                    },
                    SlotWork::Prefix(Err(error)) => {
                        stages.close_model_run(run_started);
                        self.boxed_settle_partition_run(
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
                    SlotWork::Prefix(Ok(PartitionPrefix::Done(run))) => {
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
                            self.boxed_settle_partition_run(
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
                    SlotWork::Prefix(Ok(PartitionPrefix::Extracted(extracted))) => {
                        if let Some(stop) = stopped {
                            // The window stopped ahead of this slot:
                            // account the prefix and park without
                            // finishing - the serial pass never reaches
                            // its commit. A slice that already decided
                            // the try (a trap, or a spent seat's refusal)
                            // settles as the finish would have settled it
                            // (review round 2 of #7340).
                            stages.close_model_run(run_started);
                            match super::super::step_charge::tally_extracted_outcomes(
                                ctx.vault,
                                *extracted,
                                &mut charges,
                            ) {
                                Ok(Some(decided)) => {
                                    self.boxed_settle_partition_run(
                                        &resources,
                                        Ok(decided),
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
                                Ok(None) => {
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
                                        self.boxed_finish_partition_run(
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
                                            *extracted,
                                            &mut charges,
                                        ) {
                                            // A trapped slice already parked
                                            // the attempt under its durable
                                            // trap: settle the trapped exit;
                                            // the rerun must not extract past
                                            // it (FIX 12487 round 2). A spent
                                            // seat's refusal waits on that
                                            // seat: the rerun must not ask it
                                            // again before its available
                                            // write (review round 2 of #7340).
                                            Ok(Some(decided)) => Ok(decided),
                                            Ok(None) => {
                                                self.boxed_run_partition_attempt(
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
                                    self.boxed_settle_partition_run(
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
                                    let decided =
                                        super::super::step_charge::tally_extracted_outcomes(
                                            ctx.vault,
                                            *extracted,
                                            &mut charges,
                                        )?;
                                    if let Some(decided) = decided {
                                        // The trap or the spent seat decided
                                        // first, at prefix time; the reopen
                                        // failure is moot (the resumed
                                        // attempt re-opens fresh then).
                                        // Deferring instead would requeue
                                        // behind the standing trap park
                                        // (FIX 12487 round 2), or ask the
                                        // seat again before its available
                                        // write (review round 2 of #7340).
                                        self.boxed_settle_partition_run(
                                            &resources,
                                            Ok(decided),
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
