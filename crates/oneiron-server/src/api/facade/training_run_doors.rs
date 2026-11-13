//! The role-training run doors (ROLE-TRAINING-RUN): the owner's prepare
//! (LEARN-TRAIN Q1) and the run's execute (LEARN-TRAIN Q4).
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use oneiron::task_verb::sdk::{
    RoleTrainingPrepareRequest, RoleTrainingPrepared, TRAINING_RUN_EXECUTE_VERB,
    TRAINING_RUN_PREPARE_VERB, TrainingRunExecuteRequest, TrainingRunObservation, TrainingRunPhase,
    TrainingRunProgress, training_run_execute_admits, training_run_observation,
    training_run_progress, training_run_read_for_execute, training_run_to_execute,
};
use oneiron::training_pack::{TrainingRun, TrainingState};

use super::FacadeApiError;
use super::host_doors::support::{Listed, MaybeListed, credential_listing, internal, owner_proof};
use crate::ai_host::training_pack::{TrainingStep, step, trainer_binding};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// How often an execute looks at its run again while it drives it.
const EXECUTE_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// `vault.coach.training_runs.prepare`: the owner's role run with no Train
/// offer, on a trainer connector this host names. It exports the consented
/// corpus and pins the spec; nothing runs until the owner authorizes that
/// spec. The door lists the rows the run was prepared from (FIX 5760),
/// unknown when the run's are; a refusal lists none.
pub(crate) async fn vault_coach_training_runs_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RoleTrainingPrepareRequest,
) -> MaybeListed<RoleTrainingPrepared> {
    let owner = match owner_proof(auth, server, TRAINING_RUN_PREPARE_VERB) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Some(Vec::new())),
    };
    let server = Arc::clone(server);
    let prepared = super::clock_ingress::run_blocking(move || -> MemoryResult<_> {
        let binding = trainer_binding(&server, &input.connector).ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                format!("this host names no trainer connector {:?}", input.connector),
                &["Name a role trainer from this host's [models.training.role_trainers]."],
            )
        })?;
        server
            .vault()
            .prepare_training_pack(
                &owner,
                &input.draft,
                input.scope.reservoir_scope(),
                &binding,
            )
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(TRAINING_RUN_PREPARE_VERB))
    .and_then(|prepared| prepared);
    match prepared {
        Ok(run) => (Ok(RoleTrainingPrepared::of(&run)), run.source_rows),
        Err(error) => (Err(error), Some(Vec::new())),
    }
}

/// `vault.coach.training_runs.execute`: this host's next step for a run its
/// owner authorized, for the owner or an agent whose own live Grant lists
/// the verb, checked in each snapshot the door reads. The answer is the
/// run's progress, not row content, so the door lists none.
pub(crate) async fn vault_coach_training_runs_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrainingRunExecuteRequest,
) -> Listed<TrainingRunObservation> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        TRAINING_RUN_EXECUTE_VERB,
        move |server, _, memory| execute(server, &memory, &input),
    )
    .await
}

/// The execute row's early authority check: the caller's own admission for
/// the verb, judged in a read snapshot before the row's verb hooks fire.
/// Each read the door makes checks it again.
pub(super) fn training_run_executor_admits(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<()> {
    let (actor, class) =
        super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    let memory =
        crate::api::credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality());
    training_run_execute_admits(&memory)
}

/// Takes the run's next step on this host, then drives it up to `wait_ms`:
/// it waits while the run moves on its own and scores a run that returns
/// inside the bound, then answers where the run stands. The bound ends only
/// this call: the run's trainer keeps running, and a later execute or the
/// Coach's queue takes the run on from where it stands.
fn execute(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: &TrainingRunExecuteRequest,
) -> MemoryResult<TrainingRunObservation> {
    let started = Instant::now();
    let bound = Duration::from_millis(input.wait_ms);
    let before = training_run_to_execute(memory, input)?;
    let now = || server.vault().now_recorded_at();
    let mut dispatched = step(server, &before, now()).map_err(failed)? == TrainingStep::Dispatched;
    let mut scored = before.state == TrainingState::Returned;
    loop {
        let run = training_run_read_for_execute(memory, &input.run)?.ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                "the training run was erased while it was executed",
                &[],
            )
        })?;
        // A dispatched run stays authorized until its trainer's thread
        // commits it running; a new hold is that thread's refusal.
        if dispatched && run.state == TrainingState::Authorized && run.hold == before.hold {
            if let Some(observation) = past_bound(&run, started, bound) {
                return Ok(observation);
            }
            std::thread::sleep(left(started, bound).min(EXECUTE_POLL_INTERVAL));
            continue;
        }
        dispatched = false;
        match training_run_progress(&run) {
            TrainingRunProgress::Running {
                phase: TrainingRunPhase::Evaluating,
            } if !scored => {
                scored = true;
                step(server, &run, now()).map_err(failed)?;
                continue;
            }
            TrainingRunProgress::Running { .. } => {}
            TrainingRunProgress::Outstanding { .. } | TrainingRunProgress::Done => {
                return Ok(answer(run, started));
            }
        }
        if let Some(observation) = past_bound(&run, started, bound) {
            return Ok(observation);
        }
        std::thread::sleep(left(started, bound).min(EXECUTE_POLL_INTERVAL));
    }
}

/// The answer for `run` once the bound has passed.
fn past_bound(
    run: &TrainingRun,
    started: Instant,
    bound: Duration,
) -> Option<TrainingRunObservation> {
    left(started, bound)
        .is_zero()
        .then(|| answer(run.clone(), started))
}

/// What is left of the bound.
fn left(started: Instant, bound: Duration) -> Duration {
    bound.saturating_sub(started.elapsed())
}

fn answer(run: TrainingRun, started: Instant) -> TrainingRunObservation {
    let waited_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    training_run_observation(run, waited_ms)
}

/// A step that errs on this host, by kind only: an engine error can quote
/// the vault.
fn failed(error: oneiron::Error) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!(
            "{TRAINING_RUN_EXECUTE_VERB} failed on this host: {:?}",
            error.kind()
        ),
        &["Read vault.coach.training_runs.get for where the run stands."],
    )
}
