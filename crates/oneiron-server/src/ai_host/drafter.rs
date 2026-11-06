//! The host's drafter trainer (FIX 14974, FIX 12569 slice 3): the
//! `coach.drafter_retrain` arm, which trains the version a night prepared on
//! a drafter trainer connector of this host (`[models.training.drafters]`).
//!
//! A night whose recipe a connector here lists, for the target this process
//! serves a drafter for, prepares a version and hands it here. The arm then:
//! - builds the run admission from the recipe's quote (its GPU seconds at the
//!   connector's unit cost) and admits that many units on the connector; a
//!   refusal holds the night with `no_admission`;
//! - moves the version to `training` before anything is sent
//!   (`Vault::begin_drafter_training`), then parks the night, so the night's
//!   root stays open while the GPU works;
//! - hands the job to its own thread with its own runtime: the Coach's
//!   sequential round never waits on a GPU. That thread queues the job on
//!   the target worker's device work line as background work of the
//!   recipe's declared memory (`models::DrafterTrainingSlot`), stages one
//!   private `(version, spec)` job directory, runs the worker as the
//!   training pack's connector runs its worker (`job`, `process`), and stops
//!   it on an erase, the off switch, another recipe or the recipe's GPU
//!   seconds;
//! - on a receipt that verifies, seals the output under the version's own key
//!   through `begin_drafter_artifact`, `DrafterSealing::seal_file` and
//!   `publish_drafter_artifact`: an erase during training refuses the
//!   publication and retires its key. Otherwise it records why
//!   (`Vault::fail_drafter_training`). Either way the job directory, the only
//!   place the training side was plaintext, is removed, and the units used
//!   are settled once.
//!
//! Each Coach round first runs the recovery pass ([`recover`]): a version a
//! restart left training gets its job read again without a second dispatch
//! (a receipt completes it; a worker still holding its lock runs on, and is
//! stopped when its version may no longer train; a job with neither is
//! lost), and a night parked on a job that ended is resumed, so its next run
//! records `trained` or `failed`. The night resumes only from the round, so
//! a fast job never races the round that parked it.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oneiron::attempt_queue::AttemptId;
use oneiron::drafter::{
    DrafterHoldReason, DrafterNightStep, DrafterRecipe, DrafterTrainingDispatch,
    DrafterTrainingFailure, DrafterTrainingJob, DrafterVersionState,
};
use oneiron::dreamer_runner::maintenance::coach::COACH_DRAFTER_RETRAIN_FACET;
use oneiron::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerParkCause, DreamerRunnerStore, ParkDreamerAttempt,
};
use oneiron::llm::WorkCancel;
use oneiron::llm::run_admission::{
    BudgetLine, CallOutcome, PaidConnector, RunAdmission, RunDeclaration, RunPermit,
};
use oneiron::{EntityId, Error, Vault};

use crate::config::models::DrafterTrainerSettings;
use crate::models::DrafterTrainingSlot;
use crate::server::SyncServer;

mod job;
mod process;

use job::{JobDir, Verified};

/// Who parks a night while its version trains, and alone resumes it.
pub(super) const DRAFTER_PARK_OWNER: &str = "coach.drafter_retrain";
/// The parked row's reason.
const DRAFTER_PARK_REASON: &str = "drafter.training: the night's version trains";
/// How often a running job reads whether its version may still train.
const TRAINING_WATCH_INTERVAL: Duration = Duration::from_secs(15);

/// The versions whose job has a live waiter in this process: a dispatch or a
/// recovery thread. The recovery pass leaves them alone.
static WAITERS: Mutex<BTreeSet<EntityId>> = Mutex::new(BTreeSet::new());

fn waiters() -> MutexGuard<'static, BTreeSet<EntityId>> {
    WAITERS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The admission ref a version's training runs under: one per version.
fn admission_ref(version: &EntityId) -> String {
    format!("drafter-training:{}", version.to_hex())
}

/// The declaration a version's training is admitted under, from its recipe
/// alone: a declared run that may call only the trainer's connector, on a
/// budget line of exactly the recipe's GPU seconds at the connector's unit
/// cost, in that unit.
fn drafter_declaration(
    recipe: &DrafterRecipe,
    binding: &PaidConnector,
) -> oneiron::Result<RunDeclaration> {
    let units = binding
        .unit_cost
        .checked_mul(recipe.gpu_seconds)
        .filter(|units| *units > 0)
        .ok_or_else(|| {
            Error::InvalidConfig("the drafter recipe's quote is empty or overflows".into())
        })?;
    Ok(RunDeclaration::declared(BudgetLine {
        limit_units: units,
        reserve_units: units,
        unit: binding.cost_unit.clone(),
    })
    .with_connector(binding.connector.clone()))
}

/// The `coach.drafter_retrain` arm: runs the night's step, and trains the
/// version it prepared, or recovers the one it dispatched.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let target = crate::models::drafter_retrain_target();
    let training = server.ai.model_runtime().training();
    let trains = |recipe: &DrafterRecipe| training.drafter_trainer(&recipe.id).is_some();
    match vault.run_coach_drafter_retrain(admitted, target.as_ref(), &trains, now)? {
        DrafterNightStep::Ended(outcome) => {
            tracing::debug!(?outcome, "the Coach's nightly drafter retrain");
            Ok(())
        }
        DrafterNightStep::Train(job) => train(server, admitted, *job, now),
    }
}

/// Whether the round's attempt is a night parked on its training: the round
/// keeps it open and gives back only its unit.
pub(super) fn yielded(
    store: &DreamerRunnerStore<'_>,
    admitted: &DreamerAdmittedAttempt,
) -> oneiron::Result<bool> {
    if admitted.status.payload.attempt_type != COACH_DRAFTER_RETRAIN_FACET {
        return Ok(false);
    }
    Ok(store
        .parked_attempt(admitted.status.attempt.id)?
        .is_some_and(|park| park.park_owner == DRAFTER_PARK_OWNER))
}

fn park(vault: &Vault, attempt: AttemptId, now: u64) -> oneiron::Result<()> {
    DreamerRunnerStore::new(vault).park_attempt(ParkDreamerAttempt {
        attempt_id: attempt,
        reason: DRAFTER_PARK_REASON.to_owned(),
        cause: DreamerParkCause::Signal,
        park_owner: DRAFTER_PARK_OWNER.to_owned(),
        carried_spend: None,
        now,
    })?;
    Ok(())
}

/// Ends the night whose dispatch ended before any thread took it: its next
/// step records how.
fn end_night(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let nothing = |_: &DrafterRecipe| false;
    match vault.run_coach_drafter_retrain(admitted, None, &nothing, now)? {
        DrafterNightStep::Ended(outcome) => {
            tracing::debug!(?outcome, "the Coach's nightly drafter retrain");
        }
        DrafterNightStep::Train(_) => {
            tracing::warn!("a drafter night ended its dispatch with its version still training");
        }
    }
    Ok(())
}

/// Dispatches the night's prepared version on this host's trainer, or holds
/// the night with why it cannot; a version that trains already is left to
/// its waiter or the recovery pass, the night parked.
fn train(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    job: DrafterTrainingJob,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let attempt = admitted.status.attempt.id;
    if job.state == DrafterVersionState::Training {
        return park(vault, attempt, now);
    }
    let training = server.ai.model_runtime().training();
    let Some((name, trainer)) = training.drafter_trainer(&job.recipe.id) else {
        vault.hold_drafter_night(admitted, DrafterHoldReason::NoTrainerRecipe)?;
        return Ok(());
    };
    let (name, trainer) = (name.to_owned(), trainer.clone());
    let Ok(declaration) = drafter_declaration(&job.recipe, &trainer.binding) else {
        vault.hold_drafter_night(admitted, DrafterHoldReason::NoAdmission)?;
        return Ok(());
    };
    let admission = server
        .ai
        .declared_run(admission_ref(&job.version), declaration, None)
        .admission()
        .clone();
    let permit = match admission
        .sourced(Some(job.sources.clone()))
        .admit_paid(&trainer.binding, job.recipe.gpu_seconds)
    {
        Ok(permit) => permit,
        Err(denied) => {
            tracing::info!(%denied, "a drafter night holds: its quote was not admitted");
            vault.hold_drafter_night(admitted, DrafterHoldReason::NoAdmission)?;
            return Ok(());
        }
    };
    let dispatch = DrafterTrainingDispatch {
        connector: name,
        connector_revision: trainer.binding.catalog_revision.clone(),
        quoted_units: job.recipe.gpu_seconds,
        unit_cost: trainer.binding.unit_cost,
        cost_unit: trainer.binding.cost_unit.as_str().to_owned(),
    };
    // The training state, before anything is sent.
    let generation = match vault.begin_drafter_training(&job.version, job.generation, dispatch) {
        Ok(generation) => generation,
        Err(error) => {
            tracing::info!(kind = ?error.kind(), "a drafter night holds: its version moved");
            settle_unsent(permit);
            vault.hold_drafter_night(admitted, DrafterHoldReason::PolicyMoved)?;
            return Ok(());
        }
    };
    if let Err(denied) = admission.dispatch_paid(permit.lease(), &trainer.binding) {
        tracing::info!(%denied, "a drafter training was refused before it was sent");
        settle_unsent(permit);
        vault.fail_drafter_training(
            &job.version,
            generation,
            DrafterTrainingFailure::Refused,
            None,
        )?;
        return end_night(server, admitted, now);
    }
    park(vault, attempt, now)?;
    waiters().insert(job.version);
    let version = job.version;
    let run = TrainingRun {
        vault: Arc::clone(vault),
        job,
        generation,
        trainer,
    };
    let spawned = std::thread::Builder::new()
        .name(format!("drafter-training-{}", version.to_hex()))
        .spawn(move || run.dispatched(&admission, permit));
    if spawned.is_err() {
        // The permit went with the closure that never ran: dropped
        // unsettled, it settles as failed before any process started.
        waiters().remove(&version);
        vault.fail_drafter_training(&version, generation, DrafterTrainingFailure::Refused, None)?;
        // The recovery pass resumes the parked night at the next round.
    }
    Ok(())
}

fn settle_unsent(permit: RunPermit) {
    if let Err(denied) = permit.settle_unsent() {
        tracing::warn!(%denied, "a drafter training's unsent permit did not settle");
    }
}

/// Why a job ended without a trained version, and what it measured.
#[derive(Debug, Default)]
struct Ending {
    failure: Option<DrafterTrainingFailure>,
    /// The receipt's BLAKE3 and the GPU seconds it reports, when one was read.
    receipt: Option<([u8; 32], Option<u64>)>,
    /// The units to settle: the receipt's GPU seconds, or the seconds the
    /// host saw the process run; `None` when no process ran.
    used: Option<u64>,
}

impl Ending {
    fn failed(failure: DrafterTrainingFailure) -> Self {
        Self {
            failure: Some(failure),
            ..Self::default()
        }
    }
}

/// A stop the watcher found: its reason, and the cancellation it fired.
struct Stop {
    cancel: WorkCancel,
    reason: Mutex<Option<DrafterTrainingFailure>>,
}

impl Stop {
    fn reason(&self) -> Option<DrafterTrainingFailure> {
        *self.reason.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fire(&self, reason: DrafterTrainingFailure) {
        *self.reason.lock().unwrap_or_else(PoisonError::into_inner) = Some(reason);
        self.cancel.cancel();
    }
}

/// One dispatched version's job, as its waiter thread runs it.
struct TrainingRun {
    vault: Arc<Vault>,
    job: DrafterTrainingJob,
    generation: u64,
    trainer: DrafterTrainerSettings,
}

impl TrainingRun {
    fn job_dir(&self) -> JobDir {
        JobDir::of(
            &self.trainer.jobs_root,
            &self.job.version,
            &self.job.spec_blake3,
        )
    }

    /// The waiter thread of a fresh dispatch: runs the job, records how it
    /// ended, settles the permit once and removes the job directory.
    fn dispatched(self, admission: &RunAdmission, permit: RunPermit) {
        let ending = match runtime() {
            Some(runtime) => runtime.block_on(self.execute(admission)),
            None => Ending::failed(DrafterTrainingFailure::Refused),
        };
        // Dispatched, the permit settles what the GPU ran: nothing when no
        // process started.
        let units = ending.used.unwrap_or(0);
        if let Err(denied) = permit.settle(CallOutcome::Used(units)) {
            tracing::warn!(%denied, "a drafter training's units did not settle");
        }
        self.finish(ending);
    }

    /// Records `ending` when it names a failure, removes the job directory,
    /// and lets the recovery pass resume the night.
    fn finish(&self, ending: Ending) {
        if let Some(failure) = ending.failure {
            match self.vault.fail_drafter_training(
                &self.job.version,
                self.generation,
                failure,
                ending.receipt,
            ) {
                Ok(_) => tracing::info!(?failure, "a drafter training ended untrained"),
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "a drafter training end was not recorded");
                }
            }
        }
        self.job_dir().remove();
        waiters().remove(&self.job.version);
    }

    /// The job, from its device grant to its sealed load set.
    async fn execute(&self, admission: &RunAdmission) -> Ending {
        let stop = Arc::new(Stop {
            cancel: WorkCancel::new(),
            reason: Mutex::new(None),
        });
        let watcher = tokio::spawn(watch(
            Arc::clone(&self.vault),
            self.job.version,
            self.generation,
            Arc::clone(&stop),
        ));
        let ending = self.run_job(admission, &stop).await;
        watcher.abort();
        ending
    }

    async fn run_job(&self, admission: &RunAdmission, stop: &Stop) -> Ending {
        let holder = format!("drafter-trainer:{}", self.job.version.to_hex());
        let mut slot = DrafterTrainingSlot::queue(
            &self.job.target,
            &holder,
            self.job.recipe.device_memory_mib,
            &stop.cancel,
        );
        let grant = match slot.acquire().await {
            Ok(grant) => grant,
            Err(halt) => {
                tracing::info!(?halt, device = ?slot.device(), "a drafter job lost its device");
                return Ending::failed(stop.reason().unwrap_or(DrafterTrainingFailure::Refused));
            }
        };
        if let Some(reason) = stop.reason() {
            return Ending::failed(reason);
        }
        let dir = self.job_dir();
        let staged = match dir.stage(
            &self.vault,
            &self.job,
            self.generation,
            admission.run(),
            &self.trainer,
        ) {
            Ok(staged) => staged,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a drafter training's job did not stage");
                return Ending::failed(DrafterTrainingFailure::Refused);
            }
        };
        let budget = Duration::from_secs(self.job.recipe.gpu_seconds);
        let started = Instant::now();
        let end = process::run_worker(&self.trainer, &dir, budget, &stop.cancel).await;
        let seconds = started.elapsed().as_secs().max(1);
        drop(grant);
        let end = match end {
            Ok(end) => end,
            Err(error) => {
                tracing::warn!(%error, "a drafter trainer did not start");
                return Ending::failed(DrafterTrainingFailure::Refused);
            }
        };
        match end {
            process::WorkerEnd::Exited(_) => {}
            process::WorkerEnd::Stopped => {
                return Ending {
                    used: Some(seconds),
                    ..Ending::failed(stop.reason().unwrap_or(DrafterTrainingFailure::Cancelled))
                };
            }
            process::WorkerEnd::OverBudget => {
                return Ending {
                    used: Some(seconds),
                    ..Ending::failed(DrafterTrainingFailure::OverBudget)
                };
            }
        }
        let mut ending = complete(&self.vault, &self.job, self.generation, &dir, &staged);
        ending.used = ending.used.or(Some(seconds));
        ending
    }
}

/// Fires `stop` once version `version` may no longer train at `generation`:
/// an erase, the off switch or another recipe.
async fn watch(vault: Arc<Vault>, version: EntityId, generation: u64, stop: Arc<Stop>) {
    loop {
        tokio::time::sleep(TRAINING_WATCH_INTERVAL).await;
        match vault.drafter_training_watch(&version, generation) {
            Ok(Some(reason)) => {
                stop.fire(reason);
                return;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a drafter training's watch did not read");
            }
        }
    }
}

fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
}

/// Reads the ended job's receipt and, when it verifies, seals and publishes
/// its load set. The units to settle are the receipt's GPU seconds.
fn complete(
    vault: &Vault,
    job: &DrafterTrainingJob,
    generation: u64,
    dir: &JobDir,
    staged: &job::Staged,
) -> Ending {
    let read = match dir.read_receipt(job, generation, staged) {
        Ok(read) => read,
        Err(error) => {
            tracing::warn!(%error, "a drafter trainer's receipt did not verify");
            return Ending::failed(DrafterTrainingFailure::ReceiptUnverified);
        }
    };
    let receipt = Some((read.receipt_blake3, read.gpu_seconds));
    let used = read.gpu_seconds;
    let Verified::Trained(files) = read.verified else {
        return Ending {
            receipt,
            used,
            ..Ending::failed(DrafterTrainingFailure::TrainerFailed)
        };
    };
    let gpu_seconds = read.gpu_seconds.unwrap_or_default();
    let moved = || {
        vault
            .drafter_training_watch(&job.version, generation)
            .ok()
            .flatten()
            .unwrap_or(DrafterTrainingFailure::SealFailed)
    };
    match vault.record_drafter_training_receipt(
        &job.version,
        generation,
        read.receipt_blake3,
        gpu_seconds,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Ending {
                receipt,
                used,
                ..Ending::failed(moved())
            };
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a drafter training's receipt was not recorded");
            return Ending {
                receipt,
                used,
                ..Ending::failed(DrafterTrainingFailure::SealFailed)
            };
        }
    }
    match job::seal_and_publish(vault, job, generation, dir, &files) {
        Ok(()) => {
            tracing::info!(version = %job.version.to_hex(), "a drafter version trained");
            Ending {
                receipt,
                used,
                failure: None,
            }
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a trained drafter did not seal or publish");
            Ending {
                receipt,
                used,
                ..Ending::failed(moved())
            }
        }
    }
}

/// The recovery pass, at the start of each Coach round: a version a
/// restart left training gets its job read again, never sent again; a night
/// parked on a job that ended is resumed; a job directory whose version no
/// longer trains is removed.
pub(super) fn recover(server: &SyncServer, now: u64) {
    if let Err(error) = recover_all(server, now) {
        tracing::warn!(kind = ?error.kind(), "the drafter recovery pass did not finish");
    }
}

fn recover_all(server: &SyncServer, now: u64) -> oneiron::Result<()> {
    let vault = server.vault();
    let store = DreamerRunnerStore::new(vault);
    let training = server.ai.model_runtime().training();
    let marks = vault.drafter_training_marks()?;
    let mut live = BTreeSet::new();
    for mark in &marks {
        if mark.state == DrafterVersionState::Training {
            live.insert(mark.version);
            if !waiters().contains(&mark.version) {
                recover_job(server, mark.version);
            }
            continue;
        }
        let Some(attempt) = mark.attempt else {
            continue;
        };
        if waiters().contains(&mark.version) {
            continue;
        }
        let parked = store
            .parked_attempt(attempt)?
            .is_some_and(|park| park.park_owner == DRAFTER_PARK_OWNER);
        if parked {
            store.resume_parked(attempt, DRAFTER_PARK_OWNER, now)?;
        }
    }
    let busy = waiters().clone();
    for trainer in training.drafters.values() {
        job::sweep(&trainer.jobs_root, |version| {
            live.contains(version) || busy.contains(version)
        });
    }
    Ok(())
}

/// Recovers one version a restart left training, on its own thread: its
/// job's receipt completes it, a worker still running is left to end (and
/// stopped when its version may no longer train), and a job with neither is
/// lost.
fn recover_job(server: &SyncServer, version: EntityId) {
    let vault = server.vault();
    let Ok(Some(job)) = vault.drafter_training_job(&version) else {
        return;
    };
    let Some(training) = job.training.clone() else {
        return;
    };
    let settings = server.ai.model_runtime().training();
    let Some(trainer) = settings.drafter_trainer_named(&training.connector).cloned() else {
        // The connector is no longer configured: the version waits for it.
        return;
    };
    let declaration = drafter_declaration(&job.recipe, &trainer.binding);
    let admission = declaration.ok().map(|declaration| {
        server
            .ai
            .declared_run(admission_ref(&version), declaration, None)
            .admission()
            .clone()
    });
    if !waiters().insert(version) {
        return;
    }
    let run = TrainingRun {
        vault: Arc::clone(vault),
        generation: job.generation,
        job,
        trainer,
    };
    let spawned = std::thread::Builder::new()
        .name(format!("drafter-recovery-{}", version.to_hex()))
        .spawn(move || run.recovered(admission.as_ref()));
    if spawned.is_err() {
        waiters().remove(&version);
    }
}

impl TrainingRun {
    /// The waiter thread of a recovered job.
    fn recovered(self, admission: Option<&RunAdmission>) {
        let dir = self.job_dir();
        let ending = match dir.state() {
            job::JobState::Running => {
                if let Ok(Some(reason)) = self
                    .vault
                    .drafter_training_watch(&self.job.version, self.generation)
                {
                    tracing::info!(?reason, "a recovered drafter trainer is stopped");
                    dir.stop_worker();
                }
                waiters().remove(&self.job.version);
                return;
            }
            job::JobState::Ended(staged) => {
                complete(&self.vault, &self.job, self.generation, &dir, &staged)
            }
            job::JobState::Missing => {
                let reason = self
                    .vault
                    .drafter_training_watch(&self.job.version, self.generation)
                    .ok()
                    .flatten()
                    .unwrap_or(DrafterTrainingFailure::Lost);
                Ending::failed(reason)
            }
        };
        // A first completion settles the units the job used, as the dispatch
        // does; its own permit is gone with the restart.
        if let (Some(units), Some(admission)) = (ending.used, admission) {
            let quoted = self.job.recipe.gpu_seconds;
            match admission
                .sourced(Some(self.job.sources.clone()))
                .admit_paid(&self.trainer.binding, quoted)
            {
                Ok(permit) => {
                    if let Err(denied) = permit.settle(CallOutcome::Used(units)) {
                        tracing::warn!(%denied, "recovered drafter units did not settle");
                    }
                }
                Err(denied) => {
                    tracing::warn!(%denied, "recovered drafter units were not admitted");
                }
            }
        }
        self.finish(ending);
    }
}
