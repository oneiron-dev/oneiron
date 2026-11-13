//! The role-training run doors (ROLE-TRAINING-RUN, LEARN-TRAIN Q1 and Q3).
//!
//! `vault.coach.training_runs.prepare` is the owner's own prepare of a role
//! run with no Train offer. Its host door resolves the trainer connector the
//! host names and calls [`Vault::prepare_training_pack`], which exports the
//! consented corpus and pins the spec. Nothing runs until the owner
//! authorizes that exact spec. The draft carries the owner's own statements
//! (the consent ticks and the compute choice), so only the owner prepares
//! (ruling TRAIN-PREPARE-PRINCIPAL).
//!
//! `vault.coach.training_runs.get` reads where a run stands, for the owner or
//! an agent whose own live Grant lists the verb, checked in the snapshot it
//! reads. It may wait a bounded time for the run to move, and it answers
//! Running, Outstanding or Done. The bound ends only the caller's wait: it
//! never stops, fails or re-dispatches the run.
//!
//! `vault.coach.training_runs.execute` (LEARN-TRAIN Q4) has the host take
//! its next step for a run the owner already authorized, for the owner or an
//! agent whose own live Grant lists the verb: it dispatches an authorized
//! run to its trainer, recovers a running one and scores a returned one,
//! then drives the run for a bounded time and answers as the read does. The
//! authorization stays the owner's act; execute never authorizes, and the
//! run's writer admits one dispatch whoever asks. This module holds its
//! input and its admission; its host door holds the steps.
//!
//! [`Vault::prepare_training_pack`]: crate::Vault::prepare_training_pack

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::edit_distance::reservoir::ReservoirScope;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
    MemoryResult,
};
use crate::training_pack::{
    ArtifactPin, SplitSide, TrainingHold, TrainingPackDraft, TrainingRun, TrainingRunCaller,
    TrainingState,
};

/// The owner's role prepare: the row's own name.
pub const TRAINING_RUN_PREPARE_VERB: &str = "vault.coach.training_runs.prepare";

/// The run read: the row's own name, and the verb a Grant lists for it.
pub const TRAINING_RUN_GET_VERB: &str = "vault.coach.training_runs.get";

/// The run executor: the row's own name, and the verb a Grant lists for it.
pub const TRAINING_RUN_EXECUTE_VERB: &str = "vault.coach.training_runs.execute";

/// The longest one read or execute waits for its run to move, in
/// milliseconds.
pub const TRAINING_RUN_WAIT_MAX_MS: u64 = 30_000;

/// How often a waiting read looks at its run again.
const TRAINING_RUN_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// `vault.coach.training_runs.prepare`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleTrainingPrepareRequest {
    /// The owner's role plan, sealed held-out cohort, compute choice,
    /// quantity and consent ticks for this run.
    pub draft: TrainingPackDraft,
    /// The consented reservoir's filters the corpus is exported under.
    #[serde(default)]
    pub scope: RoleTrainingScope,
    /// The trainer connector's name on this host; there is no default.
    pub connector: String,
}

/// The reservoir filters of a role run's export. Both are optional; both
/// narrow.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleTrainingScope {
    #[serde(default)]
    pub task_classes: Option<Vec<String>>,
    #[serde(default)]
    pub since: Option<u64>,
}

impl RoleTrainingScope {
    /// The exporter's scope.
    pub fn reservoir_scope(self) -> ReservoirScope {
        ReservoirScope {
            task_classes: self.task_classes,
            since: self.since,
        }
    }
}

/// A prepared role run: what the owner authorizes, and the split the
/// exporter wrote.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleTrainingPrepared {
    pub run: EntityId,
    /// The run's `spec_blake3`, as 64 hex: what the owner authorizes.
    pub spec: String,
    pub state: TrainingState,
    /// The training split: the bytes a trainer receives, readable with
    /// `vault.artifacts.export`.
    pub training: ArtifactPin,
    /// The held-out split. It never goes to a trainer.
    pub held_out: ArtifactPin,
    pub training_rows: u64,
    pub held_out_rows: u64,
    /// Pairs whose exact content sits on both sides of the split.
    pub exact_hash_overlaps: u64,
}

impl RoleTrainingPrepared {
    /// The prepare answer for `run`.
    pub fn of(run: &TrainingRun) -> Self {
        let rows_on = |side: SplitSide| {
            run.corpus
                .rows
                .iter()
                .filter(|row| row.side == side)
                .count() as u64
        };
        Self {
            run: run.id,
            spec: spec_hex(run),
            state: run.state,
            training: run.corpus.training.clone(),
            held_out: run.corpus.held_out.clone(),
            training_rows: rows_on(SplitSide::Training),
            held_out_rows: rows_on(SplitSide::HeldOut),
            exact_hash_overlaps: run.corpus.exact_hash_overlaps,
        }
    }
}

/// `vault.coach.training_runs.get`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrainingRunGetRequest {
    pub run: EntityId,
    /// How long to wait for the run to move, in milliseconds, at most
    /// [`TRAINING_RUN_WAIT_MAX_MS`]. Zero, the default, reads once.
    #[serde(default)]
    pub wait_ms: u64,
}

/// `vault.coach.training_runs.execute`'s input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingRunExecuteRequest {
    pub run: EntityId,
    /// How long to drive the run on this host, in milliseconds, at most
    /// [`TRAINING_RUN_WAIT_MAX_MS`]. Zero, the default, takes one step and
    /// reads once.
    #[serde(default)]
    pub wait_ms: u64,
}

/// Where a run stands for its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TrainingRunProgress {
    /// The run moves with no one's act: queued for the host, training, or
    /// waiting for its held-out evaluation.
    Running { phase: TrainingRunPhase },
    /// The run cannot move until someone acts: the owner's authorization of
    /// the spec, or what the host's hold names.
    Outstanding { needs: TrainingRunNeed },
    /// The run ended: scored, failed at its connector, or bound.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrainingRunPhase {
    Queued,
    Training,
    Evaluating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrainingRunNeed {
    /// The owner authorizes the prepared spec.
    OwnerAuthorization,
    /// The host cannot advance the run; the hold says why.
    Host,
}

/// A run's held-out summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingRunEvaluation {
    pub cases: u64,
    pub metrics: BTreeMap<String, f64>,
    pub passed: bool,
}

/// `vault.coach.training_runs.get`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingRunObservation {
    pub run: EntityId,
    /// The run's `spec_blake3`, as 64 hex.
    pub spec: String,
    pub state: TrainingState,
    pub progress: TrainingRunProgress,
    /// Why the host cannot advance the run. It reads only while the run waits
    /// on the host.
    pub hold: Option<TrainingHold>,
    pub evaluation: Option<TrainingRunEvaluation>,
    /// The training split, readable with `vault.artifacts.export`. The
    /// held-out split is not named here: reading it counts exposure.
    pub training: ArtifactPin,
    /// How long this read waited, in milliseconds.
    pub waited_ms: u64,
}

/// `vault.coach.training_runs.get`: the run as it stands, after waiting up to
/// `wait_ms` for its state, hold or evaluation to change. A run that ended
/// answers at once. `None` for a run this vault does not hold.
///
/// # Errors
///
/// BAD_REQUEST for a wait above [`TRAINING_RUN_WAIT_MAX_MS`]; FORBIDDEN for
/// a caller that is neither the vault owner nor an agent with a live owner
/// Grant listing the verb, checked in each snapshot it reads; storage errors.
pub fn training_run_get(
    memory: &Memory<'_>,
    input: TrainingRunGetRequest,
) -> MemoryResult<Option<TrainingRunObservation>> {
    if input.wait_ms > TRAINING_RUN_WAIT_MAX_MS {
        return Err(MemoryError::bad_request(format!(
            "a training run read waits at most {TRAINING_RUN_WAIT_MAX_MS} ms"
        )));
    }
    let bound = Duration::from_millis(input.wait_ms);
    let started = Instant::now();
    let read = |run: &EntityId| read_admitted(memory, run, TRAINING_RUN_GET_VERB);
    let Some(first) = read(&input.run)? else {
        return Ok(None);
    };
    let mut run = first.clone();
    while training_run_progress(&run) != TrainingRunProgress::Done && !moved(&first, &run) {
        let Some(left) = bound
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
        else {
            break;
        };
        std::thread::sleep(left.min(TRAINING_RUN_POLL_INTERVAL));
        match read(&input.run)? {
            Some(next) => run = next,
            // An erase removed the run while the read waited.
            None => return Ok(None),
        }
    }
    let waited_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(Some(training_run_observation(run, waited_ms)))
}

/// `vault.coach.training_runs.execute`'s admission and its run: the caller
/// is the vault owner or an agent one live Grant from a live owner names and
/// lists [`TRAINING_RUN_EXECUTE_VERB`] for, the run exists, and its owner
/// authorized it. All are read in one snapshot.
///
/// # Errors
///
/// BAD_REQUEST for a wait above [`TRAINING_RUN_WAIT_MAX_MS`]; FORBIDDEN for
/// a caller the verb does not admit; NOT_FOUND for a run this vault does
/// not hold; INVALID_STATE for a run its owner has not authorized; storage
/// errors.
pub fn training_run_to_execute(
    memory: &Memory<'_>,
    input: &TrainingRunExecuteRequest,
) -> MemoryResult<TrainingRun> {
    if input.wait_ms > TRAINING_RUN_WAIT_MAX_MS {
        return Err(MemoryError::bad_request(format!(
            "a training run execute waits at most {TRAINING_RUN_WAIT_MAX_MS} ms"
        )));
    }
    let run = training_run_read_for_execute(memory, &input.run)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "this vault holds no such training run",
            &["Prepare the run with vault.coach.training_runs.prepare first."],
        )
    })?;
    if run.state == TrainingState::Prepared {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "{TRAINING_RUN_EXECUTE_VERB} runs only a run its owner authorized; this one waits for that authorization"
            ),
            &["The owner authorizes the prepared spec first; execute never authorizes."],
        ));
    }
    Ok(run)
}

/// The run as `vault.coach.training_runs.execute` reads it while it drives
/// the run, admitting its caller again in each snapshot. `None` once an
/// erase removed it.
///
/// # Errors
///
/// FORBIDDEN for a caller the verb does not admit; storage errors.
pub fn training_run_read_for_execute(
    memory: &Memory<'_>,
    run: &EntityId,
) -> MemoryResult<Option<TrainingRun>> {
    read_admitted(memory, run, TRAINING_RUN_EXECUTE_VERB)
}

/// The early authority check of `vault.coach.training_runs.execute`: its
/// caller's admission in a read snapshot, before the row's verb hooks fire.
/// The execute reads check it again.
///
/// # Errors
///
/// FORBIDDEN for a caller the verb does not admit; storage errors.
pub fn training_run_execute_admits(memory: &Memory<'_>) -> MemoryResult<()> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    admit_caller_in_txn(memory, &txn, TRAINING_RUN_EXECUTE_VERB)
}

/// Whether the run moved between two reads: its state, hold or evaluation.
fn moved(first: &TrainingRun, now: &TrainingRun) -> bool {
    first.state != now.state
        || first.hold != now.hold
        || first.evaluation.is_some() != now.evaluation.is_some()
}

/// The run's progress, from its state and hold.
pub fn training_run_progress(run: &TrainingRun) -> TrainingRunProgress {
    use TrainingRunProgress::{Done, Outstanding, Running};
    match run.state {
        TrainingState::Prepared => Outstanding {
            needs: TrainingRunNeed::OwnerAuthorization,
        },
        TrainingState::Authorized | TrainingState::Returned if run.hold.is_some() => Outstanding {
            needs: TrainingRunNeed::Host,
        },
        TrainingState::Authorized => Running {
            phase: TrainingRunPhase::Queued,
        },
        TrainingState::Running => Running {
            phase: TrainingRunPhase::Training,
        },
        TrainingState::Returned if run.evaluation.is_none() => Running {
            phase: TrainingRunPhase::Evaluating,
        },
        TrainingState::Returned
        | TrainingState::ConnectorFailed
        | TrainingState::Scored
        | TrainingState::Bound => Done,
    }
}

/// What a read or an execute answers for `run`, after waiting `waited_ms`.
pub fn training_run_observation(run: TrainingRun, waited_ms: u64) -> TrainingRunObservation {
    let waits = run.awaits_host();
    TrainingRunObservation {
        run: run.id,
        spec: spec_hex(&run),
        state: run.state,
        progress: training_run_progress(&run),
        hold: run.hold.filter(|_| waits),
        evaluation: run.evaluation.map(|evaluation| TrainingRunEvaluation {
            cases: evaluation.cases,
            metrics: evaluation.metrics,
            passed: evaluation.passed,
        }),
        training: run.corpus.training,
        waited_ms,
    }
}

fn spec_hex(run: &TrainingRun) -> String {
    blake3::Hash::from(run.spec_blake3).to_hex().to_string()
}

/// The run, read in one snapshot that first admits the caller for `verb`.
fn read_admitted(
    memory: &Memory<'_>,
    run: &EntityId,
    verb: &str,
) -> MemoryResult<Option<TrainingRun>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    admit_caller_in_txn(memory, &txn, verb)?;
    Ok(vault.training_run_in_txn(&txn, run)?)
}

/// The vault owner, or an agent one live Grant from a live owner names and
/// lists `verb` for, in `txn`: the rule each execute-started writer checks
/// again ([`TrainingRunCaller`]).
fn admit_caller_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, verb: &str) -> MemoryResult<()> {
    match training_run_caller(memory).refusal_in_txn(memory.vault(), txn, verb)? {
        None => Ok(()),
        Some(why) => Err(refused(verb, why)),
    }
}

/// The caller of `memory`, as an execute carries it to the writers it
/// starts.
pub fn training_run_caller(memory: &Memory<'_>) -> TrainingRunCaller {
    TrainingRunCaller::new(memory.actor(), memory.actor_class())
}

/// The refusal of a caller `verb` does not admit.
fn refused(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
