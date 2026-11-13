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
//! [`Vault::prepare_training_pack`]: crate::Vault::prepare_training_pack

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::EdgeActorClass;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::edit_distance::reservoir::ReservoirScope;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::training_pack::{
    ArtifactPin, SplitSide, TrainingHold, TrainingPackDraft, TrainingRun, TrainingState,
};

/// The owner's role prepare: the row's own name.
pub const TRAINING_RUN_PREPARE_VERB: &str = "vault.coach.training_runs.prepare";

/// The run read: the row's own name, and the verb a Grant lists for it.
pub const TRAINING_RUN_GET_VERB: &str = "vault.coach.training_runs.get";

/// The longest one read waits for its run to move, in milliseconds.
pub const TRAINING_RUN_WAIT_MAX_MS: u64 = 30_000;

/// How often a waiting read looks at its run again.
const TRAINING_RUN_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// `vault.coach.training_runs.prepare`'s input.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingRunGetRequest {
    pub run: EntityId,
    /// How long to wait for the run to move, in milliseconds, at most
    /// [`TRAINING_RUN_WAIT_MAX_MS`]. Zero, the default, reads once.
    #[serde(default)]
    pub wait_ms: u64,
}

/// Where a run stands for its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingRunPhase {
    Queued,
    Training,
    Evaluating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingRunNeed {
    /// The owner authorizes the prepared spec.
    OwnerAuthorization,
    /// The host cannot advance the run; the hold says why.
    Host,
}

/// A run's held-out summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingRunEvaluation {
    pub cases: u64,
    pub metrics: BTreeMap<String, f64>,
    pub passed: bool,
}

/// `vault.coach.training_runs.get`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    let Some(first) = read_admitted(memory, &input.run)? else {
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
        match read_admitted(memory, &input.run)? {
            Some(next) => run = next,
            // An erase removed the run while the read waited.
            None => return Ok(None),
        }
    }
    let waited_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(Some(observation(run, waited_ms)))
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

fn observation(run: TrainingRun, waited_ms: u64) -> TrainingRunObservation {
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

/// The run, read in one snapshot that first admits the caller.
fn read_admitted(memory: &Memory<'_>, run: &EntityId) -> MemoryResult<Option<TrainingRun>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    admit_reader_in_txn(memory, &txn)?;
    Ok(vault.training_run_in_txn(&txn, run)?)
}

/// The vault owner, or an agent one live Grant from a live owner names and
/// lists [`TRAINING_RUN_GET_VERB`] for, in `txn`.
fn admit_reader_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    let vault = memory.vault();
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        return Ok(());
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        TRAINING_RUN_GET_VERB,
    )? {
        Ok(standing) if standing.grant.is_some() => Ok(()),
        Err(NoStanding::PactStandingLapsed) => Err(refused(PACT_STANDING_LAPSED)),
        Ok(_) | Err(NoStanding::NotStanding) => Err(refused(
            "no live Grant from a live owner names this agent and lists the verb",
        )),
    }
}

/// The read's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{TRAINING_RUN_GET_VERB} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
