//! An owner-authorized training run on the host (OF-577, OF-552). The
//! owner's yes on a prepared run queued one `coach.training_run` job; this
//! arm trains that run through the paid connector it pinned, then scores the
//! returned checkpoint, or records on the run why it cannot
//! (`Vault::hold_training_run`). Nothing here binds a model: the result
//! waits for the owner's separate swap choice.
//!
//! A train may take hours, so the arm hands the leased run to its own thread
//! with its own runtime and returns at once: the Coach's sequential round
//! never waits on a GPU. The durable `Running` state and its dispatched flag
//! record the one dispatch, and a lost waiter never sends the run again.
//!
//! The one trainer adapter is the question-head worker (FIX 7263,
//! `trainer`): a local process on this host, on a connector
//! `[models.training.connectors]` names. It trains a question run on its one
//! recipe and nothing else; a role run, another recipe or an unnamed
//! connector holds with `training.no_connector`, as with no connector at
//! all. A returned question head is scored locally on its held-out rows;
//! unsupported role recipes still hold with `training.no_evaluator`.
use std::sync::Arc;

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::llm::run_admission::{
    BudgetLine, CallOutcome, PaidConnector, RunAdmission, RunDeclaration,
};
use oneiron::training_pack::{
    HeldOutResult, TrainingConnector, TrainingEvalInput, TrainingRun, TrainingState,
};
use oneiron::{EntityId, Error, Vault};

use crate::server::SyncServer;

mod parity;
mod question_evaluation;
mod trainer;
mod wire;

use trainer::QuestionHeadTrainer;
pub(crate) use trainer::{TrainingInputCleanup, cleanup_training_job_inputs};

/// An authorized run waits: no trainer adapter serves its connector here.
const HOLD_NO_CONNECTOR: &str = "training.no_connector";
/// An authorized run waits: its pinned quote builds no run admission.
const HOLD_NO_ADMISSION: &str = "training.no_admission";
/// An authorized run waits: the dispatch refused it before sending (a
/// changed connector, declaration or custody rung).
const HOLD_REFUSED: &str = "training.refused";
/// A returned run waits: no evaluator serves its target and recipe here.
const HOLD_NO_EVALUATOR: &str = "training.no_evaluator";
/// A returned question head stops: its receipt did not reproduce on this
/// host's stack (FIX 7568), so it never serves.
const HOLD_PARITY_FAILED: &str = "training.parity_failed";

/// A seat evaluator: it scores the held-out bytes `open_training_held_out`
/// served against the returned checkpoint. It may retain run-bound verifier
/// logs; the caller alone records the evaluation and advances its state.
type TrainingEvaluator = Box<dyn Fn(&TrainingEvalInput) -> oneiron::Result<HeldOutResult>>;

/// Trains, recovers or scores the run one leased `coach.training_run`
/// attempt names. A run that moved on, or whose spec is not the one its
/// owner authorized, leaves nothing to do.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let Some(run) = server.vault().run_coach_training_run(admitted)? else {
        return Ok(());
    };
    if run.state == TrainingState::Authorized {
        train(server, &run, now)
    } else if run.state == TrainingState::Running {
        recover(server, &run)
    } else {
        evaluate(server, &run, now)
    }
}

/// The declaration the host admits a run under, from its pinned quote alone:
/// a declared run that may call only the run's own connector, on a budget
/// line of exactly the quantity the owner chose at the connector's unit
/// cost, in that unit, declaring no teachers. The owner's authorization pins
/// it, so the owner door and the dispatch build it here alike.
pub(crate) fn training_declaration(run: &TrainingRun) -> oneiron::Result<RunDeclaration> {
    let units = run
        .compute
        .unit_cost
        .checked_mul(run.compute.quantity)
        .ok_or_else(|| Error::InvalidConfig("the training quote overflows its budget".into()))?;
    Ok(RunDeclaration::declared(BudgetLine {
        limit_units: units,
        reserve_units: units,
        unit: run.compute.cost_unit.clone(),
    })
    .with_connector(run.compute.connector.clone()))
}

/// The paid connector named `name` that a trainer on this host dispatches
/// through: its route, payer, credential binding and quote, as
/// `[models.training.connectors.<name>]` configures it. There is no default
/// connector.
pub(crate) fn trainer_binding(server: &SyncServer, name: &str) -> Option<PaidConnector> {
    server
        .ai
        .model_runtime()
        .training()
        .connector(name)
        .map(|connector| connector.binding.clone())
}

/// The trainer for `run`, on the connector its compute pinned: the
/// question-head worker, for a question run on its recipe. Anything else
/// gets none before any dispatch, so a role run is never sent to it.
fn training_connector(
    server: &SyncServer,
    run: &TrainingRun,
) -> Option<Box<dyn TrainingConnector + Send + Sync>> {
    if !QuestionHeadTrainer::serves(&run.plan) {
        return None;
    }
    let connector = server
        .ai
        .model_runtime()
        .training()
        .connector(&run.compute.connector)?;
    Some(Box::new(QuestionHeadTrainer::new(
        Arc::clone(server.vault()),
        connector.clone(),
    )))
}

/// The local held-out evaluator for the question worker's recipe. Role
/// recipes remain unavailable until their own adapters are implemented.
fn training_evaluator(server: &SyncServer, run: &TrainingRun) -> Option<TrainingEvaluator> {
    if !QuestionHeadTrainer::serves(&run.plan) {
        return None;
    }
    let vault = Arc::clone(server.vault());
    let run = run.clone();
    Some(Box::new(move |input| {
        question_evaluation::evaluate(&vault, &run, input)
    }))
}

/// Hands an authorized run to its own thread, or holds it with the reason
/// this host cannot dispatch it.
fn train(server: &SyncServer, run: &TrainingRun, now: u64) -> oneiron::Result<()> {
    let vault = server.vault();
    let (Some(binding), Some(connector)) = (
        trainer_binding(server, &run.compute.connector),
        training_connector(server, run),
    ) else {
        let detail = format!("{}: no trainer adapter on this host", run.compute.connector);
        vault.hold_training_run(&run.id, HOLD_NO_CONNECTOR, &detail, now)?;
        return Ok(());
    };
    let declaration = match training_declaration(run) {
        Ok(declaration) => declaration,
        Err(error) => {
            let detail = format!("{:?}", error.kind());
            vault.hold_training_run(&run.id, HOLD_NO_ADMISSION, &detail, now)?;
            return Ok(());
        }
    };
    let admission = server
        .ai
        .declared_run(run.admission_ref(), declaration, None)
        .admission()
        .clone();
    let vault = Arc::clone(vault);
    let id = run.id;
    crate::engine_thread(format!("training-run-{}", id.to_hex()))
        .spawn(move || dispatch(&vault, &id, &admission, &binding, connector.as_ref()))
        .map_err(|_| Error::InvalidConfig("the training run's thread did not start".into()))?;
    Ok(())
}

/// The thread one dispatched run waits on. A refusal before dispatch leaves
/// the run authorized, so the owner reads why on it; once dispatched, the
/// run's own durable state is the record.
fn dispatch(
    vault: &Vault,
    id: &EntityId,
    admission: &RunAdmission,
    binding: &PaidConnector,
    connector: &dyn TrainingConnector,
) {
    let outcome = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime
            .block_on(vault.execute_authorized_training_pack(id, admission, binding, connector)),
        Err(_) => Err(Error::InvalidConfig(
            "the training run's runtime did not start".into(),
        )),
    };
    let Err(error) = outcome else {
        return;
    };
    // By kind only: an engine error can quote the vault.
    tracing::warn!(kind = ?error.kind(), run = %id.to_hex(), "a training run did not complete");
    let refused = vault
        .training_run(id)
        .ok()
        .flatten()
        .is_some_and(|run| run.state == TrainingState::Authorized);
    if refused {
        let detail = format!("{:?}", error.kind());
        if let Err(error) =
            vault.hold_training_run(id, HOLD_REFUSED, &detail, vault.now_recorded_at())
        {
            tracing::warn!(kind = ?error.kind(), "a refused training run kept no hold");
        }
    }
}

/// Recovers a Running run whose waiter was lost: polls its trainer for a
/// terminal receipt and completes it, or leaves it Running. A missing
/// trainer, binding or admission stays Running without a new hold (a Running
/// run does not await the host); a still-outstanding job polls None and is a
/// no-op. `ConnectorFailed` stays terminal. A first completion settles the
/// run's paid reservation as used, as the dispatch does; a run that already
/// holds its result needs no new settlement.
fn recover(server: &SyncServer, run: &TrainingRun) -> oneiron::Result<()> {
    let Some(binding) = trainer_binding(server, &run.compute.connector) else {
        return Ok(());
    };
    let Some(connector) = training_connector(server, run) else {
        return Ok(());
    };
    let Ok(declaration) = training_declaration(run) else {
        return Ok(());
    };
    let admission = server
        .ai
        .declared_run(run.admission_ref(), declaration, None)
        .admission()
        .clone();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return Err(Error::InvalidConfig(
                "the training run's runtime did not start".into(),
            ));
        }
    };
    let output = runtime.block_on(connector.poll(&run.id, &run.spec_blake3))?;
    match output {
        Some(output) => {
            // A result recorded since this recovery started was settled by
            // its own waiter; only a first completion settles here.
            let fresh = server
                .vault()
                .training_run(&run.id)?
                .ok_or_else(|| Error::InvalidConfig("training run not found".into()))?;
            if fresh.result.is_some() {
                server.vault().complete_training_pack(&admission, output)?;
                return Ok(());
            }
            let service_units = output.service_units;
            let permit = admission
                .sourced(fresh.source_rows.clone())
                .admit_paid(&binding, fresh.compute.quantity)
                .map_err(|e| Error::InvalidConfig(e.to_string()))?;
            match server.vault().complete_training_pack(&admission, output) {
                Ok((_, true)) => {
                    // Keep completed work even when the meter reports a
                    // settlement error, as the dispatch does.
                    permit
                        .settle(CallOutcome::Used(service_units))
                        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
                    Ok(())
                }
                Ok((_, false)) => {
                    // The live waiter completed and settled first: this
                    // permit settles Kept, charging nothing, so the one
                    // GPU job is never charged twice.
                    permit
                        .settle(CallOutcome::Kept)
                        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
                    Ok(())
                }
                Err(error) => {
                    drop(permit);
                    Err(error)
                }
            }
        }
        None => Ok(()),
    }
}

/// Scores a returned run through the held-out door, or holds it until this
/// host has an evaluator for its seat. The evaluator sees only what
/// `open_training_held_out` serves, and its result goes through
/// `record_training_evaluation`. A question head whose receipt did not
/// reproduce on this host (FIX 7568) holds as parity-failed first.
fn evaluate(server: &SyncServer, run: &TrainingRun, now: u64) -> oneiron::Result<()> {
    let vault = server.vault();
    let parity = run
        .result
        .as_ref()
        .and_then(|result| result.checks.candle_parity.as_ref());
    if let Some(parity) = parity.filter(|parity| !parity.passed()) {
        let detail = format!(
            "{} probe(s) did not reproduce on this host: {}",
            parity.token_mismatches.len(),
            parity.token_mismatches.join(", ")
        );
        vault.hold_training_run(&run.id, HOLD_PARITY_FAILED, &detail, now)?;
        return Ok(());
    }
    let Some(evaluator) = training_evaluator(server, run) else {
        vault.hold_training_run(
            &run.id,
            HOLD_NO_EVALUATOR,
            "no seat evaluator or trained-weight loader on this host",
            now,
        )?;
        return Ok(());
    };
    let input = vault.open_training_held_out(&run.id)?;
    vault.record_training_evaluation(&run.id, &evaluator(&input)?)?;
    Ok(())
}
