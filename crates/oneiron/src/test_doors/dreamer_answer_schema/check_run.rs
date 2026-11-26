//! Running the night's check on a scripted house (HOUSE-SCHEMA-CHECK), for
//! `tests/dreamer_answer_schema_check.rs`: the night's children settle so the gate stands
//! open, the check is enqueued and run as a wake runs it, its calls go to the destination
//! the test names, and the replies its calls keep are counted.

use std::sync::Arc;

use super::{ReceiptView, receipt};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_consolidation::answer_schema::check;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
    DreamerAdmissionOutcome, DreamerAttemptStatus, DreamerClaimAuthoringAdmission,
    DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerRunnerStore, decode_dreamer_attempt_payload,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext, WakePassDeadline};
use crate::error::Result;
use crate::inference_context::{HostInferenceBinding, HostInferenceContext};
use crate::settings::ReadDestination;
use oneiron_model::llm::{BudgetGuard, LlmBackend, LlmRequest, ModelId, ModelLocality};

/// The test house's egress: every call stays in the test.
fn allow_house(_: &LlmRequest) -> bool {
    true
}

/// Runs the night's check on the scripted `backend` under `guard` as `model`: enqueues the
/// check when the night has none, runs it, and reads its receipt. Returns the receipt with
/// the run's outcome.
///
/// # Errors
///
/// No night; the enqueue; the run; no receipt; storage faults.
pub async fn run_check(
    vault: &Vault,
    night: AttemptId,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    model: ModelId,
    now: u64,
) -> Result<(ReceiptView, DreamerAttemptExecution)> {
    let on_device = ReadDestination::on_device();
    let outcome =
        run_with_lend(vault, night, Some((backend, guard, model)), on_device, now).await?;
    Ok((receipt(vault, night)?, outcome))
}

/// [`run_check`] with the house rung's calls going to `destination`: a capture whose rows or
/// world may not go there drops its pair.
///
/// # Errors
///
/// No night; the enqueue; the run; no receipt; storage faults.
pub async fn run_check_toward(
    vault: &Vault,
    night: AttemptId,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    model: ModelId,
    destination: ReadDestination,
    now: u64,
) -> Result<(ReceiptView, DreamerAttemptExecution)> {
    let outcome = run_with_lend(
        vault,
        night,
        Some((backend, guard, model)),
        destination,
        now,
    )
    .await?;
    Ok((receipt(vault, night)?, outcome))
}

/// [`run_check`]'s outcome alone, for a run that stops before its receipt lands.
///
/// # Errors
///
/// No night; the enqueue; the run; storage faults.
pub async fn run_check_outcome(
    vault: &Vault,
    night: AttemptId,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    model: ModelId,
    now: u64,
) -> Result<DreamerAttemptExecution> {
    let on_device = ReadDestination::on_device();
    run_with_lend(vault, night, Some((backend, guard, model)), on_device, now).await
}

/// How many of the night's check calls keep a reply in their step rows.
///
/// # Errors
///
/// The night has no check; storage faults.
pub fn check_replies_kept(vault: &Vault, night: AttemptId) -> Result<usize> {
    crate::llm::kept_step_responses_of(vault, check_of(vault, night)?)
}

/// Runs the night's check with no house lend: the night skips with its reason when it gets
/// that far.
///
/// # Errors
///
/// No night; the enqueue; the run; no receipt; storage faults.
pub async fn run_check_no_house(
    vault: &Vault,
    night: AttemptId,
    now: u64,
) -> Result<(ReceiptView, DreamerAttemptExecution)> {
    let outcome = run_with_lend(vault, night, None, ReadDestination::on_device(), now).await?;
    Ok((receipt(vault, night)?, outcome))
}

/// Runs the night's check with an optional scripted house whose calls go to `destination`.
async fn run_with_lend(
    vault: &Vault,
    night: AttemptId,
    lend: Option<(&dyn LlmBackend, &BudgetGuard, ModelId)>,
    destination: ReadDestination,
    now: u64,
) -> Result<DreamerAttemptExecution> {
    settle_children(vault, now)?;
    let check = plant_check(vault, night, now)?;
    let status = check_status(vault, check)?;
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
    let ctx = WakeAttemptContext {
        vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "test-answer-schema-check",
        now_ms: now * 1_000,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let house = lend.map(|(backend, guard, model)| check::AnswerSchemaHouse {
        backend,
        sourced: None,
        guard,
        model: model.clone(),
        inference: HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model,
                locality: ModelLocality::OwnServer,
                keyless: true,
            },
            extraction_egress: Some(&allow_house),
        },
        destination,
    });
    check::run_answer_schema_check(&status, &ctx, house).await
}

/// Admits and completes every admittable descendant, so the gate stands open: the door's
/// children are Micro-lane attempts, admitted without a home election.
///
/// # Errors
///
/// The admission or completion.
fn settle_children(vault: &Vault, now: u64) -> Result<()> {
    const WORKER: &str = "test-answer-schema-check";
    loop {
        let outcome = DreamerRunnerStore::new(vault).admit_next_consolidation(
            AdmitDreamerConsolidationAttempt {
                scope: DreamerConsolidationScope::Micro,
                local_node_id: 1,
                claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
                admission: AdmitDreamerAttempt {
                    lease_owner: WORKER.to_owned(),
                    now,
                    budget_id: WORKER.to_owned(),
                    budget_total_units: 100_000,
                    reserve_units: 100,
                    started_milestone: None,
                },
            },
        )?;
        let admitted = match outcome {
            DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
                admitted,
            )) => *admitted,
            _ => return Ok(()),
        };
        DreamerRunnerStore::new(vault).complete(CompleteDreamerAttempt {
            id: admitted.status.attempt.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: admitted.status.attempt.attempt_count,
            now,
        })?;
    }
}

/// Enqueues the night's check (or meets the one standing) and returns its attempt.
fn plant_check(vault: &Vault, night: AttemptId, now: u64) -> Result<AttemptId> {
    let night_status = check_status(vault, night)?;
    vault.with_write_txn_grouped(|txn| check::enqueue_in_txn(vault, txn, &night_status, now))?;
    check_of(vault, night)
}

/// The night's check attempt.
fn check_of(vault: &Vault, night: AttemptId) -> Result<AttemptId> {
    let txn = vault.store.env.read_txn()?;
    for child in DreamerRunnerStore::new(vault).child_attempts_in_txn(&txn, night)? {
        let Some(record) = AttemptQueue::new(vault).get_in_txn(&txn, child)? else {
            continue;
        };
        let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
            continue;
        };
        if payload.attempt_type == check::ATTEMPT {
            return Ok(child);
        }
    }
    Err(crate::error::Error::InvalidConfig(
        "the night enqueued no check".into(),
    ))
}

/// Reads an attempt's status: its queue row with its decoded payload.
fn check_status(vault: &Vault, id: AttemptId) -> Result<DreamerAttemptStatus> {
    let txn = vault.store.env.read_txn()?;
    let record = AttemptQueue::new(vault)
        .get_in_txn(&txn, id)?
        .ok_or_else(|| crate::error::Error::InvalidConfig("no such attempt".into()))?;
    let payload = decode_dreamer_attempt_payload(&record.payload).map_err(|_| {
        crate::error::Error::InvalidConfig("the attempt payload did not read".into())
    })?;
    Ok(DreamerAttemptStatus {
        attempt: record,
        payload,
    })
}
