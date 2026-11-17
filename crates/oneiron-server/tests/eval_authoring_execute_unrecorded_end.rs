//! `vault.evals.authoring.execute` when the writes that end the execution
//! record fail (FIX EVAL-AUTHORING-EXECUTE-UNRECORDED-END): a requested
//! attempt's lease is completed or failed only after its record is terminal.
//! When the record's end writes fail and the queue's settle write would
//! succeed, the served call and the nightly Coach round return the error
//! without settling or releasing the reservation, so the lease lapses and
//! the next admission recovers the record (`Applying` ends `Failed`,
//! `Running` runs); the wake executor parks the attempt for a later pass
//! instead of failing it.
//!
//! The record-write fault is armed through the
//! `eval_authoring_execution_fault` test door: the apply's end write and
//! `finish`'s `Failed` write fail for the served call, the recovery write
//! fails for the round and the wake executor.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! eval_authoring_execute_unrecorded_end`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/eval_authoring_fixture.rs"]
mod eval_authoring_fixture;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use engine_stack::run_on_engine_stack;
use eval_authoring_fixture::{COACH_HOST, Fixture, VERB, assert_budget_settled, echo_plan};
use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases};
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use oneiron::memory::Memory;
use oneiron::skill_optimize::{
    EvalAuthoringAdmission, EvalAuthoringExecuteRequest, admit_eval_authoring_execution,
};
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::eval_authoring_execution_fault::fail_execution_writes;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const LAPSE_SECS: u64 = 100;
const LEASE_TIMEOUT_SECS: u64 = 10;

/// The execution-record write fault is process-global: each test holds this
/// lock for its whole body, so no two faulted runs overlap. A test that
/// fails while holding it poisons the lock; the next test takes it anyway,
/// so each test still fails on its own assertion.
static FAULT_LOCK: Mutex<()> = Mutex::new(());

fn hold_fault_lock() -> std::sync::MutexGuard<'static, ()> {
    FAULT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs()
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault.memory(owner, EdgeActorClass::Human)
}

/// The owner's request admitted on the engine side at `start`, as a host
/// that then stops leaves it: the attempt stays leased and the record
/// `Running`. Returns the attempt.
fn leave_requested_pass(fixture: &Fixture, start: u64) -> EntityId {
    let admission = admit_eval_authoring_execution(
        &owner_memory(&fixture.vault),
        EvalAuthoringExecuteRequest {},
        AdmitDreamerAttempt {
            lease_owner: COACH_HOST.to_owned(),
            now: start,
            budget_id: COACH_HOST.to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        },
    )
    .expect("the owner's request");
    let EvalAuthoringAdmission::Admitted { attempt, .. } = admission else {
        panic!("the first request runs its own pass: {admission:?}");
    };
    EntityId::from_bytes(*attempt.status.attempt.id.as_bytes()).expect("attempt id")
}

/// The host stopped: the manual clock moves on and the queue takes the
/// lapsed lease back.
fn lapse_the_lease(fixture: &Fixture, clock: &ManualClock, now: u64) {
    clock.set(now);
    let report = AttemptQueue::new(&fixture.vault)
        .cleanup_leases(CleanupAttemptLeases {
            now,
            lease_timeout_secs: LEASE_TIMEOUT_SECS,
        })
        .expect("the queue takes lapsed leases back");
    assert_eq!(report.stale_requeued, 1, "the pass's lease lapsed");
}

/// One Coach host round, as the nightly worker runs it, and what it
/// returned: a failed job settles and does not fail the round, except a
/// requested pass whose record stayed open.
async fn coach_round_outcome(fixture: &Fixture) -> oneiron::Result<()> {
    let server = Arc::clone(&fixture.server);
    tokio::task::spawn_blocking(move || {
        oneiron_server::test_doors::coach_round::coach_host_round(&server)
    })
    .await
    .expect("the round thread")
}

async fn fixture_at(start: u64) -> (Fixture, Arc<ManualClock>) {
    let clock = ManualClock::new(start);
    let fixture = Fixture::new(Some(Arc::clone(&clock)), vec![], Some(echo_plan())).await;
    (fixture, clock)
}

#[test]
fn execute_with_failing_record_ends_leaves_the_lease_unsettled() {
    run_on_engine_stack("execute-unrecorded-end", || async {
        let _serial = hold_fault_lock();
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start);
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        // The apply's end write and `finish`'s `Failed` write fail; the
        // queue's settle write would succeed.
        fail_execution_writes(2);
        let (status, body) = fixture.as_owner(VERB, json!({})).await;
        fail_execution_writes(0);
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "faulted execute: {body}"
        );
        assert_eq!(fixture.eval_authoring_calls(), 1, "the pass ran once");

        // The record stands `Applying` and the lease stays unsettled, for
        // the lapse and the next admission to recover.
        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Leased", "{result}");
        assert_eq!(result["terminal"], false, "{result}");
        assert_eq!(result["execution"]["outcome"], "applying", "{result}");

        // The lease lapses and the next admission recovers the record:
        // `Applying` ends `Failed`, and the attempt fails with it.
        lapse_the_lease(&fixture, &clock, start + 2 * LAPSE_SECS);
        coach_round_outcome(&fixture)
            .await
            .expect("the recovery round");
        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Failed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert_eq!(result["execution"]["outcome"], "failed", "{result}");
        assert_eq!(fixture.eval_authoring_calls(), 1, "no second pass ran");
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn round_with_failing_recovery_leaves_the_lease_unsettled() {
    run_on_engine_stack("round-unrecorded-recover", || async {
        let _serial = hold_fault_lock();
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start);
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        // The recovery write fails; the round's settle write would succeed.
        fail_execution_writes(1);
        let outcome = coach_round_outcome(&fixture).await;
        fail_execution_writes(0);
        assert!(outcome.is_err(), "the round returns the recovery error");
        assert_eq!(fixture.eval_authoring_calls(), 0, "no pass ran");

        // The record stands `Running` and the lease stays unsettled, for
        // the lapse and the next admission to run.
        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Leased", "{result}");
        assert_eq!(result["terminal"], false, "{result}");
        assert_eq!(result["execution"]["outcome"], "running", "{result}");

        // The lease lapses and the next admission runs the pass on the
        // first request's record.
        lapse_the_lease(&fixture, &clock, start + 2 * LAPSE_SECS);
        coach_round_outcome(&fixture)
            .await
            .expect("the recovery round");
        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert_eq!(result["execution"]["outcome"], "applied", "{result}");
        assert_eq!(
            result["execution"]["requested_at"], start,
            "the first request's record: {result}"
        );
        assert_eq!(fixture.eval_authoring_calls(), 1, "the pass ran once");
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn wake_executor_with_failing_recovery_parks_for_a_later_pass() {
    run_on_engine_stack("wake-unrecorded-park", || async {
        let _serial = hold_fault_lock();
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start);
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        // Admitted as the wake pass admits it, then run through the Coach
        // wake executor while the recovery write fails.
        let admitted = match DreamerRunnerStore::new(&fixture.vault)
            .admit_next_coach_host_job(AdmitDreamerAttempt {
                lease_owner: COACH_HOST.to_owned(),
                now: fixture.vault.now_recorded_at(),
                budget_id: COACH_HOST.to_owned(),
                budget_total_units: 1 << 20,
                reserve_units: 1,
                started_milestone: None,
            })
            .expect("admit the lapsed job")
        {
            DreamerAdmissionOutcome::Admitted(admitted) => *admitted,
            other => panic!("the lapsed job admits: {other:?}"),
        };
        assert_eq!(
            EntityId::from_bytes(*admitted.status.attempt.id.as_bytes()).expect("attempt id"),
            attempt,
            "the requested job admitted"
        );
        fail_execution_writes(1);
        let executed = oneiron_server::test_doors::coach_wake::coach_wake_execute(
            &fixture.server,
            &admitted,
            fixture.vault.now_recorded_at(),
        )
        .await
        .expect("the wake executor answers");
        fail_execution_writes(0);
        match executed {
            oneiron::DreamerAttemptExecution::Park { cause, .. } => assert_eq!(
                cause,
                oneiron::dreamer_runner::DreamerParkCause::Retry,
                "a later pass resumes it"
            ),
            other => panic!("an open record parks for a later pass, not {other:?}"),
        }
        assert_eq!(fixture.eval_authoring_calls(), 0, "no pass ran");

        // Nothing settled: the attempt stays leased over its `Running`
        // record.
        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Leased", "{result}");
        assert_eq!(result["terminal"], false, "{result}");
        assert_eq!(result["execution"]["outcome"], "running", "{result}");
        fixture.finish().await;
    });
}
