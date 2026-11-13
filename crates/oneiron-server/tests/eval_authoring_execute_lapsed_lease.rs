//! `vault.evals.authoring.execute` on a requested attempt whose host stopped
//! before it settled the lease (FIX EVAL-AUTHORING-EXECUTE-SERVER-CASE, cases 4
//! and 5): a later served call that finds the pass ended settles the kept end
//! (completed, or failed for a `Failed` pass) and runs no model; the nightly
//! Coach round that leases such an attempt runs `finish` for a `Running`
//! record and no pass for an ended one.
//!
//! The requested attempt is built through the engine's own writers
//! (`admit_eval_authoring_execution`, `end_requested_eval_authoring`) and its
//! lease lapsed through the queue's `cleanup_leases` at a later manual clock.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! eval_authoring_execute_lapsed_lease`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/eval_authoring_fixture.rs"]
mod eval_authoring_fixture;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use engine_stack::run_on_engine_stack;
use eval_authoring_fixture::{COACH_HOST, Fixture, VERB, assert_budget_settled, echo_plan};
use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases};
use oneiron::dreamer_runner::AdmitDreamerAttempt;
use oneiron::memory::Memory;
use oneiron::skill_optimize::{
    EvalAuthoringAdmission, EvalAuthoringExecuteRequest, EvalAuthoringOutcome,
    admit_eval_authoring_execution,
};
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

const LAPSE_SECS: u64 = 100;
const LEASE_TIMEOUT_SECS: u64 = 10;

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
/// that then stops leaves it: the attempt stays leased, the record Running,
/// or ended by `end` when given. Returns the attempt.
fn leave_requested_pass(
    fixture: &Fixture,
    start: u64,
    end: Option<EvalAuthoringOutcome>,
) -> EntityId {
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
    if let Some(outcome) = end {
        fixture
            .vault
            .end_requested_eval_authoring(&attempt, outcome, None, None, start)
            .expect("the pass ends");
    }
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

/// One Coach host round, as the nightly worker runs it.
async fn coach_round(fixture: &Fixture) {
    let server = Arc::clone(&fixture.server);
    tokio::task::spawn_blocking(move || {
        oneiron_server::test_doors::coach_round::coach_host_round(&server)
    })
    .await
    .expect("the round thread")
    .expect("the Coach round");
}

async fn fixture_at(start: u64) -> (Fixture, Arc<ManualClock>) {
    let clock = ManualClock::new(start);
    let fixture = Fixture::new(Some(Arc::clone(&clock)), vec![], Some(echo_plan())).await;
    (fixture, clock)
}

/// The served owner call after the lapse: 200 and a `ran` answer.
async fn call_after_lapse(fixture: &Fixture) -> Value {
    let (status, answer) = fixture.as_owner(VERB, json!({})).await;
    assert_eq!(status, StatusCode::OK, "owner execute: {answer}");
    assert_eq!(answer["state"], "ran", "{answer}");
    answer
}

#[test]
fn ended_pass_leased_again_settles_completed_and_runs_no_model() {
    run_on_engine_stack("execute-ended-completed", || async {
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start, Some(EvalAuthoringOutcome::NoWork));
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        let answer = call_after_lapse(&fixture).await;
        let execution = &answer["execution"];
        assert_eq!(execution["attempt"], attempt.to_hex().as_str(), "{answer}");
        assert_eq!(execution["outcome"], "no_work", "{answer}");
        assert_eq!(execution["requested_at"], start, "{answer}");
        assert_eq!(
            execution["ended_at"], start,
            "the kept end stands: {answer}"
        );
        assert_eq!(fixture.model.seen().len(), 0, "no model call");

        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert!(result["last_error"].is_null(), "{result}");
        assert_eq!(result["execution"], *execution, "{result}");
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn failed_pass_leased_again_settles_failed_and_runs_no_model() {
    run_on_engine_stack("execute-ended-failed", || async {
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start, Some(EvalAuthoringOutcome::Failed));
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        let answer = call_after_lapse(&fixture).await;
        assert_eq!(answer["execution"]["outcome"], "failed", "{answer}");
        assert_eq!(fixture.model.seen().len(), 0, "no model call");

        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Failed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert!(
            result["last_error"]
                .as_str()
                .is_some_and(|text| text.contains("coach.eval_authoring failed")),
            "{result}"
        );
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn second_call_while_the_lease_is_live_waits_on_the_attempt() {
    run_on_engine_stack("execute-waiting", || async {
        let start = unix_now();
        let (fixture, _clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start, None);

        let (status, answer) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["state"], "waiting", "{answer}");
        assert_eq!(answer["attempt"], attempt.to_hex().as_str(), "{answer}");
        assert_eq!(fixture.model.seen().len(), 0, "no model call");
        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Leased", "{result}");
        assert_eq!(result["terminal"], false, "{result}");
        assert_eq!(result["execution"]["outcome"], "running", "{result}");
        fixture.finish().await;
    });
}

#[test]
fn nightly_round_finishes_a_running_requested_pass() {
    run_on_engine_stack("round-running", || async {
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start, None);
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        coach_round(&fixture).await;

        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert!(result["last_error"].is_null(), "{result}");
        let execution = &result["execution"];
        assert_eq!(execution["outcome"], "applied", "{result}");
        assert_eq!(
            execution["caller"]["kind"], "owner",
            "the first request's caller: {result}"
        );
        assert_eq!(execution["requested_at"], start, "{result}");
        assert_eq!(execution["ended_at"], start + LAPSE_SECS, "{result}");
        assert_eq!(
            fixture.eval_authoring_calls(),
            1,
            "finish ran the pass once"
        );
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn nightly_round_runs_no_pass_for_an_ended_requested_pass() {
    run_on_engine_stack("round-ended", || async {
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start, Some(EvalAuthoringOutcome::NoWork));
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        coach_round(&fixture).await;

        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["execution"]["outcome"], "no_work", "{result}");
        assert_eq!(result["execution"]["ended_at"], start, "{result}");
        assert_eq!(fixture.eval_authoring_calls(), 0, "no pass ran");
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn nightly_round_fails_the_attempt_of_a_failed_requested_pass() {
    run_on_engine_stack("round-failed", || async {
        let start = unix_now();
        let (fixture, clock) = fixture_at(start).await;
        let attempt = leave_requested_pass(&fixture, start, Some(EvalAuthoringOutcome::Failed));
        lapse_the_lease(&fixture, &clock, start + LAPSE_SECS);

        coach_round(&fixture).await;

        let result = fixture.result_of(&attempt.to_hex()).await;
        assert_eq!(result["state"], "Failed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert!(
            result["last_error"]
                .as_str()
                .is_some_and(|text| text.contains("coach.eval_authoring failed")),
            "{result}"
        );
        assert_eq!(fixture.eval_authoring_calls(), 0, "no pass ran");
        fixture.finish().await;
    });
}
