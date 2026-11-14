//! The owner's overdraft of a run held at its spend cap (Engine ruling
//! RUNBUDGET-OVERDRAFT = C, 13 Nov 17:30): the owner's press names the cap,
//! or takes the default the ask states (the units one more call reserves);
//! the run's meters then run with that cap until the run is held again. The
//! AI status lists the open asks.
//!
//! The press, the overdraft read and the status list are new doors, so this
//! file builds only on the head:
//! `cargo test --locked -p oneiron --all-features --test run_budget_overdraft`.

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{KIND, WORKER, claim, claimed, enqueued, open, unix_now};
use oneiron::Vault;
use oneiron::agent_dispatch::{
    AgentDispatcher, BudgetHoldLease, BudgetHoldState, RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS,
    RunBudgetChoice, run_budget_questions,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptResumePoint, EnqueueAttempt};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::DecisionAnswer;
use oneiron::store::GateDecisionId;

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof")
}

/// Two rows of one run, each claimed; the first is the run's root.
fn leased_run(queue: &AttemptQueue<'_>, run: &str, now: u64) -> (AttemptRecord, AttemptRecord) {
    for index in 0..2 {
        enqueued(
            queue
                .enqueue(EnqueueAttempt {
                    kind: KIND.to_owned(),
                    payload: format!("step-{index}").into_bytes(),
                    dedupe_key: None,
                    run_id: Some(run.to_owned()),
                    now,
                })
                .expect("enqueue"),
        );
    }
    let root = claimed(claim(queue, KIND, now + 1));
    let other = claimed(claim(queue, KIND, now + 1));
    (root, other)
}

fn hold(dispatcher: &AgentDispatcher<'_>, root: &AttemptRecord, leased: &AttemptRecord, now: u64) {
    dispatcher
        .hold_for_budget(
            root.id,
            BudgetHoldLease {
                attempt: leased.id,
                lease_owner: WORKER.to_owned(),
                attempt_count: leased.attempt_count,
                resume_point: AttemptResumePoint::new("workflow-step:before-model-call", now),
            },
            None,
            "spend cap",
            now,
            None,
        )
        .expect("the budget hold is admitted");
}

/// The status lists the held run's ask with both choices and the default
/// cap. The owner's press names a cap: the run resumes, every attempt of the
/// run reads that overdraft, and the ask leaves the status.
#[test]
fn the_owners_overdraft_press_names_the_runs_cap() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let (root, other) = leased_run(&queue, "run-press", now);
    hold(&dispatcher, &root, &root, now + 2);

    let listed = run_budget_questions(&vault).expect("status list");
    assert_eq!(listed.len(), 1, "the status shows the open ask: {listed:?}");
    assert_eq!(
        listed[0].choices,
        vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft]
    );
    assert_eq!(
        listed[0].default_overdraft_units,
        RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS
    );
    assert_eq!(
        dispatcher
            .run_overdraft_units(root.id)
            .expect("overdraft read"),
        None,
        "nothing is approved before the answer"
    );

    vault
        .press_run_budget_ask(
            &proof,
            listed[0].seq,
            RunBudgetChoice::Overdraft,
            Some(20_000),
        )
        .expect("the owner's press");
    assert_eq!(
        dispatcher
            .plan_hold(root.id)
            .expect("plan hold")
            .expect("the run's hold")
            .state,
        BudgetHoldState::Resumed
    );
    for attempt in [root.id, other.id] {
        assert_eq!(
            dispatcher
                .run_overdraft_units(attempt)
                .expect("overdraft read"),
            Some(20_000),
            "every attempt of the run runs on the owner's cap"
        );
    }
    assert!(
        run_budget_questions(&vault)
            .expect("status list")
            .is_empty(),
        "the answered ask leaves the status"
    );
    let ask = vault
        .decision_ask(listed[0].seq)
        .expect("ask read")
        .expect("the ask");
    assert_eq!(
        ask.answer.map(|answer| answer.answer),
        Some(DecisionAnswer::Choice("overdraft".to_owned()))
    );
}

/// An `overdraft` answered with no cap takes the default the ask states;
/// the run's next hold spends it and asks again.
#[test]
fn an_overdraft_without_a_cap_takes_the_stated_default_until_the_next_hold() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let (root, _other) = leased_run(&queue, "run-default", now);
    hold(&dispatcher, &root, &root, now + 2);
    let seq = run_budget_questions(&vault).expect("status list")[0].seq;

    vault
        .press_run_budget_ask(&proof, seq, RunBudgetChoice::Overdraft, None)
        .expect("the owner's press");
    assert_eq!(
        dispatcher
            .run_overdraft_units(root.id)
            .expect("overdraft read"),
        Some(RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS)
    );

    let again = claimed(claim(&queue, KIND, now + 3));
    hold(&dispatcher, &root, &again, now + 4);
    assert_eq!(
        dispatcher
            .run_overdraft_units(root.id)
            .expect("overdraft read"),
        None,
        "the next hold spends the overdraft"
    );
    assert_eq!(
        run_budget_questions(&vault).expect("status list").len(),
        1,
        "and asks again"
    );
}
