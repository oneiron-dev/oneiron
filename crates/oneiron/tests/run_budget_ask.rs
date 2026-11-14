//! A run held at its spend cap asks its owner (ARCH-0026 depletion ladder,
//! policy knob; ARCH-0036 #offers-ask-home; Engine rulings RUNBUDGET-SCOPE = B
//! and RUNBUDGET-OVERDRAFT = C, 13 Nov 17:30):
//! - the budget hold queues one ask to the owner role through the ladder's
//!   human decision queue; a replayed hold, or another attempt of the run held
//!   while the run is still held, asks nothing new;
//! - with no answer, and on `stay_parked`, the run stays held;
//! - an owner's `overdraft` resumes the run in the answer's write, and the
//!   run's next hold asks again;
//! - a resume at the hold's own door withdraws the open ask.
//!
//! These tests read only doors main already has (the hold, the decision ask
//! list and the owner's answer), so they run red on main:
//! `cargo test --locked -p oneiron --all-features --test run_budget_ask`.

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{KIND, WORKER, claim, claimed, enqueued, open, read, unix_now};
use oneiron::Vault;
use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldLease, BudgetHoldState};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptResumePoint, EnqueueAttempt, PauseKind, RunState,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::{DecisionAnswer, DecisionAsk};
use oneiron::store::GateDecisionId;

/// The queue identity of run-budget asks.
const RUN_BUDGET_QUEUE: &str = "models.run_budget_questions";

/// The vault's embedded owner, and his proof.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof")
}

/// The open run-budget asks, oldest first.
fn open_asks(vault: &Vault) -> Vec<DecisionAsk> {
    vault
        .decision_asks(None, 10_000, true)
        .expect("the decision asks")
        .into_iter()
        .filter(|ask| ask.queue_pin.model == RUN_BUDGET_QUEUE)
        .collect()
}

/// `count` rows of one run, each claimed by the worker.
fn leased_run(queue: &AttemptQueue<'_>, run: &str, count: usize, now: u64) -> Vec<AttemptRecord> {
    for index in 0..count {
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
    (0..count)
        .map(|_| claimed(claim(queue, KIND, now + 1)))
        .collect()
}

/// The worker parks `leased` at the cap of the run rooted at `root`.
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

fn choice(token: &str) -> DecisionAnswer {
    DecisionAnswer::Choice(token.to_owned())
}

/// Canon: with no overdraft configured "the ladder asks up through
/// decide()". A run held at its cap queues one owner ask, offering to keep it
/// parked or approve an overdraft; holding it again, and holding its other
/// attempt while it is still held, asks nothing new.
#[test]
fn a_run_held_at_its_cap_queues_one_owner_ask() {
    let (_dir, vault) = open();
    owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let run = leased_run(&queue, "run-ask-once", 2, now);
    let (root, other) = (&run[0], &run[1]);

    hold(&dispatcher, root, root, now + 2);
    let asks = open_asks(&vault);
    assert_eq!(asks.len(), 1, "the held run asks its owner once: {asks:?}");
    let ask = &asks[0];
    let options = match &ask.question.contract {
        oneiron::llm::decision::AnswerContract::Choice { options } => options.clone(),
        contract => panic!("a choice of what the run does, got {contract:?}"),
    };
    assert_eq!(options, vec!["stay_parked", "overdraft"]);
    assert_eq!(
        ask.correlation.map(|run| *run.as_bytes()),
        Some(*root.id.as_bytes()),
        "the ask names the run's root"
    );

    hold(&dispatcher, root, root, now + 3);
    hold(&dispatcher, root, other, now + 4);
    let again = open_asks(&vault);
    assert_eq!(
        again.iter().map(|ask| ask.seq).collect::<Vec<_>>(),
        vec![ask.seq],
        "a replay, or another attempt held while the run is held, is the same ask"
    );
}

/// Canon: "Silent automatic downgrade is forbidden". With no answer the run
/// stays held; the owner's `stay_parked` closes the ask and the run stays
/// held, its attempt paused at the cap.
#[test]
fn an_unanswered_or_stay_parked_run_stays_held() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let run = leased_run(&queue, "run-stays-held", 1, now);
    let root = &run[0];
    hold(&dispatcher, root, root, now + 2);

    let asks = open_asks(&vault);
    assert_eq!(asks.len(), 1, "the held run asks its owner: {asks:?}");
    let held = |at: &str| {
        let plan = dispatcher
            .plan_hold(root.id)
            .expect("plan hold")
            .expect("the run's hold");
        assert_eq!(
            plan.state,
            BudgetHoldState::Held,
            "{at}: the run stays held"
        );
        assert_eq!(
            RunState::of(&read(&queue, root.id)),
            RunState::Paused(PauseKind::Budget),
            "{at}: its attempt stays paused at the cap"
        );
    };
    held("with no answer");

    vault
        .answer_decision_ask(&proof, asks[0].seq, choice("stay_parked"))
        .expect("the owner keeps the run parked");
    held("after stay_parked");
    assert!(
        open_asks(&vault).is_empty(),
        "the answered ask leaves the queue"
    );
}

/// Ruling RUNBUDGET-OVERDRAFT = C: the owner's `overdraft` resumes the run in
/// the answer's write. The run's next hold spends the overdraft and asks the
/// owner again.
#[test]
fn an_owner_overdraft_resumes_the_run_and_its_next_hold_asks_again() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let run = leased_run(&queue, "run-overdraft", 1, now);
    let root = &run[0];
    hold(&dispatcher, root, root, now + 2);
    let first = open_asks(&vault);
    assert_eq!(first.len(), 1, "the held run asks its owner: {first:?}");

    vault
        .answer_decision_ask(&proof, first[0].seq, choice("overdraft"))
        .expect("the owner approves an overdraft");
    let plan = dispatcher
        .plan_hold(root.id)
        .expect("plan hold")
        .expect("the run's hold");
    assert_eq!(
        plan.state,
        BudgetHoldState::Resumed,
        "the overdraft resumes the run"
    );
    assert_ne!(
        RunState::of(&read(&queue, root.id)),
        RunState::Paused(PauseKind::Budget),
        "its attempt leaves the cap"
    );

    let again = claimed(claim(&queue, KIND, now + 3));
    assert_eq!(again.id, root.id, "the same work is queued again");
    hold(&dispatcher, root, &again, now + 4);
    let second = open_asks(&vault);
    assert_eq!(second.len(), 1, "the run held again asks again: {second:?}");
    assert_ne!(second[0].seq, first[0].seq, "a new ask");
}

/// A resume at the hold's own door withdraws the run's open ask: a resumed
/// run waits on no answer.
#[test]
fn a_resume_at_the_hold_door_withdraws_the_open_ask() {
    let (_dir, vault) = open();
    owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let run = leased_run(&queue, "run-resumed", 1, now);
    let root = &run[0];
    hold(&dispatcher, root, root, now + 2);
    let asks = open_asks(&vault);
    assert_eq!(asks.len(), 1, "the held run asks its owner: {asks:?}");

    dispatcher
        .resume_budget_hold(root.id, "operator", now + 3)
        .expect("the hold resumes");
    assert!(open_asks(&vault).is_empty(), "the ask is withdrawn");
    let withdrawn = vault
        .decision_ask(asks[0].seq)
        .expect("ask read")
        .expect("the ask stays on record");
    assert!(withdrawn.withdrawn_at.is_some(), "withdrawn, not answered");
    assert!(withdrawn.answer.is_none());
}
