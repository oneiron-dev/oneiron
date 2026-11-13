//! A run held at its spend cap may continue on a free local chat model
//! (ARCH-0026 depletion ladder; Engine rulings RUNBUDGET-SCOPE = B and
//! RUNBUDGET-KNOB = A, 13 Nov 17:30). When the host names a free local model
//! at the hold, the owner's ask offers `continue_on_local`; that answer
//! resumes the run, and every attempt of it reads the local route until the
//! run is held again. The owner's `on_budget_exhausted` knob set to
//! `continue_on_local` is his standing answer: the hold resumes the run on the
//! named model in its own write and asks nothing; with no model named, he is
//! asked.
//!
//! The hold's local offer, the choice and the local-route read are new doors,
//! so this file builds only on the head:
//! `cargo test --locked -p oneiron --all-features --test run_budget_local`.

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{KIND, WORKER, claim, claimed, enqueued, open, unix_now};
use oneiron::agent_dispatch::{
    AgentDispatcher, BudgetHoldLease, BudgetHoldState, PartialResultHold, RunBudgetChoice,
    run_budget_questions,
};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptResumePoint, AttemptState, EnqueueAttempt,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::DecisionAnswer;
use oneiron::store::GateDecisionId;
use oneiron::{ModelId, Vault};
use rmpv::Value;

fn local_model() -> ModelId {
    ModelId::new("local/chat@v1").expect("model id")
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof")
}

/// Sets the stored default manifest's `on_budget_exhausted` knob to `knob`,
/// as the owner.
fn set_knob(vault: &Vault, proof: &AuthenticatedOwner, knob: Value) {
    let id = oneiron_store::policy_record::default_policy_manifest_id().expect("manifest id");
    let body = vault
        .get(&id)
        .expect("manifest read")
        .expect("the default policy manifest is stored");
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("manifest decodes")
    else {
        panic!("the default policy manifest is a map");
    };
    fields.retain(|(key, _)| key.as_str() != Some("on_budget_exhausted"));
    fields.push((Value::from("on_budget_exhausted"), knob));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields)).expect("manifest encodes");
    vault
        .install_owner_policy_manifest(proof, id, bytes, vault.now_recorded_at())
        .expect("the owner installs the manifest");
}

/// Two rows of one run, each claimed; the first is the run's root.
fn leased_run(queue: &AttemptQueue<'_>, run: &str, now: u64) -> (AttemptRecord, AttemptRecord) {
    for index in 0..2 {
        enqueued(
            queue
                .enqueue(EnqueueAttempt {
                    kind: KIND.to_owned(),
                    payload: format!("{run}-step-{index}").into_bytes(),
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

/// Holds `leased` of the run rooted at `root` at its spend cap, the host
/// naming `local` as the free local chat model it serves now.
fn hold(
    dispatcher: &AgentDispatcher<'_>,
    root: &AttemptRecord,
    leased: &AttemptRecord,
    now: u64,
    local: Option<&ModelId>,
) -> PartialResultHold {
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
            local,
        )
        .expect("the budget hold is admitted")
}

/// The ask of a run held while the host names a free local model offers
/// `continue_on_local` and names the model; the ask of a run held with none
/// named offers only `stay_parked` and `overdraft`. Nothing is chosen before
/// the owner answers.
#[test]
fn a_held_run_with_a_free_local_model_is_offered_to_continue_on_it() {
    let (_dir, vault) = open();
    let _proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let model = local_model();
    let (local_root, local_other) = leased_run(&queue, "run-local", now);
    hold(&dispatcher, &local_root, &local_root, now + 2, Some(&model));
    let (paid_root, _) = leased_run(&queue, "run-paid", now);
    hold(&dispatcher, &paid_root, &paid_root, now + 2, None);

    let listed = run_budget_questions(&vault).expect("status list");
    assert_eq!(listed.len(), 2, "each held run is asked once: {listed:?}");
    let offered: Vec<_> = listed
        .iter()
        .filter(|question| question.choices.contains(&RunBudgetChoice::ContinueOnLocal))
        .collect();
    assert_eq!(
        offered.len(),
        1,
        "only the run with a local model: {listed:?}"
    );
    assert_eq!(
        offered[0].choices,
        vec![
            RunBudgetChoice::StayParked,
            RunBudgetChoice::Overdraft,
            RunBudgetChoice::ContinueOnLocal,
        ]
    );
    assert_eq!(offered[0].local_model, Some(model));
    let other = listed
        .iter()
        .find(|question| question.seq != offered[0].seq)
        .expect("the other run's ask");
    assert_eq!(
        other.choices,
        vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft]
    );
    assert_eq!(other.local_model, None);
    for attempt in [local_root.id, local_other.id, paid_root.id] {
        assert_eq!(
            dispatcher
                .run_local_route(attempt)
                .expect("local route read"),
            None,
            "nothing is chosen before the answer"
        );
    }
}

/// The owner's `continue_on_local` press resumes the run: every attempt of it
/// reads the local route, no overdraft is approved, and the ask leaves the
/// status. The run's next hold spends the route and asks again.
#[test]
fn the_owners_continue_on_local_press_resumes_the_run_on_that_model_until_the_next_hold() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let model = local_model();
    let (root, other) = leased_run(&queue, "run-press-local", now);
    hold(&dispatcher, &root, &root, now + 2, Some(&model));
    let seq = run_budget_questions(&vault).expect("status list")[0].seq;

    vault
        .press_run_budget_ask(&proof, seq, RunBudgetChoice::ContinueOnLocal, None)
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
                .run_local_route(attempt)
                .expect("local route read"),
            Some(model.clone()),
            "every attempt of the run runs on the local model"
        );
    }
    assert_eq!(
        dispatcher
            .run_overdraft_units(root.id)
            .expect("overdraft read"),
        None,
        "continuing on the local model approves no overdraft"
    );
    assert!(
        run_budget_questions(&vault)
            .expect("status list")
            .is_empty(),
        "the answered ask leaves the status"
    );
    let ask = vault.decision_ask(seq).expect("ask read").expect("the ask");
    assert_eq!(
        ask.answer.map(|answer| answer.answer),
        Some(DecisionAnswer::Choice("continue_on_local".to_owned()))
    );

    let again = claimed(claim(&queue, KIND, now + 3));
    hold(&dispatcher, &root, &again, now + 4, None);
    assert_eq!(
        dispatcher
            .run_local_route(root.id)
            .expect("local route read"),
        None,
        "the next hold spends the local route"
    );
    let listed = run_budget_questions(&vault).expect("status list");
    assert_eq!(listed.len(), 1, "and asks again: {listed:?}");
    assert_eq!(
        listed[0].choices,
        vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft],
        "with no local model named now"
    );
}

/// The owner's `continue_on_local` knob is his standing answer: a hold that
/// names a free local model resumes the run on it in the hold's own write,
/// asks nothing and owes no notice. A later hold with no model named has
/// nothing to continue on, so the owner is asked.
#[test]
fn the_continue_on_local_knob_resumes_a_held_run_with_no_ask() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    set_knob(&vault, &proof, Value::from("continue_on_local"));
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let model = local_model();
    let (root, _other) = leased_run(&queue, "run-knob-local", now);

    let held = hold(&dispatcher, &root, &root, now + 2, Some(&model));
    assert_eq!(
        held.state,
        BudgetHoldState::Resumed,
        "the standing answer resumes the run in the hold's write"
    );
    assert_ne!(
        queue
            .get(root.id)
            .expect("row read")
            .expect("the root row")
            .state,
        AttemptState::Paused
    );
    assert_eq!(
        dispatcher
            .run_local_route(root.id)
            .expect("local route read"),
        Some(model)
    );
    assert!(
        run_budget_questions(&vault)
            .expect("status list")
            .is_empty(),
        "nothing is asked"
    );
    assert_eq!(
        dispatcher
            .deliver_budget_notice(root.id)
            .expect("notice read"),
        None,
        "a resumed run owes no held notice"
    );

    let again = claimed(claim(&queue, KIND, now + 3));
    assert_eq!(again.id, root.id, "the resumed root is claimed again");
    let held = hold(&dispatcher, &root, &again, now + 4, None);
    assert_eq!(held.state, BudgetHoldState::Held);
    assert_eq!(
        dispatcher
            .run_local_route(root.id)
            .expect("local route read"),
        None
    );
    let listed = run_budget_questions(&vault).expect("status list");
    assert_eq!(listed.len(), 1, "with no local model the owner is asked");
    assert_eq!(
        listed[0].choices,
        vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft]
    );
}
