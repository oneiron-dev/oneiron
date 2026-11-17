//! The owner adds dollars to a run held at its spend cap (owner ruling
//! RUN-BUDGET-SPENT = B, 15 Nov 2026: "you can dedicate more money"). When
//! the vault's USD quote prices the unit of the run's open root scope, the
//! run-budget ask offers `add_funds`. The owner's press names the dollars;
//! they buy whole units at the quote, rounded down, so never more than he
//! named; the root scope's cap rises by them for good (no later hold takes
//! the raise back, unlike an overdraft), the amount is recorded, and the run
//! resumes. Each of the run's meters also takes the bought units once, as it
//! takes an overdraft's cap, until the next hold (Engine ruling
//! RUNBUDGET-ADDFUNDS-METER = A, 16 Nov 2026): a step whose own line is spent
//! goes on under them. An unpriced unit is never offered the choice.
//!
//! The press, the funds read and the price on the status are new doors, so
//! this file builds only on the head:
//! `cargo test --locked -p oneiron --all-features --test run_budget_add_funds`.

#[path = "run_hold/fixture.rs"]
mod fixture;

use std::sync::Arc;

use fixture::{KIND, WORKER, claim, claimed, enqueued, open, unix_now};
use oneiron::Vault;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, BudgetHoldLease,
    BudgetHoldState, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, FundsPrice, LaunchUsdPrices,
    RunBudgetChoice, SpendScopeId, UsdPriceTarget, UsdUnitPrice, run_budget_questions,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint, ClaimOutcome, EnqueueAttempt,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::llm::decision::DecisionAnswer;
use oneiron::llm::run_admission::LeaseUnit;
use oneiron::store::GateDecisionId;

/// The root scope's cap before any answer: the run's launch budget.
const ROOT_CAP: u64 = 20_000;
/// $0.010001 at $3 per million tokens: 3,333,666.33 tokens, rounded down.
const AMOUNT_USD_MICROS: u64 = 10_001;
const BOUGHT_UNITS: u64 = 3_333_666;

/// The vault's USD quote here: $3 per million tokens, for a held run only.
struct HeldRunTokenPrice;

impl LaunchUsdPrices for HeldRunTokenPrice {
    fn quote(
        &self,
        _vault: &Vault,
        _txn: &heed::RoTxn<'_>,
        target: UsdPriceTarget<'_>,
        unit: &LeaseUnit,
    ) -> oneiron::Result<Option<UsdUnitPrice>> {
        Ok(
            (matches!(target, UsdPriceTarget::HeldRun) && *unit == LeaseUnit::tokens()).then_some(
                UsdUnitPrice {
                    usd_micros: 3,
                    per_units: 1_000,
                },
            ),
        )
    }
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof")
}

/// A run of two claimed rows. Its root is the seeded default agent,
/// dispatched into `run` with a budget of [`ROOT_CAP`] tokens and no parent
/// scope, so its launch pins the root's own hard scope, the run's root
/// scope; the other row is a plain step of the same run.
fn leased_run(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    run: &str,
    now: u64,
) -> (AttemptRecord, AttemptRecord) {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("seeded agent read")
        .expect("the default agent is seeded");
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now,
            },
            AgentSpawnContext::default()
                .with_depth_remaining(1)
                .with_budget(ROOT_CAP),
        )
        .expect("the run's root dispatches")
    else {
        panic!("one fresh agent run");
    };
    enqueued(
        queue
            .enqueue(EnqueueAttempt {
                kind: KIND.to_owned(),
                payload: b"step-1".to_vec(),
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now,
            })
            .expect("enqueue"),
    );
    let root = claim_root(queue, status.attempt.id, now + 1);
    let other = claimed(claim(queue, KIND, now + 1));
    (root, other)
}

/// Claims the run's root agent row `id` as the worker.
fn claim_root(queue: &AttemptQueue<'_>, id: AttemptId, now: u64) -> AttemptRecord {
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = claim(queue, DREAMER_RUNNER_ATTEMPT_KIND, now) else {
            break;
        };
        if row.id == id {
            return row;
        }
    }
    panic!("the run's root is ready to claim");
}

/// The run's root scope: the hard scope of [`ROOT_CAP`] tokens its root's
/// launch pinned, carved from no parent.
fn run_root_scope(dispatcher: &AgentDispatcher<'_>, root: &AttemptRecord) -> SpendScopeId {
    let scope = SpendScopeId::for_attempt(&root.id);
    let read = dispatcher
        .read_spend_scope(&scope)
        .expect("scope read")
        .expect("the root's launch pins its scope");
    assert!(read.hard, "the root scope is a hard cap");
    assert_eq!(read.parent, None, "carved from no parent");
    assert_eq!(read.cap_units, ROOT_CAP, "the launch budget");
    scope
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

fn cap_of(dispatcher: &AgentDispatcher<'_>, scope: &SpendScopeId) -> u64 {
    dispatcher
        .read_spend_scope(scope)
        .expect("scope read")
        .expect("the scope stays on record")
        .cap_units
}

/// A priced run's ask offers `add_funds` at the quote. The owner's dollars
/// buy whole units, rounded down; the root cap rises by them, the amount is
/// recorded, and the run resumes. The next hold asks again and keeps the
/// raise.
#[test]
fn the_owners_dollars_raise_a_held_runs_root_cap_for_good() {
    let (_dir, vault) = open();
    assert!(vault.install_launch_usd_prices(Arc::new(HeldRunTokenPrice)));
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let (root, other) = leased_run(&vault, &queue, "run-add-funds", now);
    let scope = run_root_scope(&dispatcher, &root);
    hold(&dispatcher, &root, &root, now + 2);

    let listed = run_budget_questions(&vault).expect("status list");
    assert_eq!(listed.len(), 1, "the status shows the open ask: {listed:?}");
    assert_eq!(
        listed[0].choices,
        vec![
            RunBudgetChoice::StayParked,
            RunBudgetChoice::Overdraft,
            RunBudgetChoice::AddFunds
        ]
    );
    assert_eq!(
        listed[0].add_funds_price,
        Some(FundsPrice {
            unit: LeaseUnit::tokens(),
            usd_micros: 3,
            per_units: 1_000,
        }),
        "the status states what a dollar buys"
    );

    vault
        .press_run_budget_add_funds(&proof, listed[0].seq, AMOUNT_USD_MICROS)
        .expect("the owner's press");
    assert_eq!(
        dispatcher
            .plan_hold(root.id)
            .expect("plan hold")
            .expect("the run's hold")
            .state,
        BudgetHoldState::Resumed
    );
    assert_eq!(
        cap_of(&dispatcher, &scope),
        ROOT_CAP + BOUGHT_UNITS,
        "the dollars buy whole units at the quote, rounded down"
    );
    for attempt in [root.id, other.id] {
        let funds = dispatcher.run_funds(attempt).expect("funds read");
        assert_eq!(funds.len(), 1, "one amount on record: {funds:?}");
        assert_eq!(funds[0].usd_micros, AMOUNT_USD_MICROS);
        assert_eq!(funds[0].units, BOUGHT_UNITS);
        assert_eq!(funds[0].ask, listed[0].seq);
    }
    let ask = vault
        .decision_ask(listed[0].seq)
        .expect("ask read")
        .expect("the ask");
    assert_eq!(
        ask.answer.map(|answer| answer.answer),
        Some(DecisionAnswer::Choice("add_funds".to_owned()))
    );

    let again = claim_root(&queue, root.id, now + 3);
    hold(&dispatcher, &root, &again, now + 4);
    assert_eq!(
        cap_of(&dispatcher, &scope),
        ROOT_CAP + BOUGHT_UNITS,
        "the next hold keeps the raise"
    );
    assert_eq!(
        dispatcher.run_funds(root.id).expect("funds read").len(),
        1,
        "and keeps its record"
    );
    assert_eq!(
        run_budget_questions(&vault).expect("status list").len(),
        1,
        "and asks again"
    );
}

/// The units the owner's dollars buy are also the held run's one-off grant:
/// each of its meters takes them once under the answer's arrival number, as
/// it takes an overdraft's cap, so a step whose own line is spent goes on
/// (Engine ruling RUNBUDGET-ADDFUNDS-METER = A). The next hold deletes the
/// grant and keeps the root scope's raise.
#[test]
fn the_owners_dollars_reach_the_held_runs_meters_once() {
    let (_dir, vault) = open();
    assert!(vault.install_launch_usd_prices(Arc::new(HeldRunTokenPrice)));
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let (root, other) = leased_run(&vault, &queue, "run-add-funds-meter", now);
    let scope = run_root_scope(&dispatcher, &root);
    hold(&dispatcher, &root, &root, now + 2);
    let seq = run_budget_questions(&vault).expect("status list")[0].seq;

    vault
        .press_run_budget_add_funds(&proof, seq, AMOUNT_USD_MICROS)
        .expect("the owner's press");
    for attempt in [root.id, other.id] {
        assert_eq!(
            dispatcher
                .run_overdraft(attempt)
                .expect("grant read")
                .map(|grant| (grant.cap_units, grant.ask)),
            Some((BOUGHT_UNITS, seq)),
            "each meter of the run takes the bought units once, under the answer's number"
        );
    }

    let again = claim_root(&queue, root.id, now + 3);
    hold(&dispatcher, &root, &again, now + 4);
    assert_eq!(
        dispatcher.run_overdraft(root.id).expect("grant read"),
        None,
        "the next hold spends the grant"
    );
    assert_eq!(
        cap_of(&dispatcher, &scope),
        ROOT_CAP + BOUGHT_UNITS,
        "and keeps the raise"
    );
}

/// With no USD price for the run's unit, the ask does not offer
/// `add_funds`, and a press of it is refused and raises nothing.
#[test]
fn an_unpriced_run_is_not_offered_add_funds() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let (root, _other) = leased_run(&vault, &queue, "run-unpriced", now);
    let scope = run_root_scope(&dispatcher, &root);
    hold(&dispatcher, &root, &root, now + 2);

    let listed = run_budget_questions(&vault).expect("status list");
    assert_eq!(
        listed[0].choices,
        vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft]
    );
    assert_eq!(listed[0].add_funds_price, None);
    assert!(
        vault
            .press_run_budget_add_funds(&proof, listed[0].seq, AMOUNT_USD_MICROS)
            .is_err(),
        "an ask that does not offer add_funds refuses it"
    );
    assert_eq!(cap_of(&dispatcher, &scope), ROOT_CAP, "nothing is raised");
    assert!(
        dispatcher
            .run_funds(root.id)
            .expect("funds read")
            .is_empty()
    );
}

/// `add_funds` names its dollars: the plain press (no amount) and a zero
/// amount are refused, and the ask stays open.
#[test]
fn add_funds_names_its_dollars() {
    let (_dir, vault) = open();
    assert!(vault.install_launch_usd_prices(Arc::new(HeldRunTokenPrice)));
    let proof = owner_proof(&vault);
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let (root, _other) = leased_run(&vault, &queue, "run-no-amount", now);
    let scope = run_root_scope(&dispatcher, &root);
    hold(&dispatcher, &root, &root, now + 2);
    let seq = run_budget_questions(&vault).expect("status list")[0].seq;

    assert!(
        vault
            .press_run_budget_ask(&proof, seq, RunBudgetChoice::AddFunds, None)
            .is_err(),
        "the plain press names no dollars"
    );
    assert!(
        vault.press_run_budget_add_funds(&proof, seq, 0).is_err(),
        "a zero amount buys nothing"
    );
    assert_eq!(cap_of(&dispatcher, &scope), ROOT_CAP, "nothing is raised");
    assert_eq!(
        run_budget_questions(&vault).expect("status list").len(),
        1,
        "the ask stays open"
    );
    assert_eq!(
        dispatcher
            .plan_hold(root.id)
            .expect("plan hold")
            .expect("the run's hold")
            .state,
        BudgetHoldState::Held
    );
}
