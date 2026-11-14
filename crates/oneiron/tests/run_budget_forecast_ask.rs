//! The advance check (owner ruling RUN-BUDGET-SPENT = B, "you can also check
//! it in advance"; Engine ruling RUNBUDGET-ADVANCE-FLOW = A). A root launch
//! whose expected spend is above what its hard root scope has left asks the
//! owner in the launch's own write, stating the projected spend and the
//! room; the run starts as before. The early ask offers `add_funds` (the
//! root's cap rises now, for good) and `stay_parked` (the run goes on and
//! holds at its cap as usual). The run's hold withdraws an early ask still
//! open, so a run has one open ask at a time. A launch within its room, or
//! on an unpriced unit, asks nothing.
//!
//! The early ask and its status fields are new, so this file builds only on
//! the head:
//! `cargo test --locked -p oneiron --all-features --test run_budget_forecast_ask`.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, BudgetHoldLease,
    DispatchAgent, LaunchUsdPrices, RunBudgetChoice, SpawnSpend, SpendScopeId, UsdPriceTarget,
    UsdUnitPrice, run_budget_questions,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint, ClaimAttempt, ClaimOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::DecisionAnswer;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`, clear of the pinned bytes a fresh vault
// already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).

const NOW: u64 = 1_700_000_000;
const LEASE_OWNER: &str = "forecast-fixture";
/// A root's cap well below an uncalibrated agent's expected spend (the
/// 8,000-token prior).
const SHORT_ROOT: u64 = 1_000;
/// $0.010001 at $3 per million tokens: 3,333,666.33 tokens, rounded down.
const AMOUNT_USD_MICROS: u64 = 10_001;
const BOUGHT_UNITS: u64 = 3_333_666;

/// The vault's USD quote here: $3 per million tokens.
struct TokenPrice;

impl LaunchUsdPrices for TokenPrice {
    fn quote(
        &self,
        _vault: &Vault,
        _txn: &heed::RoTxn<'_>,
        target: UsdPriceTarget<'_>,
        unit: &LeaseUnit,
    ) -> oneiron::Result<Option<UsdUnitPrice>> {
        let priced = matches!(
            target,
            UsdPriceTarget::HeldRun | UsdPriceTarget::Agent { .. }
        );
        Ok(
            (priced && *unit == LeaseUnit::tokens()).then_some(UsdUnitPrice {
                usd_micros: 3,
                per_units: 1_000,
            }),
        )
    }
}

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "run budget forecast fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    agent: EntityId,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A default-policy device vault, its embedded owner and one owner-created
/// Base agent; with `priced`, the vault's USD quote.
fn fixture(priced: bool) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    if priced {
        assert!(vault.install_launch_usd_prices(Arc::new(TokenPrice)));
    }
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let agent = EntityId::from_bytes([0x5C; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &agent,
        &definition("fixture.forecast"),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;
    Ok(Fixture {
        vault,
        owner,
        agent,
        _dir: dir,
    })
}

/// Opens a hard root of `units` tokens named `name`.
fn open_root(f: &Fixture, name: &str, units: u64) -> TestResult<SpendScopeId> {
    let root = SpendScopeId::launch(name)?;
    let opened = AgentDispatcher::new(&f.vault).open_root_spend_scope(
        root.clone(),
        DeclaredMaximum {
            units,
            unit: LeaseUnit::tokens(),
        },
        Some(MaximumShown { at_ms: 12_000 }),
        NOW,
    )?;
    assert!(opened.hard, "the root is a hard cap");
    Ok(root)
}

/// Launches the fixture's agent as a root run under `root`.
fn launch(f: &Fixture, root: &SpendScopeId) -> TestResult<AttemptId> {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&f.vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(f.agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now: NOW,
            },
            AgentSpawnContext {
                spend: Some(SpawnSpend {
                    scope: root.clone(),
                }),
                ..AgentSpawnContext::default()
            },
        )?
    else {
        panic!("the agent dispatches without running a model")
    };
    Ok(status.attempt.id)
}

fn cap_of(f: &Fixture, scope: &SpendScopeId) -> TestResult<u64> {
    Ok(AgentDispatcher::new(&f.vault)
        .read_spend_scope(scope)?
        .expect("the scope stays on record")
        .cap_units)
}

/// A root launch projected past its root's room asks the owner at launch:
/// `add_funds` or `stay_parked`, with the projected spend and the room. The
/// run is queued as before.
#[test]
fn a_root_launch_projected_past_its_root_asks_the_owner_early() -> TestResult {
    let f = fixture(true)?;
    let root = open_root(&f, "owen-forecast-root", SHORT_ROOT)?;
    let run = launch(&f, &root)?;

    assert!(
        AttemptQueue::new(&f.vault).get(run)?.is_some(),
        "the run starts as before"
    );
    let listed = run_budget_questions(&f.vault)?;
    assert_eq!(listed.len(), 1, "one early ask: {listed:?}");
    assert_eq!(
        listed[0].choices,
        vec![RunBudgetChoice::AddFunds, RunBudgetChoice::StayParked]
    );
    assert_eq!(listed[0].projected_units, Some(8_000), "the prior");
    assert_eq!(listed[0].available_units, Some(SHORT_ROOT));
    assert!(listed[0].add_funds_price.is_some(), "a dollar's price");
    let ask = f.vault.decision_ask(listed[0].seq)?.expect("the early ask");
    assert!(
        ask.question.text.contains("projected to need 8000 tokens"),
        "the ask states the projection: {}",
        ask.question.text
    );
    Ok(())
}

/// The owner's dollars on the early ask raise the root for good and are
/// recorded under the run; the answered ask leaves the status.
#[test]
fn the_owners_early_dollars_raise_the_root_for_good() -> TestResult {
    let f = fixture(true)?;
    let root = open_root(&f, "owen-forecast-funds", SHORT_ROOT)?;
    let run = launch(&f, &root)?;
    let seq = run_budget_questions(&f.vault)?[0].seq;

    f.vault
        .press_run_budget_add_funds(&f.owner, seq, AMOUNT_USD_MICROS)?;
    assert_eq!(
        cap_of(&f, &root)?,
        SHORT_ROOT + BOUGHT_UNITS,
        "the dollars buy whole units at the quote, rounded down"
    );
    let funds = AgentDispatcher::new(&f.vault).run_funds(run)?;
    assert_eq!(funds.len(), 1, "one amount on record: {funds:?}");
    assert_eq!(funds[0].usd_micros, AMOUNT_USD_MICROS);
    assert_eq!(funds[0].units, BOUGHT_UNITS);
    assert_eq!(
        f.vault
            .decision_ask(seq)?
            .and_then(|ask| ask.answer)
            .map(|answer| answer.answer),
        Some(DecisionAnswer::Choice("add_funds".to_owned()))
    );
    assert!(run_budget_questions(&f.vault)?.is_empty());
    Ok(())
}

/// The run's hold withdraws the early ask still open: one open ask per run.
#[test]
fn the_runs_hold_takes_the_early_asks_place() -> TestResult {
    let f = fixture(true)?;
    let root = open_root(&f, "owen-forecast-hold", SHORT_ROOT)?;
    let run = launch(&f, &root)?;
    let seq = run_budget_questions(&f.vault)?[0].seq;

    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&f.vault).claim(ClaimAttempt {
        lease_owner: LEASE_OWNER.to_owned(),
        now: NOW + 1,
    })?
    else {
        panic!("the run is ready to lease")
    };
    assert_eq!(leased.id, run);
    hold(&f, &leased, NOW + 2)?;

    let early = f.vault.decision_ask(seq)?.expect("the early ask");
    assert!(
        early.withdrawn_at.is_some(),
        "the hold withdraws the early ask"
    );
    assert!(
        run_budget_questions(&f.vault)?
            .iter()
            .all(|question| question.projected_units.is_none()),
        "no early ask stays open beside the hold"
    );
    Ok(())
}

fn hold(f: &Fixture, leased: &AttemptRecord, now: u64) -> TestResult {
    AgentDispatcher::new(&f.vault).hold_for_budget(
        leased.id,
        BudgetHoldLease {
            attempt: leased.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: leased.attempt_count,
            resume_point: AttemptResumePoint::new("workflow-step:before-model-call", now),
        },
        None,
        "spend cap",
        now,
        None,
    )?;
    Ok(())
}

/// A launch within its root's room asks nothing (a guard: it holds on the
/// base too).
#[test]
fn a_launch_within_its_room_asks_nothing() -> TestResult {
    let f = fixture(true)?;
    let root = open_root(&f, "owen-forecast-roomy", 100_000)?;
    launch(&f, &root)?;
    assert!(run_budget_questions(&f.vault)?.is_empty());
    Ok(())
}

/// With no USD price for the root's unit nothing is asked: the launch
/// statement alone states the shortfall, as before (a guard).
#[test]
fn an_unpriced_short_launch_asks_nothing() -> TestResult {
    let f = fixture(false)?;
    let root = open_root(&f, "owen-forecast-unpriced", SHORT_ROOT)?;
    launch(&f, &root)?;
    assert!(run_budget_questions(&f.vault)?.is_empty());
    Ok(())
}
