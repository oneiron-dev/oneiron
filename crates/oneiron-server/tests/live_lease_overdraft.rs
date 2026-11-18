//! ARCH-0026 depletion ladder, RUNBUDGET-OVERDRAFT = C and RUNBUDGET-KNOB = A
//! (13 Nov 17:30), review round 1 of #7913/#7914/#7916: an overdraft widens
//! a try's own line, never its spend scope's hard cap. A step's live lease
//! moves its meter's line to the scope's room at each look, and the meter's
//! overdraft (the owner's answer to a run-budget ask, or his
//! `on_budget_exhausted` knob) was added on top of that room, so the try paid
//! one more call past the cap at each look. And a step that resumes from its
//! tool cursor restores the meter it saved, so the overdraft the owner
//! approved for the run since never reached it.
//!
//! Review round 2 of #7913-#7916: a restored meter took an approval as
//! `Overdraft{cap}` in place of the overdraft it had, on the step's own line,
//! so a meter that had spent one overdraft (an earlier approval, or the
//! knob's) gained nothing from the next approval and the run held again.
//! Each approval now widens a meter by its cap past what it admitted or
//! spent, once per approval.
//!
//! Red on the head before each fix: the lease admits two calls on a scope
//! with room for one, the restored meter refuses the approved call, and a
//! second approval (or one on top of the knob) admits nothing. Green on the
//! head.
//!
//! Reaches the lease through `oneiron_server::test_doors::live_lease`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test live_lease_overdraft`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{AgentDispatcher, RunOverdraft, SpendScopeId};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::{BudgetExhaustionPolicy, Vault, VaultConfig};
use oneiron_server::test_doors::live_lease::{TryStretch, calls_a_lease_admits, calls_per_stretch};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// What one paid call reserves and spends: one call's reservation.
const CALL_UNITS: u64 = 8_000;
/// More calls than any line here has room for.
const BOUND: u64 = 5;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    Ok((dir, vault))
}

/// Opens a hard root of `units`, shown at its start.
fn open_root(
    dispatcher: &AgentDispatcher<'_>,
    name: &str,
    units: u64,
) -> Result<SpendScopeId, Box<dyn std::error::Error>> {
    let root = SpendScopeId::launch(name)?;
    let opened = dispatcher.open_root_spend_scope(
        root.clone(),
        DeclaredMaximum {
            units,
            unit: LeaseUnit::tokens(),
        },
        Some(MaximumShown { at_ms: 12_000 }),
        12,
    )?;
    assert!(opened.hard, "the root is a hard cap");
    Ok(root)
}

/// What `scope` has booked.
fn spent(
    dispatcher: &AgentDispatcher<'_>,
    scope: &SpendScopeId,
) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(dispatcher
        .read_spend_scope(scope)?
        .ok_or("the root scope is missing")?
        .spent_units)
}

/// The reviewers' case: a hard scope with room for one call, and a try
/// whose line is one call with an overdraft of one call on top. The try
/// pays the one call its scope has room for, and the next is refused.
#[test]
fn an_overdraft_never_pays_past_its_scopes_hard_cap() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-overdraft-capped-root", CALL_UNITS)?;

    let admitted = calls_a_lease_admits(
        &vault,
        &root,
        CALL_UNITS,
        CALL_UNITS,
        BudgetExhaustionPolicy::Overdraft { cap: CALL_UNITS },
        BOUND,
    )?;
    assert_eq!(admitted, 1, "the scope has room for one call only");
    assert_eq!(
        spent(&dispatcher, &root)?,
        CALL_UNITS,
        "the scope books no more than its cap"
    );
    Ok(())
}

/// The overdraft still widens the try's own line: under a scope with room,
/// a line of one call with an overdraft of one call pays two, and no third.
#[test]
fn an_overdraft_widens_the_tries_own_line_under_a_roomy_scope() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-overdraft-roomy-root", 1_000_000)?;

    let admitted = calls_a_lease_admits(
        &vault,
        &root,
        CALL_UNITS,
        CALL_UNITS,
        BudgetExhaustionPolicy::Overdraft { cap: CALL_UNITS },
        BOUND,
    )?;
    assert_eq!(admitted, 2, "the line's call and the overdraft's");
    assert_eq!(spent(&dispatcher, &root)?, 2 * CALL_UNITS);
    Ok(())
}

/// The owner's approval of `cap_units`, answering the run-budget ask `ask`.
fn approval(ask: u64, cap_units: u64) -> RunOverdraft {
    RunOverdraft {
        cap_units,
        ask,
        approved_at: 0,
    }
}

/// A stretch of the try, begun under `overdraft`, that calls until refused.
fn stretch(overdraft: Option<RunOverdraft>) -> TryStretch {
    TryStretch {
        overdraft,
        most_calls: BOUND,
    }
}

/// A step that spent its line whole and saved its tool cursor resumes on
/// the meter it saved. Once the owner approved an overdraft for the run, the
/// restored meter admits the next call; with none it stays spent.
#[test]
fn a_restored_meter_takes_the_overdraft_the_owner_approved_since() -> TestResult {
    let approved = calls_per_stretch(
        CALL_UNITS,
        BudgetExhaustionPolicy::Suspend,
        &[stretch(None), stretch(Some(approval(1, CALL_UNITS)))],
    )?;
    assert_eq!(
        approved,
        [1, 1],
        "the approved overdraft reaches the restored meter"
    );
    let none = calls_per_stretch(
        CALL_UNITS,
        BudgetExhaustionPolicy::Suspend,
        &[stretch(None), stretch(None)],
    )?;
    assert_eq!(
        none,
        [1, 0],
        "with no overdraft the restored meter stays spent"
    );
    Ok(())
}

/// The reviewers' case (round 2 of #7913, #7915, #7916): the step spends its
/// line, the owner approves one call, the step spends it and is held again,
/// and he approves one more call. The meter restored under the second
/// approval admits that call too.
#[test]
fn a_second_approval_takes_the_step_past_its_first_overdraft() -> TestResult {
    let admitted = calls_per_stretch(
        CALL_UNITS,
        BudgetExhaustionPolicy::Suspend,
        &[
            stretch(None),
            stretch(Some(approval(1, CALL_UNITS))),
            stretch(Some(approval(2, CALL_UNITS))),
        ],
    )?;
    assert_eq!(
        admitted,
        [1, 1, 1],
        "each approval admits the call it approved"
    );
    Ok(())
}

/// The reviewers' case (round 2 of #7914): the owner's knob gives the meter
/// an overdraft of one call, and the step spends its line and the knob's
/// call. His approval of one more call adds to the knob's, never takes its
/// place.
#[test]
fn an_approval_adds_to_the_overdraft_of_the_owners_knob() -> TestResult {
    let admitted = calls_per_stretch(
        CALL_UNITS,
        BudgetExhaustionPolicy::Overdraft { cap: CALL_UNITS },
        &[stretch(None), stretch(Some(approval(1, CALL_UNITS)))],
    )?;
    assert_eq!(
        admitted,
        [2, 1],
        "the line's call and the knob's, then the approved one"
    );
    Ok(())
}

/// Guard: one approval widens a meter once, however often the step saves
/// and restores it. An approval of two calls on a fresh meter, spent one
/// call per stretch across saves, admits two calls past the line in all.
#[test]
fn an_approval_widens_a_meter_once_across_its_saves() -> TestResult {
    let twice = approval(1, 2 * CALL_UNITS);
    let admitted = calls_per_stretch(
        CALL_UNITS,
        BudgetExhaustionPolicy::Suspend,
        &[
            TryStretch {
                overdraft: Some(twice),
                most_calls: 2,
            },
            stretch(Some(twice)),
            stretch(Some(twice)),
        ],
    )?;
    assert_eq!(
        admitted,
        [2, 1, 0],
        "the line's call and the approval's two, no more"
    );
    Ok(())
}
