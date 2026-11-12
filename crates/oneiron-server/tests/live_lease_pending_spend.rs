//! [RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]: a host's live lease stages each
//! settled call's spend on its scope, in a commit of its own, before any
//! drain books it there. A process that dies between a provider's answer and
//! the booking loses none of that spend: the next drain books it, once. The
//! server drains every scope at its start (its first lifecycle tick), and a
//! run step's saved answer, read again, drains its run's scope.
//!
//! Reaches the lease through `oneiron_server::test_doors::live_lease`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test live_lease_pending_spend`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::{Vault, VaultConfig};
use oneiron_server::test_doors::live_lease::{
    settle_call_and_book_rest, settle_call_and_die_after_stage,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A root roomy enough that no call here meets its cap.
const ROOT_UNITS: u64 = 1_000_000;
/// What one settled call spent.
const CALL_UNITS: u64 = 700;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    Ok((dir, vault))
}

/// Opens a hard root of [`ROOT_UNITS`], shown at its start.
fn open_root(
    dispatcher: &AgentDispatcher<'_>,
    name: &str,
) -> Result<SpendScopeId, Box<dyn std::error::Error>> {
    let root = SpendScopeId::launch(name)?;
    let opened = dispatcher.open_root_spend_scope(
        root.clone(),
        DeclaredMaximum {
            units: ROOT_UNITS,
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

#[test]
fn a_lease_that_dies_after_staging_its_call_books_that_call_once_at_the_server_start() -> TestResult
{
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-lease-death-root")?;

    settle_call_and_die_after_stage(&vault, &root, CALL_UNITS)?;
    assert_eq!(
        dispatcher.staged_lease_spend(&root)?,
        CALL_UNITS,
        "the dead lease's settled call is staged on its scope, not lost with its memory"
    );
    assert_eq!(
        spent(&dispatcher, &root)?,
        0,
        "a stage books nothing on the scope by itself"
    );

    assert_eq!(
        dispatcher.drain_all_lease_spend()?,
        CALL_UNITS,
        "the start drain books the staged call"
    );
    assert_eq!(spent(&dispatcher, &root)?, CALL_UNITS);
    assert_eq!(dispatcher.staged_lease_spend(&root)?, 0);

    assert_eq!(
        dispatcher.drain_all_lease_spend()?,
        0,
        "a second start drain finds nothing staged"
    );
    assert_eq!(
        spent(&dispatcher, &root)?,
        CALL_UNITS,
        "the dead lease's call is booked once"
    );
    Ok(())
}

#[test]
fn a_saved_answer_read_again_drains_its_own_scope_once() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    // The second root's id starts with the first's: a drain of the first
    // must not reach the second's rows.
    let run = open_root(&dispatcher, "owen-saved-step-root")?;
    let other = open_root(&dispatcher, "owen-saved-step-root-2")?;

    settle_call_and_die_after_stage(&vault, &run, CALL_UNITS)?;
    settle_call_and_die_after_stage(&vault, &other, CALL_UNITS)?;

    // What the run-step door does on a memo hit, before it answers.
    assert_eq!(dispatcher.drain_lease_spend(&run)?, CALL_UNITS);
    assert_eq!(
        dispatcher.drain_lease_spend(&run)?,
        0,
        "the key's next read finds nothing staged"
    );
    assert_eq!(
        spent(&dispatcher, &run)?,
        CALL_UNITS,
        "the saved answer's call is booked once"
    );
    assert_eq!(
        dispatcher.staged_lease_spend(&other)?,
        CALL_UNITS,
        "another scope's staged call stays for its own drain"
    );
    assert_eq!(spent(&dispatcher, &other)?, 0);
    Ok(())
}

#[test]
fn a_lease_that_ends_books_its_call_once() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-lease-end-root")?;

    settle_call_and_book_rest(&vault, &root, CALL_UNITS)?;
    assert_eq!(spent(&dispatcher, &root)?, CALL_UNITS);
    assert_eq!(
        dispatcher.staged_lease_spend(&root)?,
        0,
        "the try's end drains what it staged"
    );
    assert_eq!(dispatcher.drain_all_lease_spend()?, 0);
    assert_eq!(
        spent(&dispatcher, &root)?,
        CALL_UNITS,
        "a later drain books the ended lease's call no second time"
    );
    Ok(())
}
