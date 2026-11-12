//! [MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH]: a media job its run's spend
//! scope funds books its own guard's use on that scope as a live lease does
//! (#7268's staged spend): each part is staged in a commit of its own, then
//! the scope is drained. A job whose booking stops after its stage, its
//! process dead or its drain failed, loses none of that spend: the next
//! drain books it, once. The server drains every scope at its start (its
//! first lifecycle tick).
//!
//! Reaches the job's ledger through
//! `oneiron_server::test_doors::media_job_spend`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test media_job_staged_spend`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::{Vault, VaultConfig};
use oneiron_server::test_doors::media_job_spend::ScopedJobSpend;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A root roomy enough that no charge here meets its cap.
const ROOT_UNITS: u64 = 1_000_000;
/// What the settled rungs of the job's submit walk charged its guard.
const SUBMIT_UNITS: u64 = 300;
/// What the job's permit charged its guard when it settled at the job's end.
const END_UNITS: u64 = 700;

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
fn a_scoped_job_that_dies_after_staging_its_end_books_that_end_once_at_the_server_start()
-> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-media-death-root")?;

    let mut job = ScopedJobSpend::open(&vault, &root)?;
    job.settle(SUBMIT_UNITS)?;
    job.book(&vault);
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS,
        "the submit's settled rungs book on the scope at once"
    );

    job.settle(END_UNITS)?;
    job.stage_and_die(&vault)?;
    assert_eq!(
        dispatcher.staged_lease_spend(&root)?,
        END_UNITS,
        "the dead job's end is staged on its scope, not lost with its memory"
    );
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS,
        "a stage books nothing on the scope by itself"
    );

    assert_eq!(
        dispatcher.drain_all_lease_spend()?,
        END_UNITS,
        "the start drain books the staged end"
    );
    assert_eq!(spent(&dispatcher, &root)?, SUBMIT_UNITS + END_UNITS);
    assert_eq!(dispatcher.staged_lease_spend(&root)?, 0);

    assert_eq!(
        dispatcher.drain_all_lease_spend()?,
        0,
        "a second start drain finds nothing staged"
    );
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "the dead job's end is booked once"
    );
    Ok(())
}

#[test]
fn a_scoped_job_booked_at_its_submit_and_its_end_books_its_guard_use_once() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-media-end-root")?;

    let mut job = ScopedJobSpend::open(&vault, &root)?;
    job.settle(SUBMIT_UNITS)?;
    job.book(&vault);
    job.settle(END_UNITS)?;
    job.book(&vault);
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "the end books only what the guard used past the submit's booking"
    );
    assert_eq!(
        dispatcher.staged_lease_spend(&root)?,
        0,
        "each booking drains what it staged"
    );

    job.book(&vault);
    assert_eq!(dispatcher.drain_all_lease_spend()?, 0);
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "a booking with nothing new, and a later drain, book the job's spend no second time"
    );
    Ok(())
}
