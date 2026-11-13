//! [MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH], S7299-P1: a media job its run's
//! spend scope funds books its own guard's use on that scope as a live lease
//! does (#7268's staged spend): each part is staged, then the scope is
//! drained.
//! - A booking that stops after its stage in a commit of its own, its
//!   process dead, loses none of that part: the server's start drain books
//!   it, once.
//! - A job's end stages its part in the commit that writes its end row: a
//!   process that dies after that commit and before its drain has its end
//!   booked once by the start drain, and a restarted runtime's poll answers
//!   the job's written end, so it takes no job up whose fresh permit would
//!   charge that end a second time.
//! - A job whose end row and held end the vault both refused is held with
//!   its end, and each poll writes that end again (FIX 2963). Two such polls
//!   at once stage the end's part once (S7299 review round 3 P1): the second
//!   finds it staged.
//!
//! Reaches the job's ledger and its runtime through
//! `oneiron_server::test_doors::media_job_spend`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test media_job_staged_spend`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::media::MediaJobState;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::{FatalLlmError, LlmError, Vault, VaultConfig};
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::media_job_spend::{ScopedJobSpend, ScopedMediaJob};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A root roomy enough that no charge here meets its cap.
const ROOT_UNITS: u64 = 1_000_000;
/// What the settled rungs of the job's submit walk charged its guard.
const SUBMIT_UNITS: u64 = 300;
/// What the job's permit charged its guard when it settled at the job's end.
const END_UNITS: u64 = 700;

fn open_vault() -> Result<(tempfile::TempDir, Arc<Vault>), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    Ok((dir, Arc::new(vault)))
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

/// The end the job's provider reports: a failed job, its permit settled
/// with a charge all the same.
fn job_end() -> MediaJobState {
    MediaJobState::Failed {
        error: LlmError::Fatal(FatalLlmError::InvalidRequest),
    }
}

#[test]
fn a_booking_that_dies_after_its_stage_books_that_part_once_at_the_server_start() -> TestResult {
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
        "the dead booking's part is staged on its scope, not lost with its memory"
    );
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS,
        "a stage books nothing on the scope by itself"
    );

    assert_eq!(
        dispatcher.drain_all_lease_spend()?,
        END_UNITS,
        "the start drain books the staged part"
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
        "the dead booking's part is booked once"
    );
    Ok(())
}

#[test]
fn a_kept_scoped_job_whose_poll_writes_its_end_books_its_guard_use_once() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-media-end-root")?;

    let job = ScopedMediaJob::open(Arc::clone(&vault), &root)?;
    job.settle(SUBMIT_UNITS)?;
    let ticket = job.keep_submitted()?;
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS,
        "the submit's settled rungs book on the scope before its row is kept"
    );

    job.settle(END_UNITS)?;
    let end = job_end();
    assert_eq!(
        job.end(&ticket, &end)?,
        end,
        "the poll answers the job's end"
    );
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "the end books only what the guard used past the submit's booking"
    );
    assert_eq!(
        dispatcher.staged_lease_spend(&root)?,
        0,
        "the end's drain books what its commit staged"
    );

    assert_eq!(dispatcher.drain_all_lease_spend()?, 0);
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "a later drain books the job's spend no second time"
    );
    Ok(())
}

#[tokio::test]
async fn a_scoped_job_dead_after_its_end_commit_books_the_end_once_and_its_restart_takes_no_job_up()
-> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-media-restart-root")?;

    let job = ScopedMediaJob::open(Arc::clone(&vault), &root)?;
    job.settle(SUBMIT_UNITS)?;
    let ticket = job.keep_submitted()?;
    job.settle(END_UNITS)?;
    let end = job_end();
    job.end_and_die(&ticket, &end)?;

    // The restart: the server's start drain, then a runtime that keeps its
    // jobs in the same vault, which a poll of the job reaches.
    dispatcher.drain_all_lease_spend()?;
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "the start drain leaves the end booked once"
    );
    let restarted = ModelRuntime::unconfigured().with_media_vault(Arc::clone(&vault));
    let polled = restarted.media().poll(&ticket).await;
    assert_eq!(
        polled.as_ref().ok(),
        Some(&end),
        "the restart reads the job's end from its row, so it takes no job up whose fresh \
         permit would charge that end again: {polled:?}"
    );

    assert_eq!(dispatcher.drain_all_lease_spend()?, 0);
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "the dead job's end is booked once after its restart"
    );
    Ok(())
}

#[test]
fn two_polls_at_once_of_a_scoped_job_whose_end_writes_were_refused_book_its_end_once() -> TestResult
{
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "owen-media-refused-end-root")?;

    let job = ScopedMediaJob::open(Arc::clone(&vault), &root)?;
    job.settle(SUBMIT_UNITS)?;
    let ticket = job.keep_submitted()?;
    job.settle(END_UNITS)?;
    let end = job_end();
    job.end_refused(&ticket, &end);
    assert_eq!(
        dispatcher.staged_lease_spend(&root)?,
        0,
        "an end whose writes were refused stages nothing"
    );
    assert_eq!(spent(&dispatcher, &root)?, SUBMIT_UNITS);

    // Each poll's end waits after its snapshot of the scope's part until the
    // other's took one too, or 5 s pass.
    for polled in job.poll_twice_at_once(&ticket)? {
        assert_eq!(
            polled.as_ref().ok(),
            Some(&end),
            "each poll answers the job's end: {polled:?}"
        );
    }
    dispatcher.drain_all_lease_spend()?;
    assert_eq!(
        spent(&dispatcher, &root)?,
        SUBMIT_UNITS + END_UNITS,
        "the end is booked once, not once per poll"
    );
    assert_eq!(dispatcher.staged_lease_spend(&root)?, 0);
    Ok(())
}
