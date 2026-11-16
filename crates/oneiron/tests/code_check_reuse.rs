//! Reuse of a recorded native check (ARCH-0068 #rc5-check-reuse, FIX
//! [L4-30-CHECK-REUSE-RECORD]): a peer reuses a passed check on matching
//! inputs, each failed condition refuses, a peer outside the PROJECT cannot
//! reuse, and completion voids a reuse whose tree changed.
//!
//! WORLD-REUSE = A (a world check is never reused), REUSE-SCOPE = B (any
//! attempt in the same PROJECT whose own live run admission covers the
//! source's repo and ref), CHECK-VERBS = A (the engine captures the inputs).
//! Each source check uses its own command, so the reuse keys of the cases
//! never collide. Records are read through the owner door.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_check_reuse`.
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "the test shells out to stock git to read the worktree HEAD tree independently"
)]

#[path = "code_check/fixture.rs"]
mod check_fixture;
#[path = "repo_run/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::path::Path;

use check_fixture::{
    CheckRun, Setup, append_output, claim_run, finish_check, git, reuse_check, setup, start_check,
};
use fixture::TestResult;
use oneiron::EntityId;
use oneiron::memory::checkout_doors::CheckoutPublishInput;
use oneiron::memory::code_doors::{CodeCheckRecordView, CodeCheckRecordsRequest};
use oneiron::test_doors::check_record::{
    check_record_relabel_project, check_record_revise_task, check_record_task_revision,
    check_record_worktree_path,
};

/// One case's inputs: its own command, so the reuse keys of the cases never
/// collide, and the shared toolchain and environment.
fn case_inputs(
    case: &str,
) -> (
    Vec<String>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
) {
    (
        vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "--case".to_owned(),
            case.to_owned(),
        ],
        BTreeMap::from([("rustc".to_owned(), "1.96.0".to_owned())]),
        BTreeMap::from([("CI".to_owned(), "true".to_owned())]),
    )
}

/// The attempt's records as the owner reads them.
fn owner_records(setup: &Setup, run: &CheckRun) -> TestResult<Vec<CodeCheckRecordView>> {
    Ok(setup
        .fixture
        .owner_memory()
        .code_check_records_as(
            &setup.fixture.owner_proof,
            CodeCheckRecordsRequest {
                attempt_id: run.attempt_hex.clone(),
            },
        )?
        .records)
}

/// Run 1 runs `case` to `exit_status`; run 2's reuse answers none and adds
/// no record.
fn refuse_case(
    setup: &Setup,
    run1: &CheckRun,
    run2: &CheckRun,
    case: &str,
    world: bool,
    exit_status: Option<i32>,
) -> TestResult {
    let (command, toolchain, environment) = case_inputs(case);
    let start = start_check(setup, run1, command, toolchain, environment, world)?;
    let memory1 = run1.memory(&setup.fixture.vault);
    let output = append_output(&memory1, &setup.fixture.vault, b"case output")?;
    finish_check(setup, run1, start.check, exit_status, output)?;
    let (command, toolchain, environment) = case_inputs(case);
    let reused = reuse_check(setup, run2, command, toolchain, environment)?.reused;
    assert!(reused.is_none(), "{case} is refused");
    assert_eq!(owner_records(setup, run2)?.len(), 1);
    Ok(())
}

/// Commits one new file in the worktree through stock git: the new HEAD.
fn commit_file(worktree: &Path, name: &str) -> TestResult<String> {
    std::fs::write(worktree.join(name), "a peer moved on")?;
    git(worktree, &["add", "--", name])?;
    git(
        worktree,
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "a peer moved on",
        ],
    )?;
    git(worktree, &["rev-parse", "HEAD"])
}

/// Run 1 passes `case` and run 2 reuses it; run 2 then optionally commits a
/// new file and publishes its checkout. Answers run 2's reused record as
/// the owner reads it.
fn publish_reuse(
    setup: &Setup,
    run1: &CheckRun,
    run2: &CheckRun,
    case: &str,
    commit: bool,
) -> TestResult<CodeCheckRecordView> {
    let (command, toolchain, environment) = case_inputs(case);
    let start = start_check(setup, run1, command, toolchain, environment, false)?;
    let memory1 = run1.memory(&setup.fixture.vault);
    let output = append_output(&memory1, &setup.fixture.vault, b"case output")?;
    let done = finish_check(setup, run1, start.check, Some(0), output)?;
    assert!(done.passed && done.stable);
    let (command, toolchain, environment) = case_inputs(case);
    let reused = reuse_check(setup, run2, command, toolchain, environment)?.reused;
    assert!(reused.is_some(), "run 2 reuses run 1's passed check");
    let worktree = check_record_worktree_path(&setup.fixture.vault, &run2.checkout, run2.epoch)?;
    let observed = if commit {
        commit_file(&worktree, "run2-note.md")?
    } else {
        git(&worktree, &["rev-parse", "HEAD"])?
    };
    let memory2 = run2.held_memory(&setup.fixture.vault);
    let candidate = append_output(&memory2, &setup.fixture.vault, b"candidate")?;
    memory2.checkout_publish(CheckoutPublishInput {
        checkout: run2.checkout.clone(),
        epoch: run2.epoch,
        observed_ref: observed,
        candidate: EntityId::from_hex(candidate.as_str())?,
    })?;
    let records = owner_records(setup, run2)?;
    assert_eq!(records.len(), 1);
    records
        .into_iter()
        .next()
        .ok_or("run 2 holds its reused record".into())
}

#[test]
fn a_peer_reuses_a_passed_check_on_matching_inputs() -> TestResult {
    let setup = setup()?;
    let run1 = claim_run(&setup, "check-record-task", 0x51)?;
    let run2 = claim_run(&setup, "check-record-task-2", 0x52)?;
    let (command, toolchain, environment) = case_inputs("reuse-match");
    let start = start_check(&setup, &run1, command, toolchain, environment, false)?;
    let memory1 = run1.memory(&setup.fixture.vault);
    let output = append_output(&memory1, &setup.fixture.vault, b"test output")?;
    let done = finish_check(&setup, &run1, start.check, Some(0), output)?;
    assert!(done.passed);
    assert!(done.stable);
    let (command, toolchain, environment) = case_inputs("reuse-match");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    let Some(reused) = reused else {
        return Err("a peer reuses a passed check on matching inputs".into());
    };
    assert_eq!(reused.reused_from.attempt_id, run1.attempt_hex);
    assert_eq!(reused.reused_from.check, start.check.to_hex());
    assert_eq!(reused.inputs.tree, start.inputs.tree);
    let first = owner_records(&setup, &run1)?;
    assert_eq!(first.len(), 1);
    assert_eq!(reused.reused_from.generation, first[0].producer.generation);
    assert!(first[0].reused_from.is_none());
    let second = owner_records(&setup, &run2)?;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].reused_from.as_ref(), Some(&reused.reused_from));
    assert_eq!(second[0].passed, Some(true));
    assert!(!second[0].voided);
    Ok(())
}

#[test]
fn reuse_is_refused_for_each_failed_condition() -> TestResult {
    let setup = setup()?;
    let run1 = claim_run(&setup, "check-record-task", 0x51)?;
    let run2 = claim_run(&setup, "check-record-task-2", 0x52)?;
    let memory1 = run1.memory(&setup.fixture.vault);
    // Guard: one matching passed check reuses on this setup, so a refusal
    // below is its condition, not a broken fixture.
    let (command, toolchain, environment) = case_inputs("guard");
    let start = start_check(&setup, &run1, command, toolchain, environment, false)?;
    let output = append_output(&memory1, &setup.fixture.vault, b"guard output")?;
    let done = finish_check(&setup, &run1, start.check, Some(0), output)?;
    assert!(done.passed && done.stable);
    let (command, toolchain, environment) = case_inputs("guard");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    assert!(reused.is_some(), "the guard reuse matches");
    assert_eq!(owner_records(&setup, &run2)?.len(), 1);
    // (1) a failed check.
    refuse_case(&setup, &run1, &run2, "failed", false, Some(1))?;
    // (2) an unstable check.
    let (command, toolchain, environment) = case_inputs("unstable");
    let start = start_check(&setup, &run1, command, toolchain, environment, false)?;
    let worktree = check_record_worktree_path(&setup.fixture.vault, &run1.checkout, run1.epoch)?;
    std::fs::write(worktree.join("UNTRACKED.md"), "changed during the run")?;
    let output = append_output(&memory1, &setup.fixture.vault, b"case output")?;
    let done = finish_check(&setup, &run1, start.check, Some(0), output)?;
    assert!(done.passed);
    assert!(!done.stable);
    std::fs::remove_file(worktree.join("UNTRACKED.md"))?;
    let (command, toolchain, environment) = case_inputs("unstable");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    assert!(reused.is_none(), "an unstable check is refused");
    assert_eq!(owner_records(&setup, &run2)?.len(), 1);
    // (3) a world check.
    refuse_case(&setup, &run1, &run2, "world", true, Some(0))?;
    // (4) the source TASK revised after its check.
    let (command, toolchain, environment) = case_inputs("revised-task");
    let start = start_check(&setup, &run1, command, toolchain, environment, false)?;
    let output = append_output(&memory1, &setup.fixture.vault, b"case output")?;
    let done = finish_check(&setup, &run1, start.check, Some(0), output)?;
    assert!(done.passed && done.stable);
    let before = check_record_task_revision(&setup.fixture.vault, run1.run.task)?;
    let revised = check_record_revise_task(&setup.fixture.vault, run1.run.task)?;
    assert!(revised > before, "the source TASK revision rose");
    let (command, toolchain, environment) = case_inputs("revised-task");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    assert!(reused.is_none(), "a revised source TASK is refused");
    assert_eq!(owner_records(&setup, &run2)?.len(), 1);
    // (5) the receiver on a different tree, last: it moves run 2's HEAD.
    let (command, toolchain, environment) = case_inputs("other-tree");
    let start = start_check(&setup, &run1, command, toolchain, environment, false)?;
    let output = append_output(&memory1, &setup.fixture.vault, b"case output")?;
    let done = finish_check(&setup, &run1, start.check, Some(0), output)?;
    assert!(done.passed && done.stable);
    let worktree = check_record_worktree_path(&setup.fixture.vault, &run2.checkout, run2.epoch)?;
    commit_file(&worktree, "run2-note.md")?;
    let (command, toolchain, environment) = case_inputs("other-tree");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    assert!(
        reused.is_none(),
        "a receiver on a different tree is refused"
    );
    assert_eq!(owner_records(&setup, &run2)?.len(), 1);
    Ok(())
}

#[test]
fn a_peer_outside_the_project_cannot_reuse() -> TestResult {
    let setup = setup()?;
    let run1 = claim_run(&setup, "check-record-task", 0x51)?;
    let run2 = claim_run(&setup, "check-record-task-2", 0x52)?;
    let (command, toolchain, environment) = case_inputs("outside-project");
    let start = start_check(&setup, &run1, command, toolchain, environment, false)?;
    let memory1 = run1.memory(&setup.fixture.vault);
    let output = append_output(&memory1, &setup.fixture.vault, b"case output")?;
    let done = finish_check(&setup, &run1, start.check, Some(0), output)?;
    assert!(done.passed && done.stable);
    check_record_relabel_project(
        &setup.fixture.vault,
        &run1.attempt_hex,
        start.check,
        EntityId::now(),
    )?;
    let (command, toolchain, environment) = case_inputs("outside-project");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    assert!(reused.is_none(), "a peer outside the project cannot reuse");
    check_record_relabel_project(
        &setup.fixture.vault,
        &run1.attempt_hex,
        start.check,
        setup.fixture.project,
    )?;
    let (command, toolchain, environment) = case_inputs("outside-project");
    let reused = reuse_check(&setup, &run2, command, toolchain, environment)?.reused;
    assert!(
        reused.is_some(),
        "the guard reuse matches once the project is back"
    );
    Ok(())
}

#[test]
fn completion_voids_a_reuse_whose_tree_changed() -> TestResult {
    let setup = setup()?;
    let run1 = claim_run(&setup, "check-record-task", 0x51)?;
    let run2 = claim_run(&setup, "check-record-task-2", 0x52)?;
    let record = publish_reuse(&setup, &run1, &run2, "voided", true)?;
    let Some(source) = &record.reused_from else {
        return Err("the published record is a reuse".into());
    };
    assert_eq!(source.attempt_id, run1.attempt_hex);
    assert!(record.voided);
    Ok(())
}

#[test]
fn completion_keeps_a_reuse_on_the_reused_tree() -> TestResult {
    let setup = setup()?;
    let run1 = claim_run(&setup, "check-record-task", 0x51)?;
    let run2 = claim_run(&setup, "check-record-task-2", 0x52)?;
    let record = publish_reuse(&setup, &run1, &run2, "kept", false)?;
    assert!(
        record.reused_from.is_some(),
        "the published record is a reuse"
    );
    assert!(!record.voided);
    Ok(())
}
