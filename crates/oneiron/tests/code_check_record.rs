//! The native check record (ARCH-0068 #rc5-check-reuse, FIX
//! [L4-30-CHECK-REUSE-RECORD]): a run records the check it ran in its own
//! checkout, the engine captures the inputs, and the owner reads them back.
//!
//! Each agent run is real: an enabled AGENT_DEF paired to the owner, running a
//! TASK the owner assigned it, on a claimed attempt the host sealed with an
//! executor run. Its checkout is claimed for its TASK through
//! `Memory::checkout_claim_through`, held by the run's actor, and bound with
//! `self.code.checkout.bind` (`Memory::repo_checkout_bind_for_run`) on a repo
//! served under the vault's serving root. The test then calls the two doors as
//! the code-run host does and reads through the owner door.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_check_record`.
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

use check_fixture::{
    append_output, claim_run, finish_check, git_tree, setup, standard_inputs, start_check,
};
use fixture::{MAIN, TestResult};
use oneiron::memory::code_doors::CodeCheckRecordsRequest;
use oneiron::memory::repo_doors::RepoCheckFinishInput;
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND};

#[test]
fn a_run_records_its_native_check_with_engine_captured_inputs() -> TestResult {
    let setup = setup()?;
    let run = claim_run(&setup, "check-record-task", 0x51)?;
    let (command, toolchain, _) = standard_inputs();
    let start = start_check(
        &setup,
        &run,
        command.clone(),
        toolchain,
        BTreeMap::from([("CI".to_owned(), "s3cr3t-value".to_owned())]),
        false,
    )?;
    let memory = run.memory(&setup.fixture.vault);
    let output = append_output(&memory, &setup.fixture.vault, b"test output")?;
    let finish = finish_check(&setup, &run, start.check, Some(0), output.clone())?;
    assert!(finish.passed);
    assert!(finish.stable);
    let worktree = oneiron::test_doors::check_record::check_record_worktree_path(
        &setup.fixture.vault,
        &run.checkout,
        run.epoch,
    )?;
    let tree = git_tree(&worktree)?;
    assert_eq!(start.inputs.tree.as_deref(), Some(tree.as_str()));
    assert_eq!(finish.after.tree.as_deref(), Some(tree.as_str()));
    let revision = oneiron::test_doors::check_record::check_record_task_revision(
        &setup.fixture.vault,
        run.run.task,
    )?;
    assert_eq!(start.inputs.request_revision, revision);
    assert_eq!(finish.after.request_revision, revision);
    let view = setup.fixture.owner_memory().code_check_records_as(
        &setup.fixture.owner_proof,
        CodeCheckRecordsRequest {
            attempt_id: run.attempt_hex.clone(),
        },
    )?;
    assert_eq!(view.attempt_id, run.attempt_hex);
    assert_eq!(view.records.len(), 1);
    let record = &view.records[0];
    assert_eq!(record.producer.attempt_id, run.attempt_hex);
    assert_eq!(record.command, command);
    assert_eq!(
        record.toolchain.get("rustc").map(String::as_str),
        Some("1.96.0")
    );
    assert_eq!(record.environment_names, vec!["CI".to_owned()]);
    assert_eq!(record.output, Some(output.as_str().to_owned()));
    assert!(record.finished);
    assert_eq!(record.passed, Some(true));
    assert_eq!(record.stable, Some(true));
    assert_eq!(record.inputs.request_revision, revision);
    assert_eq!(record.inputs.tree.as_deref(), Some(tree.as_str()));
    assert_eq!(
        record.limits,
        vec![
            "undeclared_inputs".to_owned(),
            "outside_state".to_owned(),
            "transient_writes".to_owned(),
            "relocation".to_owned(),
        ]
    );
    assert_eq!(
        record.declared,
        vec!["toolchain".to_owned(), "environment".to_owned()]
    );
    let json = serde_json::to_value(&view)?.to_string();
    assert!(
        !json.contains("s3cr3t-value"),
        "environment values are never stored"
    );
    assert!(json.contains("CI"), "environment names are stored");
    Ok(())
}

#[test]
fn a_check_whose_worktree_changed_during_the_run_is_unstable() -> TestResult {
    let setup = setup()?;
    let run = claim_run(&setup, "check-record-task", 0x51)?;
    let (command, toolchain, environment) = standard_inputs();
    let start = start_check(&setup, &run, command, toolchain, environment, false)?;
    assert!(start.inputs.tree.is_some());
    let worktree = oneiron::test_doors::check_record::check_record_worktree_path(
        &setup.fixture.vault,
        &run.checkout,
        run.epoch,
    )?;
    std::fs::write(worktree.join("NEW-FILE.md"), "changed during the run")?;
    let memory = run.memory(&setup.fixture.vault);
    let output = append_output(&memory, &setup.fixture.vault, b"output")?;
    let finish = finish_check(&setup, &run, start.check, Some(0), output)?;
    assert!(finish.passed);
    assert!(!finish.stable);
    assert_eq!(finish.after.tree, None);
    Ok(())
}

#[test]
fn a_dirty_worktree_records_an_unpinned_tree() -> TestResult {
    let setup = setup()?;
    let run = claim_run(&setup, "check-record-task", 0x51)?;
    let worktree = oneiron::test_doors::check_record::check_record_worktree_path(
        &setup.fixture.vault,
        &run.checkout,
        run.epoch,
    )?;
    std::fs::write(worktree.join("UNCOMMITTED.md"), "dirty")?;
    let (command, toolchain, environment) = standard_inputs();
    let start = start_check(&setup, &run, command, toolchain, environment, false)?;
    assert_eq!(start.inputs.tree, None);
    let memory = run.memory(&setup.fixture.vault);
    let output = append_output(&memory, &setup.fixture.vault, b"output")?;
    let finish = finish_check(&setup, &run, start.check, Some(0), output)?;
    assert!(finish.passed);
    assert!(!finish.stable);
    Ok(())
}

#[test]
fn a_run_cannot_finish_another_attempts_check() -> TestResult {
    let setup = setup()?;
    let run = claim_run(&setup, "check-record-task", 0x51)?;
    let (command, toolchain, environment) = standard_inputs();
    let start = start_check(&setup, &run, command, toolchain, environment, false)?;
    // A second run of the same agent, another attempt with its own checkout.
    let run2 = claim_run(&setup, "check-record-task-2", 0x52)?;
    let memory2 = run2.held_memory(&setup.fixture.vault);
    let output2 = append_output(&memory2, &setup.fixture.vault, b"peer output")?;
    let refused = memory2.repo_checks_finish_for_run(
        &run2.run.binding,
        RepoCheckFinishInput {
            repo: setup.served,
            git_ref: MAIN.to_owned(),
            checkout: run2.checkout.clone(),
            epoch: run2.epoch,
            check: start.check,
            exit_status: Some(0),
            output: output2,
        },
    );
    match refused {
        Err(error) => assert_eq!(error.code, MEMORY_CODE_NOT_FOUND),
        Ok(_) => return Err("a run cannot finish another attempt's check".into()),
    }
    // Its own run finishes once, and a second finish is refused.
    let memory = run.memory(&setup.fixture.vault);
    let output = append_output(&memory, &setup.fixture.vault, b"output")?;
    let done = finish_check(&setup, &run, start.check, Some(0), output.clone())?;
    assert!(done.passed);
    let again = memory.repo_checks_finish_for_run(
        &run.run.binding,
        RepoCheckFinishInput {
            repo: setup.served,
            git_ref: MAIN.to_owned(),
            checkout: run.checkout.clone(),
            epoch: run.epoch,
            check: start.check,
            exit_status: Some(0),
            output,
        },
    );
    match again {
        Err(error) => assert_eq!(error.code, MEMORY_CODE_INVALID_STATE),
        Ok(_) => return Err("a second finish of the same check is refused".into()),
    }
    Ok(())
}
