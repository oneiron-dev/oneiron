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

#[path = "repo_run/fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use fixture::{
    MAIN, RepoFixture, RunBinding, TestResult, bind_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::attempt_queue::AttemptResultRef;
use oneiron::federation::RepoAccessBounds;
use oneiron::memory::checkout_doors::{CheckoutClaimInput, CheckoutClass};
use oneiron::memory::code_doors::CodeCheckRecordsRequest;
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::memory::repo_doors::{
    RepoCheckFinishInput, RepoCheckFinishOutput, RepoCheckStartInput, RepoCheckStartOutput,
    RepoCheckoutBindInput,
};
use oneiron::memory::{
    BlobArtifactInput, BlobVersionAppendOutcome, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND,
    Memory,
};
use oneiron::origin::smart_http::origin_serving_root;
use oneiron::store::checkout_lease::{
    CheckoutId, CheckoutLiveness, CheckoutLivenessPulse, CheckoutResult,
};
use oneiron::{EntityId, Vault};

/// The claim's liveness sink: the test holds no presence.
struct TestLiveness;

impl CheckoutLiveness for TestLiveness {
    fn publish(&mut self, _pulse: CheckoutLivenessPulse) -> CheckoutResult<()> {
        Ok(())
    }

    fn current(&self, _id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(None)
    }

    fn clear(&mut self, _id: CheckoutId, _epoch: u64) -> CheckoutResult<()> {
        Ok(())
    }
}

/// One `git` call in `dir`, its trimmed stdout.
fn git(dir: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").args(args).current_dir(dir).output()?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// A seeded source repo on `refs/heads/main` with two Rust files in one
/// commit: its tempdir and commit.
fn seed_source() -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", MAIN])?;
    std::fs::write(dir.path().join("math.rs"), fixture::MATH_RS)?;
    std::fs::write(dir.path().join("label.rs"), fixture::LABEL_RS)?;
    git(dir.path(), &["add", "--", "math.rs", "label.rs"])?;
    git(
        dir.path(),
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
            "two files",
        ],
    )?;
    let commit = git(dir.path(), &["rev-parse", "HEAD"])?;
    Ok((dir, commit))
}

/// The source served under the vault's serving root as `name.git`: its directory.
fn served_repo(vault: &Vault, source: &Path, name: &str) -> TestResult<PathBuf> {
    let root = origin_serving_root(vault)?;
    let dir = root.join(format!("{name}.git"));
    let source = source.to_str().ok_or("UTF-8 source path")?;
    let target = dir.to_str().ok_or("UTF-8 served path")?;
    git(&root, &["clone", "--quiet", "--bare", "--", source, target])?;
    Ok(dir)
}

/// The CODE_ARTIFACT of the served repo at `commit`, ingested from the served store itself.
fn ingest_served(fixture: &RepoFixture, served_dir: &Path, commit: &str) -> TestResult<EntityId> {
    Ok(fixture
        .owner_memory()
        .code_snapshot_ingest_as(
            &fixture.owner_proof,
            CodeSnapshotIngestRequest {
                project_id: fixture.project.to_hex(),
                pointer: CodeRepoPointer {
                    local_folder: served_dir.to_str().ok_or("UTF-8 served path")?.to_owned(),
                    commit: commit.to_owned(),
                },
                repository: None,
            },
        )?
        .repo)
}

/// One agent's live run with its checkout claimed and bound on its served repo.
struct Setup {
    fixture: RepoFixture,
    agent: EntityId,
    served: EntityId,
    run: RunBinding,
    attempt_hex: String,
    checkout: String,
    epoch: u64,
}

impl Setup {
    /// The run's own Memory handle: the agent, as the binding names it.
    fn memory(&self) -> Memory<'_> {
        self.run.memory(&self.fixture.vault)
    }
}

fn setup() -> TestResult<Setup> {
    let fixture = RepoFixture::new()?;
    let agent = create_enabled_agent(&fixture.vault, &fixture.owner_proof, "check-record-agent")?;
    let slip = paired_agent_slip(
        &fixture.vault,
        &fixture.issuer,
        &fixture.owner_proof,
        agent,
        0x51,
    )?;
    let (source_dir, commit) = seed_source()?;
    let served_dir = served_repo(&fixture.vault, source_dir.path(), "demo")?;
    let served = ingest_served(&fixture, &served_dir, &commit)?;
    fixture.vault.put_project_member(served, fixture.project)?;
    let bounds = RepoAccessBounds {
        repo: served,
        project: fixture.project,
        refs: BTreeSet::from([MAIN.to_owned()]),
        readable: BTreeSet::from(["*.rs".to_owned()]),
        editable: BTreeSet::from(["*.rs".to_owned()]),
    };
    let _grant = mint_repo_grant(&fixture.vault, &fixture.owner_proof, agent, Some(&bounds))?;
    let owner_memory = fixture.owner_memory();
    let (task, actor, leased) = leased_try(
        &fixture.vault,
        &owner_memory,
        fixture.owner,
        agent,
        "check-record-task",
    )?;
    let attempt_hex = hex_lower(leased.id.as_bytes());
    let run = bind_run(&fixture.vault, &slip, (task, actor, leased))?;
    let checkout = EntityId::now().to_hex();
    // The agent claims on its own credential, as production does through the
    // host door: the TASK standing proof reads the presented slip.
    let memory = run.memory(&fixture.vault).with_read_proof(&slip);
    let mut live = TestLiveness;
    let claim = memory.checkout_claim_through(
        CheckoutClaimInput {
            checkout: checkout.clone(),
            repo: served,
            task: run.task,
            task_class: CheckoutClass::Edit,
            ttl_seconds: 3_600,
            declared_idempotent: false,
        },
        &mut live,
    )?;
    let bind = memory.repo_checkout_bind_for_run(
        &run.binding,
        RepoCheckoutBindInput {
            repo: served,
            git_ref: MAIN.to_owned(),
            checkout: checkout.clone(),
            epoch: claim.epoch,
            endpoint: None,
        },
    )?;
    Ok(Setup {
        fixture,
        agent,
        served,
        run,
        attempt_hex,
        checkout,
        epoch: bind.output.epoch,
    })
}

/// Starts the run's check with the given command and declarations.
fn start_check(
    setup: &Setup,
    command: Vec<String>,
    toolchain: BTreeMap<String, String>,
    environment: BTreeMap<String, String>,
) -> TestResult<RepoCheckStartOutput> {
    Ok(setup
        .memory()
        .repo_checks_start_for_run(
            &setup.run.binding,
            RepoCheckStartInput {
                repo: setup.served,
                git_ref: MAIN.to_owned(),
                checkout: setup.checkout.clone(),
                epoch: setup.epoch,
                command,
                toolchain,
                environment,
                world: false,
            },
        )?
        .output)
}

/// Finishes the run's check with an exited-zero status and the stored output.
fn finish_check(
    setup: &Setup,
    check: EntityId,
    output: AttemptResultRef,
) -> TestResult<RepoCheckFinishOutput> {
    Ok(setup
        .memory()
        .repo_checks_finish_for_run(
            &setup.run.binding,
            RepoCheckFinishInput {
                repo: setup.served,
                git_ref: MAIN.to_owned(),
                checkout: setup.checkout.clone(),
                epoch: setup.epoch,
                check,
                exit_status: Some(0),
                output,
            },
        )?
        .output)
}

/// Appends the run's check output bytes as one landed artifact version, the way a run does.
fn append_output(memory: &Memory, vault: &Vault, bytes: &[u8]) -> TestResult<AttemptResultRef> {
    let artifact = EntityId::now();
    let now = vault.now_recorded_at();
    memory.put_blob_artifact(&BlobArtifactInput {
        id: Some(artifact.to_hex()),
        name: "check-output.bin".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        occurred_at: now,
        learned_at: None,
    })?;
    let outcome = memory.append_blob_version(&artifact.to_hex(), bytes, None, now, None)?;
    if !matches!(outcome, BlobVersionAppendOutcome::Landed(_)) {
        return Err("the check output version lands".into());
    }
    Ok(AttemptResultRef::new(artifact.to_hex())?)
}

/// The worktree's HEAD tree, read independently through stock git.
fn git_tree(worktree: &Path) -> TestResult<String> {
    git(worktree, &["rev-parse", "HEAD^{tree}"])
}

/// Lower-hex of bytes, as the receipt views render ids.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn standard_inputs() -> (
    Vec<String>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
) {
    (
        vec!["cargo".to_owned(), "test".to_owned()],
        BTreeMap::from([("rustc".to_owned(), "1.96.0".to_owned())]),
        BTreeMap::from([("CI".to_owned(), "true".to_owned())]),
    )
}

#[test]
fn a_run_records_its_native_check_with_engine_captured_inputs() -> TestResult {
    let setup = setup()?;
    let (command, toolchain, _) = standard_inputs();
    let start = start_check(
        &setup,
        command.clone(),
        toolchain,
        BTreeMap::from([("CI".to_owned(), "s3cr3t-value".to_owned())]),
    )?;
    let memory = setup.memory();
    let output = append_output(&memory, &setup.fixture.vault, b"test output")?;
    let finish = finish_check(&setup, start.check, output.clone())?;
    assert!(finish.passed);
    assert!(finish.stable);
    let worktree = oneiron::test_doors::check_record::check_record_worktree_path(
        &setup.fixture.vault,
        &setup.checkout,
        setup.epoch,
    )?;
    let tree = git_tree(&worktree)?;
    assert_eq!(start.inputs.tree.as_deref(), Some(tree.as_str()));
    assert_eq!(finish.after.tree.as_deref(), Some(tree.as_str()));
    let revision = oneiron::test_doors::check_record::check_record_task_revision(
        &setup.fixture.vault,
        setup.run.task,
    )?;
    assert_eq!(start.inputs.request_revision, revision);
    assert_eq!(finish.after.request_revision, revision);
    let view = setup.fixture.owner_memory().code_check_records_as(
        &setup.fixture.owner_proof,
        CodeCheckRecordsRequest {
            attempt_id: setup.attempt_hex.clone(),
        },
    )?;
    assert_eq!(view.attempt_id, setup.attempt_hex);
    assert_eq!(view.records.len(), 1);
    let record = &view.records[0];
    assert_eq!(record.producer.attempt_id, setup.attempt_hex);
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
    let (command, toolchain, environment) = standard_inputs();
    let start = start_check(&setup, command, toolchain, environment)?;
    assert!(start.inputs.tree.is_some());
    let worktree = oneiron::test_doors::check_record::check_record_worktree_path(
        &setup.fixture.vault,
        &setup.checkout,
        setup.epoch,
    )?;
    std::fs::write(worktree.join("NEW-FILE.md"), "changed during the run")?;
    let memory = setup.memory();
    let output = append_output(&memory, &setup.fixture.vault, b"output")?;
    let finish = finish_check(&setup, start.check, output)?;
    assert!(finish.passed);
    assert!(!finish.stable);
    assert_eq!(finish.after.tree, None);
    Ok(())
}

#[test]
fn a_dirty_worktree_records_an_unpinned_tree() -> TestResult {
    let setup = setup()?;
    let worktree = oneiron::test_doors::check_record::check_record_worktree_path(
        &setup.fixture.vault,
        &setup.checkout,
        setup.epoch,
    )?;
    std::fs::write(worktree.join("UNCOMMITTED.md"), "dirty")?;
    let (command, toolchain, environment) = standard_inputs();
    let start = start_check(&setup, command, toolchain, environment)?;
    assert_eq!(start.inputs.tree, None);
    let memory = setup.memory();
    let output = append_output(&memory, &setup.fixture.vault, b"output")?;
    let finish = finish_check(&setup, start.check, output)?;
    assert!(finish.passed);
    assert!(!finish.stable);
    Ok(())
}

#[test]
fn a_run_cannot_finish_another_attempts_check() -> TestResult {
    let setup = setup()?;
    let (command, toolchain, environment) = standard_inputs();
    let start = start_check(&setup, command, toolchain, environment)?;
    // A second run of the same agent, another attempt with its own checkout.
    let owner_memory = setup.fixture.owner_memory();
    let (task2, actor2, leased2) = leased_try(
        &setup.fixture.vault,
        &owner_memory,
        setup.fixture.owner,
        setup.agent,
        "check-record-task-2",
    )?;
    let slip2 = paired_agent_slip(
        &setup.fixture.vault,
        &setup.fixture.issuer,
        &setup.fixture.owner_proof,
        setup.agent,
        0x52,
    )?;
    let run2 = bind_run(&setup.fixture.vault, &slip2, (task2, actor2, leased2))?;
    let memory2 = run2.memory(&setup.fixture.vault).with_read_proof(&slip2);
    let checkout2 = EntityId::now().to_hex();
    let mut live = TestLiveness;
    let claim2 = memory2.checkout_claim_through(
        CheckoutClaimInput {
            checkout: checkout2.clone(),
            repo: setup.served,
            task: task2,
            task_class: CheckoutClass::Edit,
            ttl_seconds: 3_600,
            declared_idempotent: false,
        },
        &mut live,
    )?;
    memory2.repo_checkout_bind_for_run(
        &run2.binding,
        RepoCheckoutBindInput {
            repo: setup.served,
            git_ref: MAIN.to_owned(),
            checkout: checkout2.clone(),
            epoch: claim2.epoch,
            endpoint: None,
        },
    )?;
    let output2 = append_output(&memory2, &setup.fixture.vault, b"peer output")?;
    let refused = memory2.repo_checks_finish_for_run(
        &run2.binding,
        RepoCheckFinishInput {
            repo: setup.served,
            git_ref: MAIN.to_owned(),
            checkout: checkout2,
            epoch: claim2.epoch,
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
    let memory = setup.memory();
    let output = append_output(&memory, &setup.fixture.vault, b"output")?;
    let done = finish_check(&setup, start.check, output.clone())?;
    assert!(done.passed);
    let again = memory.repo_checks_finish_for_run(
        &setup.run.binding,
        RepoCheckFinishInput {
            repo: setup.served,
            git_ref: MAIN.to_owned(),
            checkout: setup.checkout.clone(),
            epoch: setup.epoch,
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
