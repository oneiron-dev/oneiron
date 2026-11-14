//! The native check tests' shared fixture (ARCH-0068 #rc5-check-reuse, FIX
//! [L4-30-CHECK-REUSE-RECORD]): one served repo with one granted agent in one
//! PROJECT, one live run a call, each with its checkout claimed and bound on
//! that repo, and the start, finish and reuse calls as the code-run host
//! makes them. Each agent run is real: an enabled AGENT_DEF paired to the
//! owner, running a TASK the owner assigned it, on a claimed attempt the
//! host sealed with an executor run.
#![allow(dead_code)] // each integration binary uses a subset of these helpers

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::fixture::{
    MAIN, RepoFixture, RunBinding, TestResult, bind_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::attempt_queue::AttemptResultRef;
use oneiron::authority::VerifiedSlip;
use oneiron::federation::RepoAccessBounds;
use oneiron::memory::checkout_doors::{CheckoutClaimInput, CheckoutClass};
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::memory::repo_doors::{
    RepoCheckFinishInput, RepoCheckFinishOutput, RepoCheckReuseInput, RepoCheckReuseOutput,
    RepoCheckStartInput, RepoCheckStartOutput, RepoCheckoutBindInput,
};
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome, Memory};
use oneiron::origin::smart_http::origin_serving_root;
use oneiron::store::checkout_lease::{
    CheckoutId, CheckoutLiveness, CheckoutLivenessPulse, CheckoutResult,
};
use oneiron::{EntityId, Vault};

/// The claim's liveness sink: the test holds no presence.
pub(crate) struct TestLiveness;

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
pub(crate) fn git(dir: &Path, args: &[&str]) -> TestResult<String> {
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
pub(crate) fn seed_source() -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", MAIN])?;
    std::fs::write(dir.path().join("math.rs"), crate::fixture::MATH_RS)?;
    std::fs::write(dir.path().join("label.rs"), crate::fixture::LABEL_RS)?;
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
pub(crate) fn served_repo(vault: &Vault, source: &Path, name: &str) -> TestResult<PathBuf> {
    let root = origin_serving_root(vault)?;
    let dir = root.join(format!("{name}.git"));
    let source = source.to_str().ok_or("UTF-8 source path")?;
    let target = dir.to_str().ok_or("UTF-8 served path")?;
    git(&root, &["clone", "--quiet", "--bare", "--", source, target])?;
    Ok(dir)
}

/// The CODE_ARTIFACT of the served repo at `commit`, ingested from the served store itself.
pub(crate) fn ingest_served(
    fixture: &RepoFixture,
    served_dir: &Path,
    commit: &str,
) -> TestResult<EntityId> {
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

/// One served repo with one granted agent in one PROJECT.
pub(crate) struct Setup {
    pub(crate) fixture: RepoFixture,
    pub(crate) agent: EntityId,
    pub(crate) served: EntityId,
}

/// One agent's live run on the served repo: its sealed binding and slip, its
/// attempt, and its claimed and bound checkout.
pub(crate) struct CheckRun {
    pub(crate) run: RunBinding,
    pub(crate) slip: VerifiedSlip,
    pub(crate) attempt_hex: String,
    pub(crate) checkout: String,
    pub(crate) epoch: u64,
}

impl CheckRun {
    /// The run's own Memory handle: the agent, as the binding names it.
    pub(crate) fn memory<'v>(&self, vault: &'v Vault) -> Memory<'v> {
        self.run.memory(vault)
    }

    /// The run's own Memory handle on its own credential: what claims and
    /// publishes its checkout.
    pub(crate) fn held_memory<'v>(&self, vault: &'v Vault) -> Memory<'v> {
        self.run.memory(vault).with_read_proof(&self.slip)
    }
}

pub(crate) fn setup() -> TestResult<Setup> {
    let fixture = RepoFixture::new()?;
    let agent = create_enabled_agent(&fixture.vault, &fixture.owner_proof, "check-record-agent")?;
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
    Ok(Setup {
        fixture,
        agent,
        served,
    })
}

/// One agent's live run in the setup's PROJECT on its served repo: its TASK,
/// its sealed binding, and its claimed and bound checkout.
pub(crate) fn claim_run(setup: &Setup, label: &str, seed: u8) -> TestResult<CheckRun> {
    let owner_memory = setup.fixture.owner_memory();
    let (task, actor, leased) = leased_try(
        &setup.fixture.vault,
        &owner_memory,
        setup.fixture.owner,
        setup.agent,
        label,
    )?;
    let slip = paired_agent_slip(
        &setup.fixture.vault,
        &setup.fixture.issuer,
        &setup.fixture.owner_proof,
        setup.agent,
        seed,
    )?;
    let attempt_hex = hex_lower(leased.id.as_bytes());
    let run = bind_run(&setup.fixture.vault, &slip, (task, actor, leased))?;
    let checkout = EntityId::now().to_hex();
    // The agent claims on its own credential, as production does through the
    // host door: the TASK standing proof reads the presented slip.
    let memory = run.memory(&setup.fixture.vault).with_read_proof(&slip);
    let mut live = TestLiveness;
    let claim = memory.checkout_claim_through(
        CheckoutClaimInput {
            checkout: checkout.clone(),
            repo: setup.served,
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
            repo: setup.served,
            git_ref: MAIN.to_owned(),
            checkout: checkout.clone(),
            epoch: claim.epoch,
            endpoint: None,
        },
    )?;
    Ok(CheckRun {
        run,
        slip,
        attempt_hex,
        checkout,
        epoch: bind.output.epoch,
    })
}

/// Starts the run's check with the given command and declarations.
pub(crate) fn start_check(
    setup: &Setup,
    run: &CheckRun,
    command: Vec<String>,
    toolchain: BTreeMap<String, String>,
    environment: BTreeMap<String, String>,
    world: bool,
) -> TestResult<RepoCheckStartOutput> {
    Ok(run
        .memory(&setup.fixture.vault)
        .repo_checks_start_for_run(
            &run.run.binding,
            RepoCheckStartInput {
                repo: setup.served,
                git_ref: MAIN.to_owned(),
                checkout: run.checkout.clone(),
                epoch: run.epoch,
                command,
                toolchain,
                environment,
                world,
            },
        )?
        .output)
}

/// Finishes the run's check with the given exit status and the stored output.
pub(crate) fn finish_check(
    setup: &Setup,
    run: &CheckRun,
    check: EntityId,
    exit_status: Option<i32>,
    output: AttemptResultRef,
) -> TestResult<RepoCheckFinishOutput> {
    Ok(run
        .memory(&setup.fixture.vault)
        .repo_checks_finish_for_run(
            &run.run.binding,
            RepoCheckFinishInput {
                repo: setup.served,
                git_ref: MAIN.to_owned(),
                checkout: run.checkout.clone(),
                epoch: run.epoch,
                check,
                exit_status,
                output,
            },
        )?
        .output)
}

/// Reuses the recorded check matching the run's inputs, if one is recorded.
pub(crate) fn reuse_check(
    setup: &Setup,
    run: &CheckRun,
    command: Vec<String>,
    toolchain: BTreeMap<String, String>,
    environment: BTreeMap<String, String>,
) -> TestResult<RepoCheckReuseOutput> {
    Ok(run
        .memory(&setup.fixture.vault)
        .repo_checks_reuse_for_run(
            &run.run.binding,
            RepoCheckReuseInput {
                repo: setup.served,
                git_ref: MAIN.to_owned(),
                checkout: run.checkout.clone(),
                epoch: run.epoch,
                command,
                toolchain,
                environment,
            },
        )?
        .output)
}

/// Appends the run's check output bytes as one landed artifact version, the way a run does.
pub(crate) fn append_output(
    memory: &Memory,
    vault: &Vault,
    bytes: &[u8],
) -> TestResult<AttemptResultRef> {
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
pub(crate) fn git_tree(worktree: &Path) -> TestResult<String> {
    git(worktree, &["rev-parse", "HEAD^{tree}"])
}

/// Lower-hex of bytes, as the receipt views render ids.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn standard_inputs() -> (
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
