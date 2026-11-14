//! The runner fence on a seat's official CLI (canon `#runner-fence`, row
//! L8-27): the seat executor starts the CLI under the vault's runner fence,
//! so the CLI cannot read the vault or the key custody directory beside it
//! and keeps its checkout, and the run's exhaust carries the session
//! manifest; a host that cannot prove the fence still runs the CLI, with an
//! unproven manifest (canon `#fence-unproven`).
//!
//! The executor finds `claude` on `PATH`, so the tests put a stand-in first
//! on it once. Run them with `--test-threads=1`: the process environment
//! changes once, before any CLI starts.
#![cfg(unix)]

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use oneiron::EntityId;
use oneiron::checkout::{CheckoutId, CheckoutLeaseAct, CheckoutLeaseState, CheckoutTaskClass};
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::codebase::RepoRef;
use oneiron::dispatch_byoa::{ByoaCliExecutor, ByoaError, ByoaExhaust, CliSandboxSpec};
use oneiron_container::{GuestSeccomp, RunnerFence, RunnerFenceMechanism};
use oneiron_server::runtime::runner_fence::HostRunnerFence;
use oneiron_server::runtime::seat_login::{OfficialCliSeatExecutor, SEAT_RUNNER_BACKEND};

/// A stand-in for the official CLI: for each path it is given, it says
/// whether it could read it, then whether it could make a temp file.
const STAND_IN: &str = r#"#!/bin/sh
for path in "$@"; do
  if cat "$path" >/dev/null 2>&1; then echo "read $path"; else echo "refused $path"; fi
done
if temp=$(mktemp 2>/dev/null); then rm -f "$temp"; echo "temp made"; else echo "temp refused"; fi
"#;

/// Puts the stand-in `claude` first on `PATH`, once for the whole binary.
fn stand_in_on_path() {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let bin = tempfile::tempdir().expect("bin dir").keep();
        let claude = bin.join("claude");
        fs::write(&claude, STAND_IN).expect("stand-in claude");
        fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("executable");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![bin.clone()];
        dirs.extend(std::env::split_paths(&path));
        let joined = std::env::join_paths(dirs).expect("PATH");
        // SAFETY: the tests run on one thread (`--test-threads=1`), and this
        // runs once, before any of them starts a process.
        unsafe { std::env::set_var("PATH", joined) };
        bin
    });
}

/// A vault directory and the key custody directory beside it, each holding
/// a probe file, and a checkout beside them.
struct Layout {
    _root: tempfile::TempDir,
    vault: PathBuf,
    vault_probe: PathBuf,
    custody_probe: PathBuf,
    checkout: PathBuf,
}

fn layout() -> Layout {
    let root = tempfile::tempdir().expect("temp root");
    let vault = root.path().join("vault");
    let custody = oneiron::store::custody_container_path(&vault).expect("custody path");
    let checkout = root.path().join("checkout");
    for dir in [&vault, &custody, &checkout] {
        fs::create_dir_all(dir).expect("layout directory");
    }
    let vault_probe = vault.join("probe");
    let custody_probe = custody.join("probe");
    fs::write(&vault_probe, "vault-secret").expect("vault probe");
    fs::write(&custody_probe, "custody-secret").expect("custody probe");
    fs::write(checkout.join("checkout-file"), "checkout").expect("checkout file");
    Layout {
        _root: root,
        vault,
        vault_probe,
        custody_probe,
        checkout,
    }
}

/// The two probes and a checkout file, as the stand-in's arguments.
fn probes(layout: &Layout) -> Vec<String> {
    vec![
        layout.vault_probe.display().to_string(),
        layout.custody_probe.display().to_string(),
        "checkout-file".to_owned(),
    ]
}

/// One seat run of the stand-in over `argv`, and what it printed.
fn run_seat(
    layout: &Layout,
    runner_fence: Option<Arc<HostRunnerFence>>,
    argv: Vec<String>,
) -> (ByoaExhaust, String) {
    stand_in_on_path();
    let checkout_id = CheckoutId::from_bytes(*EntityId::now().as_bytes()).expect("checkout id");
    let spec = CliSandboxSpec {
        program: "claude".to_owned(),
        argv,
        checkout_id,
        egress_profile_ref: "egress/none".to_owned(),
        credential_handles: Vec::new(),
        staged_input: None,
    };
    let checkout = CheckoutLeaseAct {
        checkout_id,
        task_ref: EntityId::now(),
        repo_ref: RepoRef::LocalFolder {
            path: layout.checkout.display().to_string(),
            commit: "a".repeat(40),
        },
        holder_ref: "owen".to_owned(),
        epoch: 1,
        task_class: CheckoutTaskClass::Edit,
        state: CheckoutLeaseState::Active,
        claimed_at: 1,
        lease_expires_at: None,
        updated_at: 1,
        bound_attempt: None,
    };
    let mut executor = OfficialCliSeatExecutor {
        workdir: layout.checkout.clone(),
        secret_destinations: None,
        floor: None,
        stop: None,
        helper_env: None,
        model_env: None,
        runner_fence,
    };
    let exhaust = executor
        .run(
            &spec,
            &checkout,
            CliSandboxSpec::boundary_contract(),
            ExecutionBudget::new(30, 128, 8),
            &mut |_, _| Err(ByoaError::Backend("a seat run takes no egress".to_owned())),
        )
        .expect("the seat run");
    let mut printed = String::new();
    exhaust
        .stdout
        .reader()
        .read_to_string(&mut printed)
        .expect("stdout");
    (exhaust, printed)
}

#[test]
fn a_seat_cli_cannot_read_the_vault_or_its_key_custody_and_keeps_its_checkout() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let outcome = fence.outcome().clone();
    eprintln!("runner_fence_seat: mechanism {:?}", outcome.mechanism);
    if outcome.mechanism == RunnerFenceMechanism::Unavailable {
        assert!(!outcome.proven, "a host with no mechanism proves nothing");
        return;
    }
    assert!(outcome.proven, "proof failed: {outcome:?}");
    let (exhaust, printed) = run_seat(&layout, Some(Arc::new(fence)), probes(&layout));
    eprintln!("runner_fence_seat: the CLI printed:\n{printed}");
    for probe in [&layout.vault_probe, &layout.custody_probe] {
        assert!(
            printed.contains(&format!("refused {}", probe.display())),
            "the CLI read {}: {printed}",
            probe.display()
        );
    }
    assert!(
        printed.contains("read checkout-file"),
        "the CLI lost its checkout: {printed}"
    );
    // The test's vault lies below the system temp directory, which is then
    // on the way to a removed tree: the CLI writes in its own TMPDIR.
    assert!(
        printed.contains("temp made"),
        "the CLI cannot make a temp file: {printed}"
    );
    let manifest = exhaust
        .session_manifest
        .expect("a fenced seat run carries its session manifest");
    assert_eq!(manifest.backend, SEAT_RUNNER_BACKEND);
    assert_eq!(manifest.runtime, "claude");
    assert_eq!(manifest.network, "host");
    assert_eq!(manifest.seccomp, GuestSeccomp::Unfiltered);
    assert!(!manifest.fence_unproven);
    let proof = manifest
        .fence_proof
        .expect("a proven session carries its proof");
    assert_eq!(proof.ruleset_hash, outcome.ruleset_hash);
    assert_eq!(proof.sandbox_generation, outcome.sandbox_generation);
}

#[test]
fn the_seat_fence_removes_the_vault_and_its_key_custody_directory() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let custody = layout.custody_probe.parent().expect("custody dir");
    let expected =
        RunnerFence::for_host([layout.vault.clone(), custody.to_path_buf()]).expect("runner fence");
    assert_eq!(
        fence.outcome().ruleset_hash,
        expected.ruleset_hash(),
        "the hash names the removed trees: the vault and its key custody directory"
    );
}

#[test]
fn a_seat_cli_on_a_host_without_the_fence_runs_with_an_unproven_manifest() {
    let layout = layout();
    let fence = HostRunnerFence::proved(
        RunnerFence::unavailable([layout.vault.clone()]).expect("runner fence"),
    );
    let (exhaust, printed) = run_seat(&layout, Some(Arc::new(fence)), probes(&layout));
    assert!(
        printed.contains(&format!("read {}", layout.vault_probe.display())),
        "the run goes on, unfenced: {printed}"
    );
    let manifest = exhaust
        .session_manifest
        .expect("an unfenced seat run still carries its session manifest");
    assert_eq!(manifest.backend, SEAT_RUNNER_BACKEND);
    assert!(manifest.fence_unproven);
    assert!(manifest.fence_proof.is_none(), "no ruleset hash is claimed");
}

#[test]
fn a_seat_cli_whose_checkout_is_a_worktree_of_a_repository_in_the_vault_runs_unproven() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    if fence.outcome().mechanism == RunnerFenceMechanism::Unavailable {
        return;
    }
    // A masked copy's checkout (FIX 7608): a linked worktree of a repository
    // in the vault's data tree, which git in the checkout reads.
    let repository = layout
        .vault
        .join("repo-secret-projections")
        .join("store")
        .join("graph")
        .join("repo.git");
    let git_dir = repository.join("worktrees").join("tree");
    fs::create_dir_all(&git_dir).expect("worktree git directory");
    fs::write(git_dir.join("commondir"), "../..\n").expect("commondir");
    let head = repository.join("HEAD");
    fs::write(&head, "ref: refs/heads/main\n").expect("repository HEAD");
    fs::write(
        layout.checkout.join(".git"),
        format!("gitdir: {}\n", git_dir.display()),
    )
    .expect("worktree .git file");
    let (exhaust, printed) = run_seat(
        &layout,
        Some(Arc::new(fence)),
        vec![head.display().to_string()],
    );
    assert!(
        printed.contains(&format!("read {}", head.display())),
        "the CLI lost its checkout's repository: {printed}"
    );
    let manifest = exhaust
        .session_manifest
        .expect("an unfenced seat run still carries its session manifest");
    assert!(manifest.fence_unproven, "the run went on without the rule");
    assert!(manifest.fence_proof.is_none(), "no ruleset hash is claimed");
}
