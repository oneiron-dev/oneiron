//! Origin registration on the host's Git (E2E CODE-CUSTODY-06, `origin.register`).
//!
//! Each test re-runs itself in a child process with a `/bin/sh` git shim first on
//! PATH, because GitWire pins the git executable from PATH once per process.
//! Mode `reject-ref-format` answers like Git before 2.45 (no `--ref-format`);
//! mode `fail-init` fails every `git init`, which the engine reports as INTERNAL.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError};
use oneiron::origin::smart_http::{origin_repo_dir, origin_serving_root};
use oneiron::store::GateDecisionId;
use oneiron::{ErrorKind, Vault, VaultConfig};

const SHIM_MODE_ENV: &str = "ONEIRON_IT_HOST_GIT_SHIM_MODE";
const REAL_GIT_ENV: &str = "ONEIRON_IT_REAL_GIT";

fn setup() -> (
    tempfile::TempDir,
    Vault,
    oneiron::consent::AuthenticatedOwner,
) {
    let dir = tempfile::tempdir().expect("create origin-registration fixture directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open fixture vault");
    let id = vault
        .ensure_embedded_owner_actor()
        .expect("ensure fixture owner actor");
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate fixture owner");
    (dir, vault, owner)
}

fn run_in_child_with_git_shim(test_name: &str, mode: &str) {
    let original_path = std::env::var_os("PATH").expect("PATH is required to locate host Git");
    let real_git = std::env::split_paths(&original_path)
        .filter(|directory| !directory.as_os_str().is_empty())
        .map(|directory| directory.join("git"))
        .find(|candidate| {
            candidate.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .expect("an executable regular git file must exist on PATH")
        .canonicalize()
        .expect("canonicalize host Git executable");
    let real_git_path = real_git
        .to_str()
        .expect("host Git path must be UTF-8 for the shell shim");
    assert!(
        !real_git_path.contains('\''),
        "host Git path must not contain a single quote"
    );
    let shim_dir = tempfile::tempdir().expect("create Git shim directory");
    let shim = shim_dir.path().join("git");
    let script = format!(
        r#"#!/bin/sh
# Simulates a host Git older than 2.45 (mode reject-ref-format) or a host Git whose init fails (mode fail-init).
for arg in "$@"; do
  case "{mode}:$arg" in
    reject-ref-format:--ref-format|reject-ref-format:--ref-format=*)
      echo "error: unknown option \`ref-format=files'" >&2
      echo "usage: git init [<options>] [<directory>]" >&2
      exit 129 ;;
    fail-init:init)
      echo "usage: git init [<options>] [<directory>]" >&2
      exit 129 ;;
  esac
done
exec '{real_git_path}' "$@"
"#
    );
    std::fs::write(&shim, script).expect("write Git shim script");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
        .expect("make Git shim executable");
    let shim_path = std::env::join_paths(
        std::iter::once(shim_dir.path().to_path_buf()).chain(std::env::split_paths(&original_path)),
    )
    .expect("prepend Git shim directory to PATH");
    let output = Command::new(std::env::current_exe().expect("locate integration test binary"))
        .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
        .env("PATH", shim_path)
        .env(SHIM_MODE_ENV, mode)
        .env(REAL_GIT_ENV, &real_git)
        .output()
        .expect("execute integration test with Git shim");
    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.success(),
        "shim child {test_name} ({mode}) failed with {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn real_git_stdout(repo_dir: &Path, args: &[&str]) -> String {
    let real_git = PathBuf::from(
        std::env::var_os(REAL_GIT_ENV).expect("child must receive the real Git executable path"),
    );
    assert!(real_git.is_absolute(), "real Git path must be absolute");
    let output = Command::new(real_git)
        .arg("--git-dir")
        .arg(repo_dir)
        .args(args)
        .output()
        .expect("read registered repository with real Git");
    let status = output.status;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.success(),
        "real Git {args:?} failed with {status}: {stderr}"
    );
    String::from_utf8(output.stdout).expect("Git repository read-back must be UTF-8")
}

fn origin_register_succeeds_when_host_git_lacks_ref_format_body() {
    let (dir, vault, owner) = setup();
    vault
        .register_served_origin_as_owner(&owner, "custody06", "main")
        .expect("register origin on host Git without --ref-format");
    let repo_dir = origin_repo_dir(&vault, "custody06").expect("resolve registered origin");
    assert!(repo_dir.is_dir(), "registered origin must be a directory");
    assert_eq!(
        real_git_stdout(&repo_dir, &["symbolic-ref", "HEAD"]).trim(),
        "refs/heads/main"
    );
    assert_eq!(
        real_git_stdout(&repo_dir, &["rev-parse", "--is-bare-repository"]).trim(),
        "true"
    );
    let duplicate = vault
        .register_served_origin_as_owner(&owner, "custody06", "main")
        .expect_err("duplicate origin registration must be refused");
    assert_eq!(duplicate.kind(), ErrorKind::ConcurrentWrite);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::device()).expect("reopen fixture vault");
    assert_eq!(
        origin_repo_dir(&reopened, "custody06").expect("resolve origin after restart"),
        repo_dir
    );
}

fn origin_register_reports_host_git_init_failure_as_internal_body() {
    let (_dir, vault, owner) = setup();
    let error = vault
        .register_served_origin_as_owner(&owner, "custody07", "main")
        .expect_err("host Git init failure must refuse registration");
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(MemoryError::from(error).code, MEMORY_CODE_INTERNAL);
    assert!(origin_repo_dir(&vault, "custody07").is_err());
    let root = origin_serving_root(&vault).expect("resolve origin serving root");
    for entry in std::fs::read_dir(root).expect("read origin serving root") {
        let entry = entry.expect("read origin serving entry");
        let name = entry.file_name();
        assert!(
            !name.to_string_lossy().starts_with(".register-"),
            "failed registration left staging entry {name:?}"
        );
    }
}

#[test]
fn origin_register_succeeds_when_host_git_lacks_ref_format() {
    if std::env::var_os(SHIM_MODE_ENV).is_some() {
        origin_register_succeeds_when_host_git_lacks_ref_format_body();
    } else {
        run_in_child_with_git_shim(
            "origin_register_succeeds_when_host_git_lacks_ref_format",
            "reject-ref-format",
        );
    }
}

#[test]
fn origin_register_reports_host_git_init_failure_as_internal() {
    if std::env::var_os(SHIM_MODE_ENV).is_some() {
        origin_register_reports_host_git_init_failure_as_internal_body();
    } else {
        run_in_child_with_git_shim(
            "origin_register_reports_host_git_init_failure_as_internal",
            "fail-init",
        );
    }
}
