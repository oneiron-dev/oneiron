//! FIX RUN-DECLARE-ANCHOR-MANIFEST (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-03): a run's symbol declaration and queue entry on a repo
//! registered through `vault.repo.anchor.bind` find the symbol manifest of
//! the work's base snapshot. A Grant names the repo by its stable anchor,
//! which holds no manifest; the ingest keys the manifest by the snapshot
//! artifact. Before, both looked the anchor up and found nothing, so a
//! declaration on a registered repo answered NOT_FOUND. The selector picks
//! the snapshot of the anchor's own folder at the work's pinned commit; another
//! commit or another folder is not selected.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test repo_anchor_symbol_manifest`.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::repo_base_manifest::repo_base_symbol_manifest;
use oneiron::verbs::{RepoAnchorBindInput, bind_repo_anchor_as};
use oneiron::{EdgeActorClass, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

/// Commits `files` and returns the commit's 40-hex id.
fn commit(dir: &Path, files: &[(&str, &str)], message: &str) -> TestResult<String> {
    for (path, body) in files {
        std::fs::write(dir.join(path), body)?;
        git(dir, &["add", "--", path])?;
    }
    git(
        dir,
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
            message,
        ],
    )?;
    git(dir, &["rev-parse", "HEAD"])
}

#[test]
fn a_registered_anchor_finds_its_base_snapshot_manifest() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let vault = Vault::open(vault_dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let (owner, proof) = embedded_owner(&vault)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let project = vault.root_project()?;

    let repo_dir = tempfile::tempdir()?;
    git(repo_dir.path(), &["init", "--quiet"])?;
    git(
        repo_dir.path(),
        &["symbolic-ref", "HEAD", "refs/heads/main"],
    )?;
    let first = commit(
        repo_dir.path(),
        &[
            (
                "math.rs",
                "pub fn add_one(value: u32) -> u32 {\n    value + 1\n}\n",
            ),
            (
                "label.rs",
                "pub fn label() -> &'static str {\n    \"ready\"\n}\n",
            ),
        ],
        "two files",
    )?;
    let folder = repo_dir
        .path()
        .canonicalize()?
        .to_str()
        .ok_or("UTF-8 repo path")?
        .to_owned();

    // The owner registers the folder: a stable CODE anchor, no manifest.
    let anchor = bind_repo_anchor_as(
        &vault,
        &proof,
        RepoAnchorBindInput {
            repo: None,
            local_folder: Some(folder.clone()),
            project,
            anchor: None,
            editable: None,
        },
    )?
    .anchor
    .repo;
    let ingest = |commit: &str| {
        memory.code_snapshot_ingest_as(
            &proof,
            CodeSnapshotIngestRequest {
                project_id: project.to_hex(),
                pointer: CodeRepoPointer {
                    local_folder: folder.clone(),
                    commit: commit.to_owned(),
                },
                repository: Some(anchor),
            },
        )
    };
    let first_snapshot = ingest(&first)?;
    let second = commit(
        repo_dir.path(),
        &[(
            "math.rs",
            "pub fn add_one(value: u32) -> u32 {\n    value + 1\n}\n\npub fn add_two(value: u32) -> u32 {\n    value + 2\n}\n",
        )],
        "a second function",
    )?;
    let second_snapshot = ingest(&second)?;
    assert_ne!(
        first_snapshot.repo, anchor,
        "the snapshot is its own artifact"
    );

    // The lookup the run doors used: the anchor holds no manifest.
    assert!(vault.get_code_symbol_manifest(&anchor)?.is_none());

    // The selector finds each commit's own snapshot manifest.
    for (commit, snapshot) in [(&first, &first_snapshot), (&second, &second_snapshot)] {
        let selected = repo_base_symbol_manifest(&vault, anchor, &folder, commit)?
            .ok_or("the work's base snapshot has a manifest")?;
        assert_eq!(
            Some(selected),
            vault.get_code_symbol_manifest(&snapshot.repo)?,
            "the manifest of the snapshot at {commit}"
        );
    }
    let first_manifest = repo_base_symbol_manifest(&vault, anchor, &folder, &first)?
        .ok_or("the first snapshot's manifest")?;
    assert!(
        first_manifest
            .symbols
            .iter()
            .all(|symbol| symbol.name != "add_two"),
        "a later revision's symbol is not in the earlier base"
    );

    // Another folder, or a commit no snapshot is of, selects nothing.
    let other = tempfile::tempdir()?;
    let other_folder = other.path().canonicalize()?;
    assert!(
        repo_base_symbol_manifest(
            &vault,
            anchor,
            other_folder.to_str().ok_or("UTF-8 path")?,
            &first
        )?
        .is_none()
    );
    assert!(repo_base_symbol_manifest(&vault, anchor, &folder, &"0".repeat(40))?.is_none());
    Ok(())
}
